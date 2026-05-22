package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/feliux/kscope/pkg/utils"
	"golang.org/x/sys/unix"
)

type Server struct {
	ListenV4 string
	ListenV6 string

	OrigDstMap     *ciliumebpf.Map
	OrigDstPidPort *ciliumebpf.Map
	OrigDstFlowV4  *ciliumebpf.Map
	OrigDstFlowV6  *ciliumebpf.Map
	Logger         *log.Logger

	DialTimeout time.Duration
}

func (s *Server) Run(ctx context.Context) error {
	if s.OrigDstMap == nil {
		return errors.New("orig destination map is nil")
	}

	if s.Logger == nil {
		s.Logger = log.New(os.Stderr, "proxy: ", log.LstdFlags)
	}

	if s.DialTimeout == 0 {
		s.DialTimeout = 5 * time.Second
	}

	var listeners []*net.TCPListener

	if s.ListenV4 != "" {
		ln, err := listenTCP(s.ListenV4)
		if err != nil {
			return err
		}
		listeners = append(listeners, ln)
	}

	if s.ListenV6 != "" {
		ln, err := listenTCP(s.ListenV6)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return errors.New("no proxy listeners configured")
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(listeners))

	for _, ln := range listeners {
		wg.Add(1)
		go func(l *net.TCPListener) {
			defer wg.Done()
			if err := s.acceptLoop(ctx, l); err != nil {
				errCh <- err
			}
		}(ln)
	}

	select {
	case <-ctx.Done():
		for _, l := range listeners {
			_ = l.Close()
		}
		wg.Wait()
		return nil
	case err := <-errCh:
		for _, l := range listeners {
			_ = l.Close()
		}
		wg.Wait()
		return err
	}
}

func listenTCP(addr string) (*net.TCPListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("listener is not tcp: %s", addr)
	}

	return tcpLn, nil
}

func (s *Server) acceptLoop(ctx context.Context, ln *net.TCPListener) error {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		if s.Logger != nil {
			s.Logger.Printf("proxy accepted src=%s", conn.RemoteAddr().String())
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn *net.TCPConn) {
	defer conn.Close()

	cookie, err := socketCookie(conn)
	if err != nil {
		s.Logger.Printf("cookie error: %v", err)
		return
	}

	via := "cookie"
	var dst origDst
	if err := s.OrigDstMap.Lookup(&cookie, &dst); err != nil {
		if lookupPidPortOrigDst(s, conn, &dst) {
			via = "pidport"
		} else if lookupFlowOrigDst(s, conn, &dst) {
			via = "flow"
		} else {
			s.Logger.Printf("orig dst lookup failed: %v", err)
			return
		}
	} else {
		_ = s.OrigDstMap.Delete(&cookie)
	}

	target, err := formatOriginalAddr(dst)
	if err != nil {
		s.Logger.Printf("invalid original dst: %v", err)
		return
	}

	upstream, err := net.DialTimeout("tcp", target, s.DialTimeout)
	if err != nil {
		s.Logger.Printf("dial %s failed: %v", target, err)
		return
	}
	defer upstream.Close()

	s.Logger.Printf("proxy connected src=%s dst=%s via=%s", conn.RemoteAddr().String(), target, via)

	if err := relay(conn, upstream); err != nil && !errors.Is(err, net.ErrClosed) {
		s.Logger.Printf("relay error: %v", err)
	}
}

func relay(a *net.TCPConn, b net.Conn) error {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(b, a)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(a, b)
		errCh <- err
	}()

	err1 := <-errCh
	_ = a.CloseWrite()
	_ = a.CloseRead()
	return err1
}

func socketCookie(conn *net.TCPConn) (uint64, error) {
	var cookie uint64
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var ctrlErr error
	err = raw.Control(func(fd uintptr) {
		cookie, ctrlErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	})
	if err != nil {
		return 0, err
	}
	if ctrlErr != nil {
		return 0, ctrlErr
	}

	return cookie, nil
}

func formatOriginalAddr(dst origDst) (string, error) {
	if dst.Port == 0 {
		return "", errors.New("original port is zero")
	}

	switch dst.IPVersion {
	case 4:
		ip := utils.IPv4FromUint32(dst.AddrV4).String()
		return net.JoinHostPort(ip, strconv.Itoa(int(dst.Port))), nil
	case 6:
		ip := net.IP(dst.AddrV6[:]).String()
		return net.JoinHostPort(ip, strconv.Itoa(int(dst.Port))), nil
	default:
		return "", fmt.Errorf("unknown ip version: %d", dst.IPVersion)
	}
}

func lookupPidPortOrigDst(s *Server, conn *net.TCPConn, dst *origDst) bool {
	if s.OrigDstPidPort == nil {
		return false
	}

	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return false
	}

	ipVersion := uint8(4)
	if remote.IP.To4() == nil {
		ipVersion = 6
	}
	port := uint16(remote.Port)

	tryLookup := func(pid uint32) bool {
		key := pidPortKey{
			PID:       pid,
			Port:      port,
			IPVersion: ipVersion,
		}
		if err := s.OrigDstPidPort.Lookup(&key, dst); err == nil {
			_ = s.OrigDstPidPort.Delete(&key)
			return true
		}
		return false
	}

	if pid, err := peerPID(conn); err == nil && pid != 0 {
		if tryLookup(pid) {
			return true
		}
	}

	return tryLookup(0)
}

func peerPID(conn *net.TCPConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var cred *unix.Ucred
	var ctrlErr error
	err = raw.Control(func(fd uintptr) {
		cred, ctrlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	if cred == nil {
		return 0, errors.New("peer credentials unavailable")
	}

	return uint32(cred.Pid), nil
}

func lookupFlowOrigDst(s *Server, conn *net.TCPConn, dst *origDst) bool {
	if s.OrigDstFlowV4 == nil && s.OrigDstFlowV6 == nil {
		return false
	}

	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return false
	}

	if ip4 := remote.IP.To4(); ip4 != nil {
		if s.OrigDstFlowV4 == nil {
			return false
		}
		key := flowKeyV4{
			IP:   ipv4ToUint32(ip4),
			Port: uint16(remote.Port),
		}
		if err := s.OrigDstFlowV4.Lookup(&key, dst); err == nil {
			_ = s.OrigDstFlowV4.Delete(&key)
			return true
		}
		return false
	}

	ip16 := remote.IP.To16()
	if ip16 == nil || s.OrigDstFlowV6 == nil {
		return false
	}
	key := flowKeyV6{
		Port: uint16(remote.Port),
	}
	copy(key.IP[:], ip16)
	if err := s.OrigDstFlowV6.Lookup(&key, dst); err == nil {
		_ = s.OrigDstFlowV6.Delete(&key)
		return true
	}

	return false
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
}

type pidPortKey struct {
	PID       uint32
	Port      uint16
	IPVersion uint8
	Pad       uint8
}

type flowKeyV4 struct {
	IP   uint32
	Port uint16
	Pad  uint16
}

type flowKeyV6 struct {
	IP   [16]byte
	Port uint16
	Pad  uint16
}

type origDst struct {
	IPVersion uint8
	Pad       uint8
	Port      uint16
	AddrV4    uint32
	AddrV6    [16]byte
}
