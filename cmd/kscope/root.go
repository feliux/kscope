package main

import "github.com/spf13/cobra"

func newRootCmd() *cobra.Command {
	obsCfg := defaultObserveConfig()
	proxyCfg := defaultProxyConfig()

	root := &cobra.Command{
		Use:   "kscope",
		Short: "Kernel Scope runtime",
		Long:  "eBPF-powered offensive runtime discovery and attack surface observability",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runObserve(obsCfg)
		},
	}

	observeCmd := &cobra.Command{
		Use:   "observe",
		Short: "Run the observability pipeline",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runObserve(obsCfg)
		},
	}

	proxyCmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run TCP proxy with eBPF redirection",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProxy(proxyCfg)
		},
	}

	addObserveFlags(root, &obsCfg)
	addObserveFlags(observeCmd, &obsCfg)
	addProxyFlags(proxyCmd, &proxyCfg)

	root.AddCommand(observeCmd, proxyCmd)

	return root
}
