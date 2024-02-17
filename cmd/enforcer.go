package cmd

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/mrtc0/ebpf-demo/pkg/enforcer"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(enforceCmd)
}

var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "",
	Run: func(cmd *cobra.Command, args []string) {
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

		if err := rlimit.RemoveMemlock(); err != nil {
			slog.Error("failed unlock memoery lock", "error", err)
			os.Exit(1)
		}

		connectEnforcer := enforcer.NewSocketConnectEnforcer(stopper)
		err := connectEnforcer.Start()
		if err != nil {
			slog.Error("failed start enforcer", "error", err)
			os.Exit(1)
		}
	},
}
