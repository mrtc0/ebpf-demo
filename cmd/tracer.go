package cmd

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/mrtc0/ebpf-demo/pkg/tracer"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(tracerCmd)
}

var tracerCmd = &cobra.Command{
	Use:   "trace",
	Short: "",
	Run: func(cmd *cobra.Command, args []string) {
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

		if err := rlimit.RemoveMemlock(); err != nil {
			slog.Error("failed unlock memoery lock", "error", err)
			os.Exit(1)
		}

		connectTracer := tracer.NewSocketConnectTracer(stopper)
		err := connectTracer.Start()
		if err != nil {
			slog.Error("failed start taracer", "error", err)
			os.Exit(1)
		}
	},
}
