package enforcer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/mrtc0/ebpf-demo/pkg/support/endian"
	"github.com/mrtc0/ebpf-demo/pkg/support/network"
	"golang.org/x/sys/unix"
)

var (
	// 93.184.216.34 is example.com A record
	exampleComIPAddr = net.ParseIP("93.184.216.34")
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -Werror -I /usr/include/x86_64-linux-gnu" -type event socketConnect ../../bpf/enforce_connect.c

type socketConnectEnforcer struct {
	stopper chan os.Signal
}

// newSocketConnectEnforcer create a new connect(sys_onnect) syscall blocker
func NewSocketConnectEnforcer(stopper chan os.Signal) Enforcer {
	return &socketConnectEnforcer{
		stopper: stopper,
	}
}

// Start attaches to sys_connect kprobe to get and display events from ring buffer
// The eBPF program loaded by this function blocks connections to example.com
func (e *socketConnectEnforcer) Start() error {
	var objs socketConnectObjects
	if err := loadSocketConnectObjects(&objs, nil); err != nil {
		slog.Error("failed load eBPF object", "error", err)
		return err
	}
	defer objs.Close()

	link, err := link.Kprobe("sys_connect", objs.KprobeSysConnect, nil)
	if err != nil {
		slog.Error("failed attach kprobe:sys_connect", "error", err)
		return err
	}
	defer link.Close()

	err = objs.DeniedIpaddrMap.Put(&socketConnectIpv4LpmKey{
		Prefixlen: 32,
		Data:      network.IPToInt(exampleComIPAddr),
	}, uint32(0))
	if err != nil {
		slog.Error("failed putting data to map", "error", err)
		return err
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		slog.Error("failed open ringbuf reader", "error", err)
		return err
	}
	defer rd.Close()

	go func() {
		<-e.stopper

		if err := rd.Close(); err != nil {
			slog.Error("failed close ringbuf reader", "error", err)
		}
	}()

	slog.Info("waiting for events...")

	var event socketConnectEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				slog.Info("Received signal, exiting...")
				return nil
			}

			slog.Warn("failed read ringbuf", "error", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), endian.NativeEndian, &event); err != nil {
			slog.Warn("failed decoding event", "error", err)
			continue
		}

		slog.Info("🛡 BLOCKED", "comm", unix.ByteSliceToString(event.Comm[:]), "addr", network.IntToIP(event.Dst.S_addr))
	}
}
