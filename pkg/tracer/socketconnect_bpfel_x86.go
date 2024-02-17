// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type socketConnectEvent struct {
	Dst  struct{ S_addr uint32 }
	Comm [16]uint8
}

type socketConnectIpv4LpmKey struct {
	Prefixlen uint32
	Data      uint32
}

// loadSocketConnect returns the embedded CollectionSpec for socketConnect.
func loadSocketConnect() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SocketConnectBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load socketConnect: %w", err)
	}

	return spec, err
}

// loadSocketConnectObjects loads socketConnect and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*socketConnectObjects
//	*socketConnectPrograms
//	*socketConnectMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSocketConnectObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSocketConnect()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// socketConnectSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketConnectSpecs struct {
	socketConnectProgramSpecs
	socketConnectMapSpecs
}

// socketConnectSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketConnectProgramSpecs struct {
	HandleSecuritySocketConnect *ebpf.ProgramSpec `ebpf:"handle_security_socket_connect"`
}

// socketConnectMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketConnectMapSpecs struct {
	DeniedIpaddrMap *ebpf.MapSpec `ebpf:"denied_ipaddr_map"`
	Events          *ebpf.MapSpec `ebpf:"events"`
}

// socketConnectObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSocketConnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketConnectObjects struct {
	socketConnectPrograms
	socketConnectMaps
}

func (o *socketConnectObjects) Close() error {
	return _SocketConnectClose(
		&o.socketConnectPrograms,
		&o.socketConnectMaps,
	)
}

// socketConnectMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSocketConnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketConnectMaps struct {
	DeniedIpaddrMap *ebpf.Map `ebpf:"denied_ipaddr_map"`
	Events          *ebpf.Map `ebpf:"events"`
}

func (m *socketConnectMaps) Close() error {
	return _SocketConnectClose(
		m.DeniedIpaddrMap,
		m.Events,
	)
}

// socketConnectPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSocketConnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketConnectPrograms struct {
	HandleSecuritySocketConnect *ebpf.Program `ebpf:"handle_security_socket_connect"`
}

func (p *socketConnectPrograms) Close() error {
	return _SocketConnectClose(
		p.HandleSecuritySocketConnect,
	)
}

func _SocketConnectClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed socketconnect_bpfel_x86.o
var _SocketConnectBytes []byte
