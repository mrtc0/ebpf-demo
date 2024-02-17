package network

import (
	"net"

	"github.com/mrtc0/ebpf-demo/pkg/support/endian"
)

func IntToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	endian.NativeEndian.PutUint32(ip, ipNum)
	return ip
}

func IPToInt(ip net.IP) uint32 {
	if len(ip) == 16 {
		return endian.NativeEndian.Uint32(ip[12:16])
	}

	return endian.NativeEndian.Uint32(ip)
}
