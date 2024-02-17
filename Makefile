build:
	go generate ./...
	go build -o bin/ .

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
