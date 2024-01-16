package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=amd64 -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf network-events.c -- -I $BPF_HEADERS

func main() {

	// allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	l, err := link.Kprobe("tcp_v4_connect", objs.KprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatalf("error kprobe: %v", err)
	}
	defer l.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Successfully loaded and Waiting for events..")
	startMap := objs.bpfMaps.Events

	perfEvent, err := perf.NewReader(startMap, 4096)
	if err != nil {
		log.Fatalf("error perf event: %v", err)
	}

	defer perfEvent.Close()

	go func() {
		// event handler
		for {
			r, err := perfEvent.Read()
			if err != nil {
				log.Println(err)
				continue
			}

			fmt.Println("===>", string(r.RawSample))

		}

	}()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}

func readEvent(rd *perf.Reader) {
	var event tcpEvent
	for {
		record, err := rd.Read()
		if err != nil {
			log.Println("error reading perf")
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing perf event: %v", err)
		}

		log.Printf("tcp event: [%d] %d:%d -> %d:%d",
			event.Pid,
			event.SAddr,
			event.SPort,
			event.DAddr,
			event.DPort,
		)
	}
}

type tcpEvent struct {
	Type  uint32
	Pid   uint32
	SPort uint16
	DPort uint16
	SAddr [16]byte
	DAddr [16]byte
}

// utils
func long2ip(iplong uint32) string {
	ipByte := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipByte, iplong)
	ip := net.IP(ipByte)
	return ip.String()
}

func long2DNS(iplong uint32) string {
	ip := long2ip(iplong)

	names, err := net.LookupAddr(ip)
	if err != nil {
		goto RET
	}

	if len(names) > 0 {
		return names[0]
	}
RET:
	return "-"
}
