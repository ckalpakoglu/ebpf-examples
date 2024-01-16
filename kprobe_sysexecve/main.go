// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf kprobe.c -- -I $BPF_HEADERS

const mapKey uint32 = 0

type data struct {
	Pid         uint32
	ProgramName [16]byte
}

func main() {
	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Link kprobe events
	kp, err := link.Kprobe(fn, objs.BpfCaptureExec, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	perfEvents, err := perf.NewReader(objs.bpfMaps.Events, 4096)
	if err != nil {
		log.Fatalf("reading perf reader error:%v", err)
	}
	defer perfEvents.Close()

	for {
		var e data
		record, err := perfEvents.Read()
		if err != nil {
			fmt.Println("err")
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parsing perf event: %s", err)
		}

		fmt.Printf("%d ---> %v\n", e.Pid, toStr(e.ProgramName[:]))
	}
}

func toStr(b []byte) string {
	var buf bytes.Buffer
	buf.Write(b)
	defer buf.Reset()

	return buf.String()
}
