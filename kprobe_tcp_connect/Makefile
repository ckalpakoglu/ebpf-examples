CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror

LIBEBPF_TOP = $(pwd)
HEADERS = $(LIBEBPF_TOP)/../headers

all: generate build

generate: export BPF_CLANG=$(CLANG)
generate: export BPF_CFLAGS=$(CFLAGS)
generate: export BPF_HEADERS=$(HEADERS)
generate:
	go generate ./...
clean:
	rm *.o kprobe 
build:
	go build -o kprobe .
