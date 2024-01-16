This repository contains some sample eBPF codes presented in the talk topic "Security CI/CD runners through eBPF agent" in [Open Security summit] (https://open-security-summit.org/)

The code samples uses Cilium's go library.

# How to test 
```
cd kprobe_sysexecve
make 
sudo ./kprobe
```

# Requirements 
- Linux >= 4.9
- LLVM 11 or later (clang and llvm-strip)
- [Cilium] (https://github.com/cilium/ebpf)
