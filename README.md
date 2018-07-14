# MoonShine: Seed Generation for OS Fuzzers (USENIX '18)
See the USENIX'18 paper [MoonShine: Optimizing Seed Selection for OS Fuzzers with Trace Distillation] (http://www.cs.columbia.edu/~suman/docs/moonshine.pdf) for more details.

## Prerequisite
At present, MoonShine can only generate seeds for Syzkaller and is only supported on Linux. 
### Golang
See [here](https://golang.org/doc/install) for instructions to install golang. After successfully installing golang set
```bash
export PATH=$PATH:$GOPATH/bin/
```

### Ragel
```bash
sudo apt-get update
sudo apt-get install ragel
```

### Goyacc
```bash
go get golang.org/x/tools/cmd/goyacc
```
