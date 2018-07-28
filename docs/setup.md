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
#### Version
We suggest that you use strace versions >= 4.0 as those are the only versions we have used so far. You can check the strace version as follows: 

```bash
$ strace -V
strace -- version 4.XX
```
### Strace Installation
At the present, MoonShine can only parse traces gathered from [strace](https://github.com/strace/strace)

#### Source
Strace can be built from source by following the instructions [here](https://github.com/strace/strace/blob/master/INSTALL).

#### Package
On Debian it can be installed as follows:

```bash
apt-get update
apt-get install strace
```

