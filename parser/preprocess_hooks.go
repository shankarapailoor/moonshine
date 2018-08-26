package parser

import (
	"github.com/google/syzkaller/prog"
	. "github.com/shankarapailoor/moonshine/logging"
	"github.com/shankarapailoor/moonshine/straceTypes"
)

type PreprocessHook func(ctx *Context)

func Preprocess(ctx *Context) {
	call := ctx.CurrentStraceCall.CallName
	if procFunc, ok := PreprocessMap[call]; ok {
		procFunc(ctx)
	}
	return
}

var PreprocessMap = map[string]PreprocessHook{
	"bpf":         bpf,
	"accept":      accept,
	"accept4":     accept,
	"bind":        bind,
	"connect":     connect,
	"fcntl":       fcntl,
	"getsockname": getsockname,
	"getsockopt":  getsockopt,
	"ioctl":       ioctl,
	"open":        open,
	"prctl":       prctl,
	"recvfrom":    recvfrom,
	"mknod":       mknod,
	"modify_ldt":  modifyLdt,
	"openat":      openat,
	"sendto":      sendto,
	"setsockopt":  setsockopt,
	"shmctl":      shmctl,
	"socket":      socket,
}

func bpf(ctx *Context) {
	bpfCmd := ctx.CurrentStraceCall.Args[0].String()
	if suffix, ok := straceTypes.BpfLabels[bpfCmd]; ok {
		ctx.CurrentStraceCall.CallName += suffix
	} else if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+bpfCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + bpfCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func accept(ctx *Context) {
	/*
		Accept can take on many subforms such as
		accept$inet
		accept$inet6

		In order to determine the proper form we need to look at the file descriptor to determine
		the proper socket type. We refer to the $inet as a suffix to the name
	*/
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0] //File descriptor of Accept
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = straceTypes.AcceptLabels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func bind(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = straceTypes.BindLabels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func connect(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = straceTypes.ConnectLabels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func getsockname(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = straceTypes.GetsocknameLabels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func socket(ctx *Context) {
	straceFd := ctx.CurrentStraceCall.Args[0]

	if suffix, ok := straceTypes.SocketLabels[straceFd.String()]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}
}

func setsockopt(ctx *Context) {
	sockLevel := ctx.CurrentStraceCall.Args[1]
	optName := ctx.CurrentStraceCall.Args[2]
	pair := straceTypes.Pair{
		A: sockLevel.String(),
		B: optName.String(),
	}
	if suffix, ok := straceTypes.SetsockoptLabels[pair]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}

}

func getsockopt(ctx *Context) {
	sockLevel := ctx.CurrentStraceCall.Args[1]
	optName := ctx.CurrentStraceCall.Args[2]
	pair := straceTypes.Pair{
		A: sockLevel.String(),
		B: optName.String(),
	}
	if suffix, ok := straceTypes.GetsockoptLabels[pair]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}

}

func recvfrom(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = straceTypes.RecvfromLabels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func open(ctx *Context) {
	if len(ctx.CurrentStraceCall.Args) < 3 {
		ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
			straceTypes.NewExpression(straceTypes.NewIntType(int64(0))))
	}
}

func mknod(ctx *Context) {
	if len(ctx.CurrentStraceCall.Args) < 3 {
		ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
			straceTypes.NewExpression(straceTypes.NewIntType(int64(0))))
	}
}

func openat(ctx *Context) {
	if len(ctx.CurrentSyzCall.Args) < 4 {
		ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
			straceTypes.NewExpression(straceTypes.NewIntType(int64(0))))
	}
}

func ioctl(ctx *Context) {
	ioctlCmd := ctx.CurrentStraceCall.Args[1].String()
	if suffix, ok := straceTypes.IoctlMap[ioctlCmd]; ok {
		ctx.CurrentStraceCall.CallName += suffix
	} else if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+ioctlCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + ioctlCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func fcntl(ctx *Context) {
	fcntlCmd := ctx.CurrentStraceCall.Args[1].String()
	if suffix, ok := straceTypes.FcntlLabels[fcntlCmd]; ok {
		ctx.CurrentStraceCall.CallName += suffix
	} else if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+fcntlCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + fcntlCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func prctl(ctx *Context) {
	prctlCmd := ctx.CurrentStraceCall.Args[0].String()
	if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+prctlCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + prctlCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func shmctl(ctx *Context) {
	shmctlCmd := ctx.CurrentStraceCall.Args[1].String()
	if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+shmctlCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + shmctlCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func sendto(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0] //File descriptor of Accept
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = straceTypes.SendtoLabels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func modifyLdt(ctx *Context) {
	suffix := ""
	switch a := ctx.CurrentStraceCall.Args[0].(type) {
	case *straceTypes.Expression:
		switch a.Eval(ctx.Target) {
		case 0:
			suffix = "$read"
		case 1:
			suffix = "$write"
		case 2:
			suffix = "$read_default"
		case 17:
			suffix = "$write2"
		}
	default:
		Failf("Preprocess modifyldt received unexpected strace type: %s\n", a.Name())
	}
	ctx.CurrentStraceCall.CallName = ctx.CurrentStraceCall.CallName + suffix
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}
