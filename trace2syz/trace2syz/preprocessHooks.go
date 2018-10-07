package trace2syz

import (
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"strings"
)

type sock struct {
	domain uint64
	level uint64
	protocol uint64
}

/*
 Mappings of system calls to their varaints
 Keys represent
 */
type CallVariantMap struct {
	Fcntl map[uint64]string
	Bpf map[uint64]string
	Socket map[sock]string
	Ioctl map[uint64]string
	GetSetsockopt map[pair]string
	ConnectionCalls map[string]string //accept, bind, connect
}


func buildVariantMap1Field(variants []*prog.Syscall, callMap map[uint64]string, idx int) {
	for _, variant := range(variants) {
		switch a := variant.Args[idx].(type) {
		case *prog.ConstType:
			callMap[a.Val] = variant.Name
		case *prog.FlagsType:
			for _, val := range a.Vals {
				if _, ok := callMap[val]; !ok {
					callMap[val] = variant.Name
				}
			}
		}
	}
}

func (c *CallVariantMap) addSocket(key sock, val string, target *prog.Target) {
	level := key.level
	c.Socket[key] = val
	key.level = level | target.ConstMap["SOCK_CLOEXEC"]
	c.Socket[key] = val
	key.level = level | target.ConstMap["SOCK_NONBLOCK"]
	c.Socket[key] = val
	key.level |= target.ConstMap["SOCK_CLOEXEC"]
	c.Socket[key] = val
}

func (c *CallVariantMap) buildSocketMap(variants []*prog.Syscall, target *prog.Target) {
	for _, variant := range(variants) {
		suffix := strings.Split(variant.Name, "$")[1]
		key := sock{}
		switch a := variant.Args[0].(type) {
		case *prog.ConstType:
			key.domain = a.Val
		}
		switch a := variant.Args[2].(type) {
		case *prog.ConstType:
			key.protocol = a.Val
		default:
			key.protocol = ^uint64(0)
		}
		switch a := variant.Args[1].(type) {
		case *prog.ConstType:
			key.level = a.Val
			c.addSocket(key, suffix, target)
		case *prog.FlagsType:
			for _, val := range a.Vals {
				key.level = val
				if _, ok := c.Socket[key]; !ok {
					c.addSocket(key, suffix, target)
				}
			}
		}
	}
}

func (c *CallVariantMap) buildGetSetsockoptMap(variants []*prog.Syscall) {
	for _, variant := range(variants) {
		level := variant.Args[1].(*prog.ConstType).Val
		switch a := variant.Args[2].(type) {
		case *prog.FlagsType:
			var p pair;
			for _, val := range a.Vals {
				p.A = fmt.Sprint(level)
				p.B = fmt.Sprint(val)
				if _, ok := c.GetSetsockopt[p]; !ok {
					c.GetSetsockopt[p] = strings.Split(variant.Name, "$")[1]
				}
			}
		case *prog.ConstType:
			var p pair;
			p.A = fmt.Sprint(variant.Args[1].(*prog.ConstType).Val)
			p.B = fmt.Sprint(a.Val)
			c.GetSetsockopt[p] = strings.Split(variant.Name, "$")[1]
		}
	}
}

func (c *CallVariantMap) buildConnectCallMap(variants []*prog.Syscall) {
	for _, variant := range(variants) {
		resourceName := variant.Args[0].(*prog.ResourceType).TypeName
		c.ConnectionCalls[resourceName] = strings.Split(variant.Name, "$")[1]
	}
}

func (c *CallVariantMap) Build(target *prog.Target) {
	callVariants := make(map[string][]*prog.Syscall)
	for _, call := range target.Syscalls {
		if strings.Contains(call.Name, "$") {
			if _, ok := callVariants[call.CallName]; !ok {
				callVariants[call.CallName] = []*prog.Syscall{}
			}
			callVariants[call.CallName] = append(callVariants[call.CallName], call)
		}
	}

	for call, variants := range(callVariants) {
		switch call {
		case "socket", "socketpair":
			c.buildSocketMap(variants, target)
		case "ioctl":
			buildVariantMap1Field(variants, c.Ioctl, 1)
		case "bpf":
			buildVariantMap1Field(variants, c.Bpf, 0)
		case "fcntl":
			buildVariantMap1Field(variants, c.Fcntl, 1)
		case "getsockopt", "setsockopt":
			c.buildGetSetsockoptMap(variants)
		case "accept", "bind", "connect", "accept4", "recvfrom", "sendto", "getsockname":
			c.buildConnectCallMap(variants)
		}
	}
}


func NewCall2VariantMap() (c *CallVariantMap) {
	c = new(CallVariantMap)
	c.Fcntl = make(map[uint64]string)
	c.Bpf = make(map[uint64]string)
	c.Socket = 	make(map[sock]string)
	c.Ioctl = make(map[uint64]string)
	c.GetSetsockopt = make(map[pair]string)
	c.ConnectionCalls = make(map[string]string)
	return
}


type preprocessHook func(ctx *Context)

func preprocess(ctx *Context) {
	call := ctx.CurrentStraceCall.CallName
	if procFunc, ok := preprocessMap[call]; ok {
		procFunc(ctx)
	}
}

var preprocessMap = map[string]preprocessHook{
	"bpf":         bpf,
	"accept":      connectCalls,
	"accept4":     connectCalls,
	"bind":        connectCalls,
	"connect":     connectCalls,
	"fcntl":       fcntl,
	"getsockname": connectCalls,
	"getsockopt":  getSetsockoptCalls,
	"ioctl":       ioctl,
	"open":        open,
	"prctl":       prctl,
	"recvfrom":    connectCalls,
	"mknod":       mknod,
	"modify_ldt":  modifyLdt,
	"openat":      openat,
	"sendto":      connectCalls,
	"setsockopt":  getSetsockoptCalls,
	"shmctl":      shmctl,
	"socket":      socket,
	"socketpair": socket,
	"shmget":      shmget,
}

func bpf(ctx *Context) {
	val := ctx.CurrentStraceCall.Args[0].Eval(ctx.Target)
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.Call2Variant.Bpf[val]]
}

func socket(ctx *Context) {
	val1 := ctx.CurrentStraceCall.Args[0].Eval(ctx.Target)
	val2 := ctx.CurrentStraceCall.Args[1].Eval(ctx.Target)
	val3 := ctx.CurrentStraceCall.Args[2].Eval(ctx.Target)
	key := sock{val1, val2, val3}
	if _, ok := ctx.Call2Variant.Socket[key]; !ok {
		key.protocol = ^uint64(0)
	}
	if suffix, ok := ctx.Call2Variant.Socket[key]; ok {
		name := ctx.CurrentStraceCall.CallName + "$" + suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[name]
	}
}

func ioctl(ctx *Context) {
	val := ctx.CurrentStraceCall.Args[1].Eval(ctx.Target)
	if name, ok := ctx.Call2Variant.Ioctl[val]; ok {
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[name]
	}
}

func fcntl(ctx *Context) {
	val := ctx.CurrentStraceCall.Args[1].Eval(ctx.Target)
	if name, ok := ctx.Call2Variant.Fcntl[val]; ok {
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[name]
	}
}

func connectCalls(ctx *Context) {
	/*
	Connection system calls can take on many subforms such as
	accept$inet
	bind$inet6

	In order to determine the proper form we need to look at the file descriptor to determine
	the proper socket type. We refer to the $inet as a suffix to the name
*/
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	var arg prog.Arg
	if arg = ctx.ReturnCache.get(syzFd, straceFd); arg == nil {
		return
	}
	switch a := arg.Type().(type) {
	case *prog.ResourceType:
		//Start with most descriptive type and see if there is a match
		//Then work backwards to more general resource types
		var suffix string
		for i := len(a.Desc.Kind)-1; i > -1; i-- {
			if suffix = ctx.Call2Variant.ConnectionCalls[a.Desc.Kind[i]]; suffix == "" {
				continue
			}
			syzName := ctx.CurrentStraceCall.CallName + "$" + suffix
			ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[syzName]
			return
		}
	}
}

func getSetsockoptCalls(ctx *Context) {
	sockLevel := ctx.CurrentStraceCall.Args[1]
	optName := ctx.CurrentStraceCall.Args[2]
	pair := pair{
		A: fmt.Sprint(sockLevel.Eval(ctx.Target)),
		B: fmt.Sprint(optName.Eval(ctx.Target)),
	}
	if suffix, ok := ctx.Call2Variant.GetSetsockopt[pair]; ok {
		syzName := ctx.CurrentStraceCall.CallName + "$" + suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[syzName]
	}
}

func open(ctx *Context) {
	if len(ctx.CurrentStraceCall.Args) >= 3 {
		return
	}
	ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
		newExpression(newIntType(int64(0))))
}

func mknod(ctx *Context) {
	if len(ctx.CurrentStraceCall.Args) >= 3 {
		return
	}
	ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
		newExpression(newIntType(int64(0))))
}

func openat(ctx *Context) {
	if len(ctx.CurrentSyzCall.Args) >= 4 {
		return
	}
	ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
		newExpression(newIntType(int64(0))))
}

func prctl(ctx *Context) {
	prctlCmd := ctx.CurrentStraceCall.Args[0].String()
	variantName := ctx.CurrentStraceCall.CallName+"$"+prctlCmd
	if _, ok := ctx.Target.SyscallMap[variantName]; !ok {
		return
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[variantName]
}

func shmctl(ctx *Context) {
	shmctlCmd := ctx.CurrentStraceCall.Args[1].String()
	variantName := ctx.CurrentStraceCall.CallName+"$"+shmctlCmd
	if _, ok := ctx.Target.SyscallMap[variantName]; !ok {
		return
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[variantName]
}

func modifyLdt(ctx *Context) {
	suffix := ""
	switch a := ctx.CurrentStraceCall.Args[0].(type) {
	case *expression:
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
		log.Fatalf("Preprocess modifyldt received unexpected strace type: %s\n", a.Name())
	}
	ctx.CurrentStraceCall.CallName = ctx.CurrentStraceCall.CallName + suffix
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func shmget(ctx *Context) {
	if ctx.CurrentStraceCall.Ret <= 0 {
		//We have a successful shmget
		return
	}
	switch a := ctx.CurrentStraceCall.Args[1].(type) {
	case *expression:
		size := a.Eval(ctx.Target)
		ctx.State.Tracker.addShmRequest(uint64(ctx.CurrentStraceCall.Ret), size)
	default:
		log.Fatalf("shmctl could not evaluate size of buffer: %#v\n", a)
	}
}
