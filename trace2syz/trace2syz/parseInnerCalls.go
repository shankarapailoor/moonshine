package trace2syz

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"strconv"
	"strings"
)

func parseInnerCall(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	switch traceType.CallName {
	case "htons":
		return htonsHtonl(syzType, traceType, ctx)
	case "htonl":
		return htonsHtonl(syzType, traceType, ctx)
	case "inet_addr":
		return inetAddr(syzType, traceType, ctx)
	case "inet_pton":
		return inetPton(syzType, traceType, ctx)
	case "makedev":
		return makedev(syzType, traceType, ctx)
	default:
		log.Fatalf("Inner Call: %s Unsupported", traceType.CallName)
	}
	return nil
}

func makedev(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	var major, minor, id int64

	arg1 := traceType.Args[0].(*expression)
	arg2 := traceType.Args[1].(*expression)
	major = int64(arg1.Eval(ctx.Target))
	minor = int64(arg2.Eval(ctx.Target))

	id = ((minor & 0xff) | ((major & 0xfff) << 8) | ((minor & ^0xff) << 12) | ((major & ^0xfff) << 32))

	return prog.MakeConstArg(syzType, uint64(id))

}

func htonsHtonl(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	if len(traceType.Args) > 1 {
		panic("Parsing Htons/Htonl...it has more than one arg.")
	}
	switch typ := syzType.(type) {
	case *prog.ProcType:
		switch a := traceType.Args[0].(type) {
		case *expression:
			val := a.Eval(ctx.Target)
			if val >= typ.ValuesPerProc {
				return prog.MakeConstArg(syzType, typ.ValuesPerProc-1)
			}
			return prog.MakeConstArg(syzType, val)
		default:
			panic("First arg of Htons/Htonl is not expression")
		}
	case *prog.ConstType, *prog.IntType, *prog.FlagsType:
		switch a := traceType.Args[0].(type) {
		case *expression:
			val := a.Eval(ctx.Target)
			return prog.MakeConstArg(syzType, val)
		default:
			panic("First arg of Htons/Htonl is not expression")
		}
	default:
		log.Fatalf("First arg of Htons/Htonl is not const Type: %s\n", syzType.Name())
	}
	return nil
}

func inetAddr(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	var ip uint64
	inet_addr := func (ipaddr string) uint64 {
		var (
			ip                 = strings.Split(ipaddr, ".")
			ip1, ip2, ip3, ip4 uint64
			ret                uint64
		)
		ip1, _ = strconv.ParseUint(ip[0], 10, 8)
		ip2, _ = strconv.ParseUint(ip[1], 10, 8)
		ip3, _ = strconv.ParseUint(ip[2], 10, 8)
		ip4, _ = strconv.ParseUint(ip[3], 10, 8)
		ret = ip1<<24 + ip2<<16 + ip3<<8 + ip4
		return ret
	}
	if len(traceType.Args) > 1 {
		panic("Parsing InetAddr...it has more than one arg.")
	}
	switch a := traceType.Args[0].(type) {
	case *ipType:
		ip = inet_addr(a.Str)
	default:
		log.Fatalf("Parsing inet_addr and inner arg has non ipv4 type")
	}
	switch a := syzType.(type) {
	case *prog.UnionType:
		for _, field := range(a.Fields) {
			if !strings.Contains(field.FieldName(), "rand") {
				continue
			}
			switch field.(type) {
			case *prog.IntType:
				return prog.MakeUnionArg(syzType, prog.MakeConstArg(field, ip))
			default:
				log.Fatalf("Rand field isn't int type. Instead is %s", field.Name())
			}
		}
	default:
		log.Fatalf("Parsing ip address for non-union type %s", a.Name())
	}
	log.Logf(4, "Generating default arg for ip address")
	return prog.DefaultArg(syzType)
}

func inetPton(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	log.Logf(4, "type name: %s", syzType.Name())
	unionType := syzType.(*prog.UnionType)
	var optType prog.Type
	var innerArg prog.Arg
	if len(traceType.Args) != 3 {
		log.Fatalf("InetPton expects 3 args: %v.", traceType.Args)
	}
	switch a := traceType.Args[1].(type) {
	case *ipType:
		switch a.Str {
		case "::":
			optType = unionType.Fields[0]
		case "::1":
			optType = unionType.Fields[3]
		default:
			optType = unionType.Fields[0]
		}
		innerArg = prog.DefaultArg(optType)
	default:
		panic("Parsing inet_addr and inner arg has non ipv4 type")
	}
	return prog.MakeUnionArg(syzType, innerArg)
}
