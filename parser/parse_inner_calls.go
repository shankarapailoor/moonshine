package parser

import (
	"github.com/google/syzkaller/prog"
	. "github.com/shankarapailoor/moonshine/logging"
	"github.com/shankarapailoor/moonshine/straceTypes"
)

func ParseInnerCall(syzType prog.Type, straceType *straceTypes.Call, ctx *Context) prog.Arg {
	switch straceType.CallName {
	case "htons":
		return parse_HtonsHtonl(syzType, straceType, ctx)
	case "htonl":
		return parse_HtonsHtonl(syzType, straceType, ctx)
	case "inet_addr":
		return parse_InetAddr(syzType, straceType, ctx)
	case "inet_pton":
		return parse_InetPton(syzType, straceType, ctx)
	case "makedev":
		return parse_Makedev(syzType, straceType, ctx)
	default:
		Failf("Inner Call: %s Unsupported", straceType.CallName)
	}
	return nil
}

func parse_Makedev(syzType prog.Type, straceType *straceTypes.Call, ctx *Context) prog.Arg {
	var major, minor, id int64

	arg1 := straceType.Args[0].(*straceTypes.Expression)
	arg2 := straceType.Args[1].(*straceTypes.Expression)
	major = int64(arg1.Eval(ctx.Target))
	minor = int64(arg2.Eval(ctx.Target))

	id = ((minor & 0xff) | ((major & 0xfff) << 8) | ((minor & ^0xff) << 12) | ((major & ^0xfff) << 32))

	return straceTypes.ConstArg(syzType, uint64(id))

}

func parse_HtonsHtonl(syzType prog.Type, straceType *straceTypes.Call, ctx *Context) prog.Arg {
	if len(straceType.Args) > 1 {
		panic("Parsing Htons/Htonl...it has more than one arg.")
	}
	switch typ := syzType.(type) {
	case *prog.ProcType:
		switch a := straceType.Args[0].(type) {
		case *straceTypes.Expression:
			val := a.Eval(ctx.Target)
			if val >= typ.ValuesPerProc {
				return straceTypes.ConstArg(syzType, typ.ValuesPerProc-1)
			}
			return prog.MakeConstArg(syzType, val)
		default:
			panic("First arg of Htons/Htonl is not expression")
		}
	case *prog.ConstType, *prog.IntType, *prog.FlagsType:
		switch a := straceType.Args[0].(type) {
		case *straceTypes.Expression:
			val := a.Eval(ctx.Target)
			return prog.MakeConstArg(syzType, val)
		default:
			panic("First arg of Htons/Htonl is not expression")
		}
	default:
		Failf("First arg of Htons/Htonl is not const Type: %s\n", syzType.Name())
	}
	return nil
}

func parse_InetAddr(syzType prog.Type, straceType *straceTypes.Call, ctx *Context) prog.Arg {
	unionType := syzType.(*prog.UnionType)
	var optType prog.Type
	var inner_arg prog.Arg
	if len(straceType.Args) > 1 {
		panic("Parsing InetAddr...it has more than one arg.")
	}
	switch a := straceType.Args[0].(type) {
	case *straceTypes.IpType:
		switch a.Str {
		case "0.0.0.0":
			optType = unionType.Fields[0]
		case "127.0.0.1":
			optType = unionType.Fields[3]
		case "255.255.255.255":
			optType = unionType.Fields[6]
		default:
			optType = unionType.Fields[7]
		}
		inner_arg = ctx.Target.DefaultArg(optType)
	default:
		panic("Parsing inet_addr and inner arg has non ipv4 type")
	}
	return straceTypes.UnionArg(syzType, inner_arg)
}

func parse_InetPton(syzType prog.Type, straceType *straceTypes.Call, ctx *Context) prog.Arg {
	unionType := syzType.(*prog.UnionType)
	var optType prog.Type
	var inner_arg prog.Arg
	if len(straceType.Args) != 3 {
		Failf("InetPton expects 3 args: %v.", straceType.Args)
	}
	switch a := straceType.Args[1].(type) {
	case *straceTypes.IpType:
		switch a.Str {
		case "::":
			optType = unionType.Fields[0]
		case "::1":
			optType = unionType.Fields[3]
		default:
			optType = unionType.Fields[0]
		}
		inner_arg = ctx.Target.DefaultArg(optType)
	default:
		panic("Parsing inet_addr and inner arg has non ipv4 type")
	}
	return straceTypes.UnionArg(syzType, inner_arg)
}
