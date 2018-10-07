package trace2syz

import (
	"encoding/binary"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"math/rand"
	"strings"
)

type returnCache map[resourceDescription]prog.Arg

func newRCache() returnCache {
	return make(map[resourceDescription]prog.Arg)
}

func (r *returnCache) buildKey(syzType prog.Type) string {
	switch a := syzType.(type) {
	case *prog.ResourceType:
		return "ResourceType-" + a.Desc.Kind[0]
	default:
		log.Fatalf("Caching non resource type")
	}
	return ""
}

func (r *returnCache) cache(syzType prog.Type, traceType irType, arg prog.Arg) {
	log.Logf(2, "Caching resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	(*r)[resDesc] = arg
}

func (r *returnCache) get(syzType prog.Type, traceType irType) prog.Arg {
	log.Logf(2, "Fetching resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	if arg, ok := (*r)[resDesc]; ok {
		if arg != nil {
			log.Logf(2, "Cache hit for resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
			return arg
		}
	}
	return nil
}

type resourceDescription struct {
	Type string
	Val  string
}

//Context stores metadata related to a syzkaller program
//Currently we are embedding the State object within the Context.
// We should probably merge the two objects
type Context struct {
	ReturnCache       returnCache
	Prog              *prog.Prog
	CurrentStraceCall *Syscall
	CurrentSyzCall    *prog.Call
	CurrentStraceArg  irType
	State             *State
	Target            *prog.Target
	CallToCover       map[*prog.Call][]uint64
	Call2Variant      *CallVariantMap
	DependsOn         map[*prog.Call]map[*prog.Call]int
}

func newContext(target *prog.Target, variantMap *CallVariantMap) (ctx *Context) {
	ctx = &Context{}
	ctx.ReturnCache = newRCache()
	ctx.CurrentStraceCall = nil
	ctx.State = newState(target)
	ctx.CurrentStraceArg = nil
	ctx.Target = target
	ctx.CallToCover = make(map[*prog.Call][]uint64)
	ctx.Call2Variant = variantMap
	ctx.DependsOn = make(map[*prog.Call]map[*prog.Call]int)
	return
}

func (ctx *Context) FillOutMemory() {
	if err := ctx.State.Tracker.fillOutMemory(ctx.Prog); err != nil {
		log.Fatalf("Failed to fill out memory for prog: %s", err.Error())
	}
	totalMemory := ctx.State.Tracker.getTotalMemoryAllocations(ctx.Prog)
	log.Logf(2, "Total memory for program is: %d", totalMemory)
	if totalMemory == 0 {
		log.Logf(1, "Program requires no mmaps", totalMemory)
		return
	}
	mmapCall := ctx.Target.MakeMmap(0, totalMemory)
	calls := make([]*prog.Call, 0)
	calls = append(append(calls, mmapCall), ctx.Prog.Calls...)
	ctx.Prog.Calls = calls
}

//ParseTrace converts a trace to a syzkaller program
func GenSyzProg(trace *Trace, target *prog.Target, variantMap *CallVariantMap) (*Context) {
	syzProg := new(prog.Prog)
	syzProg.Target = target
	ctx := newContext(target, variantMap)
	ctx.Prog = syzProg
	var call *prog.Call
	for _, sCall := range trace.Calls {
		ctx.CurrentStraceCall = sCall
		if _, ok := unsupported[sCall.CallName]; ok {
			continue
		}
		if sCall.Paused {
			/*Probably a case where the call was killed by a signal like the following
			2179  wait4(2180,  <unfinished ...>
			2179  <... wait4 resumed> 0x7fff28981bf8, 0, NULL) = ? ERESTARTSYS
			2179  --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER, si_pid=2180, si_uid=0} ---
			*/
			continue
		}
		ctx.CurrentStraceCall = sCall

		if shouldSkip(ctx) {
			log.Logf(3, "Skipping call: %s", ctx.CurrentStraceCall.CallName)
			continue
		}
		if call = genCall(ctx); call == nil {
			continue
		}

		ctx.CallToCover[call] = sCall.Cover
		ctx.State.analyze(call)
		ctx.Target.AssignSizesCall(call)
		syzProg.Calls = append(syzProg.Calls, call)
	}
	return ctx
}

func genCall(ctx *Context) *prog.Call {
	log.Logf(2, "parsing call: %s", ctx.CurrentStraceCall.CallName)
	straceCall := ctx.CurrentStraceCall
	syzCallDef := ctx.Target.SyscallMap[straceCall.CallName]
	retCall := new(prog.Call)
	retCall.Meta = syzCallDef
	ctx.CurrentSyzCall = retCall

	preprocess(ctx)
	if ctx.CurrentSyzCall.Meta == nil {
		//A call like fcntl may have variants like fcntl$get_flag
		//but no generic fcntl system call in Syzkaller
		return nil
	}
	retCall.Ret = prog.MakeReturnArg(ctx.CurrentSyzCall.Meta.Ret)

	if call := ParseMemoryCall(ctx); call != nil {
		ctx.Target.SanitizeCall(call)
		return call
	}
	for i := range retCall.Meta.Args {
		var strArg irType
		if i < len(straceCall.Args) {
			strArg = straceCall.Args[i]
		}
		res := genArgs(retCall.Meta.Args[i], strArg, ctx)
		retCall.Args = append(retCall.Args, res)
	}
	genResult(retCall.Meta.Ret, straceCall.Ret, ctx)
	ctx.Target.SanitizeCall(retCall)
	return retCall
}

func genResult(syzType prog.Type, straceRet int64, ctx *Context) {
	if straceRet > 0 {
		//TODO: This is a hack NEED to refacto lexer to parser return values into strace types
		straceExpr := newExpression(newIntsType([]int64{straceRet}))
		switch syzType.(type) {
		case *prog.ResourceType:
			log.Logf(2, "Call: %s returned a resource type with val: %s",
				ctx.CurrentStraceCall.CallName, straceExpr.String())
			ctx.ReturnCache.cache(syzType, straceExpr, ctx.CurrentSyzCall.Ret)
		}
	}
}

func genArgs(syzType prog.Type, traceArg irType, ctx *Context) prog.Arg {
	if traceArg == nil {
		log.Logf(3, "Parsing syzType: %s, traceArg is nil. Generating default arg...", syzType.Name())
		return GenDefaultArg(syzType, ctx)
	}
	ctx.CurrentStraceArg = traceArg
	log.Logf(3, "Parsing Arg of syz type: %s, ir type: %s", syzType.Name(), traceArg.Name())

	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.CsumType:
		return genConst(a, traceArg, ctx)
	case *prog.LenType:
		return GenDefaultArg(syzType, ctx)
	case *prog.ProcType:
		return parseProc(a, traceArg, ctx)
	case *prog.ResourceType:
		return genResource(a, traceArg, ctx)
	case *prog.PtrType:
		return genPtr(a, traceArg, ctx)
	case *prog.BufferType:
		return genBuffer(a, traceArg, ctx)
	case *prog.StructType:
		return genStruct(a, traceArg, ctx)
	case *prog.ArrayType:
		return genArray(a, traceArg, ctx)
	case *prog.UnionType:
		return genUnionArg(a, traceArg, ctx)
	case *prog.VmaType:
		return genVma(a, traceArg, ctx)
	default:
		log.Fatalf("Unsupported  Type: %v", syzType)
	}
	return nil
}

func genVma(syzType *prog.VmaType, traceType irType, ctx *Context) prog.Arg {
	var npages uint64 = 1
	// TODO: strace doesn't give complete info, need to guess random page range
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = syzType.RangeEnd
	}
	arg := prog.MakeVmaPointerArg(syzType, 0, npages)
	ctx.State.Tracker.addAllocation(ctx.CurrentSyzCall, ctx.Target.PageSize, arg)
	return arg
}

func genArray(syzType *prog.ArrayType, traceType irType, ctx *Context) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *arrayType:
		if syzType.Dir() == prog.DirOut {
			return GenDefaultArg(syzType, ctx)
		}
		for i := 0; i < a.Len; i++ {
			args = append(args, genArgs(syzType.Type, a.Elems[i], ctx))
		}
	case *field:
		return genArray(syzType, a.Val, ctx)
	case *pointerType, *expression, *bufferType:
		return GenDefaultArg(syzType, ctx)
	default:
		log.Fatalf("Error parsing Array: %s with Wrong Type: %s", syzType.FldName, traceType.Name())
	}
	return prog.MakeGroupArg(syzType, args)
}

func genStruct(syzType *prog.StructType, traceType irType, ctx *Context) prog.Arg {
	traceType = preprocessStruct(syzType, traceType, ctx)
	args := make([]prog.Arg, 0)
	switch a := traceType.(type) {
	case *structType:
		reorderStructFields(syzType, a, ctx)
		args = append(args, evalFields(syzType.Fields, a.Fields, ctx)...)
	case *arrayType:
		//Syzkaller's pipe definition expects a pipefd struct
		//But strace returns an array type
		args = append(args, evalFields(syzType.Fields, a.Elems, ctx)...)
	case *field:
		return genArgs(syzType, a.Val, ctx)
		log.Fatalf("Error parsing struct field: %#v", ctx)
	case *call:
		args = append(args, parseInnerCall(syzType, a, ctx))
	case *expression:
		return GenDefaultArg(syzType, ctx)
	case *bufferType:
		return serialize(syzType, []byte(a.Val), ctx)
	default:
		log.Fatalf("Unsupported Strace Type: %#v to Struct Type", a)
	}
	return prog.MakeGroupArg(syzType, args)
}

func evalFields(syzFields []prog.Type, straceFields []irType, ctx *Context) []prog.Arg {
	var args []prog.Arg
	j := 0
	for i := range syzFields {
		if prog.IsPad(syzFields[i]) {
			args = append(args, prog.DefaultArg(syzFields[i]))
		} else {
			if j >= len(straceFields) {
				args = append(args, GenDefaultArg(syzFields[i], ctx))
			} else {
				args = append(args, genArgs(syzFields[i], straceFields[j], ctx))
			}
			j++
		}
	}
	return args
}

func genUnionArg(syzType *prog.UnionType, straceType irType, ctx *Context) prog.Arg {
	log.Logf(4, "Generating union arg: %s %s", syzType.TypeName, straceType.Name())
	switch strType := straceType.(type) {
	case *field:
		switch strValType := strType.Val.(type) {
		case *call:
			return parseInnerCall(syzType, strValType, ctx)
		default:
			return genUnionArg(syzType, strType.Val, ctx)
		}
	case *call:
		return parseInnerCall(syzType, strType, ctx)
	default:
		idx := identifyUnionType(syzType, ctx, syzType.TypeName)
		innerType := syzType.Fields[idx]
		return prog.MakeUnionArg(syzType, genArgs(innerType, straceType, ctx))
	}
	return nil
}

func identifyUnionType(syzType *prog.UnionType, ctx *Context, typeName string) int {
	log.Logf(4, "Identifying union arg: %s", syzType.TypeName)
	switch typeName {
	case "sockaddr_storage":
		return identifySockaddrStorage(syzType, ctx)
	case "sockaddr_nl":
		return identifySockaddrNetlinkUnion(syzType, ctx)
	case "ifr_ifru":
		return identifyIfrIfruUnion(ctx)
	case "ifconf":
		return identifyIfconfUnion(ctx)
	case "bpf_instructions":
		return 0
	case "bpf_insn":
		return 1
	}
	return 0
}

func identifySockaddrStorage(syzType *prog.UnionType, ctx *Context) int {
	field2Opt := make(map[string]int)
	for i, field := range(syzType.Fields) {
		field2Opt[field.FieldName()] = i
	}
	//We currently look at the first argument of the system call
	//To determine which option of the union we select.
	call := ctx.CurrentStraceCall
	var straceArg irType
	switch call.CallName {
	//May need to handle special cases.
	case "recvfrom":
		straceArg = call.Args[4]
	default:
		if len(call.Args) >= 2 {
			straceArg = call.Args[1]
		} else {
			log.Fatalf("Unable identify union for sockaddr_storage for call: %s",
				call.CallName)
		}
	}
	switch strType := straceArg.(type) {
	case *structType:
		for i := range strType.Fields {
			fieldStr := strType.Fields[i].String()
			if strings.Contains(fieldStr, "AF_INET6") {
				return field2Opt["in6"]
			} else if strings.Contains(fieldStr, "AF_INET") {
				return field2Opt["in"]
			} else if strings.Contains(fieldStr, "AF_UNIX") {
				return field2Opt["un"]
			} else if strings.Contains(fieldStr, "AF_NETLINK") {
				return field2Opt["nl"]
			} else {
				log.Fatalf("Unable to identify option for sockaddr storage union." +
					" Field is: %s", fieldStr)
			}
		}
	default:
		log.Fatalf("Failed to parse Sockaddr Stroage Union Type. Strace Type: %#v", strType)
	}
	return -1
}

func identifySockaddrNetlinkUnion(syzType *prog.UnionType, ctx *Context) int {
	field2Opt := make(map[string]int)
	for i, field := range(syzType.Fields) {
		field2Opt[field.FieldName()] = i
	}
	switch a := ctx.CurrentStraceArg.(type) {
	case *structType:
		if len(a.Fields) > 2 {
			switch b := a.Fields[1].(type) {
			case *expression:
				pid := b.Eval(ctx.Target)
				if pid > 0 {
					//User
					return field2Opt["proc"]
				} else if pid == 0 {
					//Kernel
					return field2Opt["kern"]
				} else {
					//Unspec
					return field2Opt["unspec"]
				}
			case *field:
				curArg := ctx.CurrentStraceArg
				ctx.CurrentStraceArg = b.Val
				idx := identifySockaddrNetlinkUnion(syzType, ctx)
				ctx.CurrentStraceArg = curArg
				return idx
			default:
				log.Fatalf("Parsing netlink addr struct and expect expression for first arg: %s", a.Name())
			}
		}
	}
	return 2
}

func identifyIfrIfruUnion(ctx *Context) int {
	switch ctx.CurrentStraceArg.(type) {
	case *expression:
		return 2
	case *field:
		return 2
	default:
		return 0
	}
}

func identifyIfconfUnion(ctx *Context) int {
	switch ctx.CurrentStraceArg.(type) {
	case *structType:
		return 1
	default:
		return 0
	}
}

func genBuffer(syzType *prog.BufferType, traceType irType, ctx *Context) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		if !syzType.Varlen() {
			return prog.MakeOutDataArg(syzType, syzType.Size())
		}
		switch a := traceType.(type) {
		case *bufferType:
			return prog.MakeOutDataArg(syzType, uint64(len(a.Val)))
		case *field:
			return genBuffer(syzType, a.Val, ctx)
		default:
			switch syzType.Kind {
			case prog.BufferBlobRand:
				size := rand.Intn(256)
				return prog.MakeOutDataArg(syzType, uint64(size))

			case prog.BufferBlobRange:
				max := rand.Intn(int(syzType.RangeEnd) - int(syzType.RangeBegin) + 1)
				size := max + int(syzType.RangeBegin)
				return prog.MakeOutDataArg(syzType, uint64(size))
			default:
				panic(fmt.Sprintf("unexpected buffer type kind: %v. call %v arg %v", syzType.Kind, ctx.CurrentSyzCall, traceType))
			}
		}
	}
	var bufVal []byte
	switch a := traceType.(type) {
	case *bufferType:
		bufVal = []byte(a.Val)
	case *expression:
		val := a.Eval(ctx.Target)
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *pointerType:
		val := a.Address
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *arrayType:
		//
	case *structType:
		return GenDefaultArg(syzType, ctx)
	case *field:
		return genArgs(syzType, a.Val, ctx)
	default:
		log.Fatalf("Cannot parse type %#v for Buffer Type\n", traceType)
	}
	if !syzType.Varlen() {
		size := syzType.Size()
		for uint64(len(bufVal)) < size {
			bufVal = append(bufVal, 0)
		}
		bufVal = bufVal[:size]
	}
	return prog.MakeDataArg(syzType, bufVal)
}

func genPtr(syzType *prog.PtrType, traceType irType, ctx *Context) prog.Arg {
	switch a := traceType.(type) {
	case *pointerType:
		if a.IsNull() {
			return prog.DefaultArg(syzType)
		}
		if a.Res == nil {
			res := GenDefaultArg(syzType.Type, ctx)
			return addr(ctx, syzType, res.Size(), res)
		}
		res := genArgs(syzType.Type, a.Res, ctx)
		return addr(ctx, syzType, res.Size(), res)

	case *expression:
		//Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := GenDefaultArg(syzType.Type, ctx)
		return addr(ctx, syzType, res.Size(), res)
	default:
		res := genArgs(syzType.Type, a, ctx)
		return addr(ctx, syzType, res.Size(), res)
	}
	return nil
}

func genConst(syzType prog.Type, traceType irType, ctx *Context) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		return prog.DefaultArg(syzType)
	}
	switch a := traceType.(type) {
	case *expression:
		if a.IntsType != nil && len(a.IntsType) >= 2 {
			/*
				 	May get here through select. E.g. select(2, [6, 7], ..) since Expression can
					 be Ints. However, creating fd set is hard and we let default arg through
			*/
			return GenDefaultArg(syzType, ctx)
		}
		return prog.MakeConstArg(syzType, a.Eval(ctx.Target))
	case *dynamicType:
		return prog.MakeConstArg(syzType, a.BeforeCall.Eval(ctx.Target))
	case *arrayType:
		/*
			Sometimes strace represents a pointer to int as [0] which gets parsed
			as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]).
		*/
		if a.Len == 0 {
			log.Fatalf("Parsing const type. Got array type with len 0: %#v", ctx)
		}
		return genConst(syzType, a.Elems[0], ctx)
	case *structType:
		/*
			Sometimes system calls have an int type that is actually a union. Strace will represent the union
			like a struct e.g.
			sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
			For now we choose the first option
		*/
		return genConst(syzType, a.Fields[0], ctx)
	case *field:
		//We have an argument of the form sin_port=IntType(0)
		return genArgs(syzType, a.Val, ctx)
	case *call:
		//We have likely hit a call like inet_pton, htonl, etc
		return parseInnerCall(syzType, a, ctx)
	case *bufferType:
		//The call almost certainly an error or missing fields
		return GenDefaultArg(syzType, ctx)
		//E.g. ltp_bind01 two arguments are empty and
	case *pointerType:
		/*
			This can be triggered by the following:
			2435  connect(3, {sa_family=0x2f ,..., 16)*/
		return prog.MakeConstArg(syzType, a.Address)
	default:
		log.Fatalf("Cannot convert Strace Type: %s to Const Type", traceType.Name())
	}
	return nil
}

func genResource(syzType *prog.ResourceType, traceType irType, ctx *Context) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		log.Logf(2, "Resource returned by call argument: %s\n", traceType.String())
		res := prog.MakeResultArg(syzType, nil, syzType.Default())
		ctx.ReturnCache.cache(syzType, traceType, res)
		return res
	}
	switch a := traceType.(type) {
	case *expression:
		val := a.Eval(ctx.Target)
		if arg := ctx.ReturnCache.get(syzType, traceType); arg != nil {
			res := prog.MakeResultArg(syzType, arg.(*prog.ResultArg), syzType.Default())
			return res
		}
		res := prog.MakeResultArg(syzType, nil, val)
		return res
	case *field:
		return genResource(syzType, a.Val, ctx)
	default:
		log.Fatalf("Resource Type only supports Expression")
	}
	return nil
}

func parseProc(syzType *prog.ProcType, traceType irType, ctx *Context) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		return GenDefaultArg(syzType, ctx)
	}
	switch a := traceType.(type) {
	case *expression:
		val := a.Eval(ctx.Target)
		if val >= syzType.ValuesPerProc {
			return prog.MakeConstArg(syzType, syzType.ValuesPerProc-1)
		}
		return prog.MakeConstArg(syzType, val)
	case *field:
		return genArgs(syzType, a.Val, ctx)
	case *call:
		return parseInnerCall(syzType, a, ctx)
	case *bufferType:
		/* Again probably an error case
		   Something like the following will trigger this
		    bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
		*/
		return GenDefaultArg(syzType, ctx)
	default:
		log.Fatalf("Unsupported Type for Proc: %#v\n", traceType)
	}
	return nil
}

func GenDefaultArg(syzType prog.Type, ctx *Context) prog.Arg {
	switch a := syzType.(type) {
	case *prog.PtrType:
		res := prog.DefaultArg(a.Type)
		return addr(ctx, syzType, res.Size(), res)
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.ProcType, *prog.CsumType:
		return prog.DefaultArg(a)
	case *prog.BufferType:
		return prog.DefaultArg(a)
	case *prog.StructType:
		var inner []prog.Arg
		for _, field := range a.Fields {
			inner = append(inner, GenDefaultArg(field, ctx))
		}
		return prog.MakeGroupArg(a, inner)
	case *prog.UnionType:
		optType := a.Fields[0]
		return prog.MakeUnionArg(a, GenDefaultArg(optType, ctx))
	case *prog.ArrayType:
		return prog.DefaultArg(syzType)
	case *prog.ResourceType:
		return prog.MakeResultArg(syzType, nil, a.Default())
	case *prog.VmaType:
		return prog.DefaultArg(syzType)
	default:
		log.Fatalf("Unsupported Type: %#v", syzType)
	}
	return nil
}

func serialize(syzType prog.Type, buf []byte, ctx *Context) prog.Arg {
	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.CsumType:
		return prog.MakeConstArg(a, bufToUint(buf[:syzType.Size()]))
	case *prog.ProcType:
		return GenDefaultArg(syzType, ctx)
	case *prog.PtrType:
		res := serialize(a.Type, buf, ctx)
		return addr(ctx, a, res.Size(), res)
	case *prog.StructType:
		pos := uint64(0)
		bufLen := uint64(len(buf))
		args := make([]prog.Arg, 0)
		for _, field := range a.Fields {
			if pos+field.Size() >= bufLen {
				args = append(args, GenDefaultArg(field, ctx))
				continue
			} else {
				args = append(args, serialize(field, buf[pos:pos+field.Size()], ctx))
			}
			pos += field.Size()
		}
		return prog.MakeGroupArg(syzType, args)
	default:
		log.Fatalf("Unsupported Type: %s", a.Name())
	}
	return nil
}

func bufToUint(buf []byte) uint64 {
	switch len(buf) {
	case 1:
		return uint64(buf[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(buf))
	case 4:
		return uint64(binary.LittleEndian.Uint32(buf))
	case 8:
		return binary.LittleEndian.Uint64(buf)
	default:
		panic("Failed to convert byte to int")
	}
}

func addr(ctx *Context, syzType prog.Type, size uint64, data prog.Arg) prog.Arg {
	arg := prog.MakePointerArg(syzType, uint64(0), data)
	ctx.State.Tracker.addAllocation(ctx.CurrentSyzCall, size, arg)
	return arg
}

func reorderStructFields(syzType *prog.StructType, traceType *structType, ctx *Context) {
	/*
		Sometimes strace reports struct fields out of order compared to Syzkaller.
		Example: 5704  bind(3, {sa_family=AF_INET6,
					sin6_port=htons(8888),
					inet_pton(AF_INET6, "::", &sin6_addr),
					sin6_flowinfo=htonl(2206138368),
					sin6_scope_id=2049825634}, 128) = 0
		The flow_info and pton fields are switched in Syzkaller
	*/
	switch syzType.TypeName {
	case "sockaddr_in6":
		log.Logf(5, "Reordering in6")
		field2 := traceType.Fields[2]
		traceType.Fields[2] = traceType.Fields[3]
		traceType.Fields[3] = field2
	case "bpf_insn_generic", "bpf_insn_exit", "bpf_insn_alu", "bpf_insn_jmp", "bpf_insn_ldst":
		fmt.Printf("bpf_insn_generic size: %d, typsize: %d\n", syzType.Size(), syzType.TypeSize)
		reg := (traceType.Fields[1].Eval(ctx.Target)) | (traceType.Fields[2].Eval(ctx.Target) << 4)
		newFields := make([]irType, len(traceType.Fields)-1)
		newFields[0] = traceType.Fields[0]
		newFields[1] = newExpression(newIntType(int64(reg)))
		newFields[2] = traceType.Fields[3]
		newFields[3] = traceType.Fields[4]
		traceType.Fields = newFields
	}
}

func genDefaultTraceType(syzType prog.Type) irType {
	switch a := syzType.(type) {
	case *prog.StructType:
		straceFields := make([]irType, len(a.Fields))
		for i := 0; i < len(straceFields); i++ {
			straceFields[i] = genDefaultTraceType(a.Fields[i])
		}
		return newStructType(straceFields)
	case *prog.ArrayType:
		straceFields := make([]irType, 1)
		straceFields[0] = genDefaultTraceType(a.Type)
		return newArrayType(straceFields)
	case *prog.ConstType, *prog.ProcType, *prog.LenType, *prog.FlagsType, *prog.IntType:
		return newExpression(newIntType(0))
	case *prog.PtrType:
		return newPointerType(0, genDefaultTraceType(a.Type))
	case *prog.UnionType:
		return genDefaultTraceType(a.Fields[0])
	default:
		log.Fatalf("Unsupported syz type for generating default strace type: %s", syzType.Name())
	}
	return nil
}

func shouldSkip(ctx *Context) bool {
	syscall := ctx.CurrentStraceCall
	switch syscall.CallName {
	case "write":
		switch a := syscall.Args[0].(type) {
		case *expression:
			val := a.Eval(ctx.Target)
			if val == 1 || val == 2 {
				return true
			}
		}
	}
	return false
}
