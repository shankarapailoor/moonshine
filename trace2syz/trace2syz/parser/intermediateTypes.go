package trace2syz

import (
	"bytes"
	"fmt"
	"github.com/google/syzkaller/prog"
	"strconv"
)

type Operation int

const (
	ORop       = iota //OR = |
	ANDop             //AND = &
	XORop             //XOR = ^
	NOTop             //NOT = !
	LSHIFTop          //LSHIFT = <<
	RSHIFTop          //RSHIFT = >>
	ONESCOMPop        //ONESCOMP = ~
	TIMESop           //TIMES = *
	LANDop            //LAND = &&
	LORop             //LOR = ||
	LEQUALop          //LEQUAL = ==
)

//TraceTree struct contains intermediate representation of trace
//If a trace is multiprocess it constructs a trace for each type
type TraceTree struct {
	TraceMap map[int64]*Trace
	Ptree    map[int64][]int64
	RootPid  int64
	Filename string
}

//NewTraceTree initializes a TraceTree
func NewTraceTree() (tree *TraceTree) {
	tree = &TraceTree{
		TraceMap: make(map[int64]*Trace),
		Ptree:    make(map[int64][]int64),
		RootPid:  -1,
	}
	return
}

func (tree *TraceTree) Contains(pid int64) bool {
	if _, ok := tree.TraceMap[pid]; ok {
		return true
	}
	return false
}

func (tree *TraceTree) Add(call *Syscall) *Syscall {
	if tree.RootPid < 0 {
		tree.RootPid = call.Pid
	}
	if !call.Resumed {
		if !tree.Contains(call.Pid) {
			tree.TraceMap[call.Pid] = newTrace()
			tree.Ptree[call.Pid] = make([]int64, 0)
		}
	}
	c := tree.TraceMap[call.Pid].Add(call)
	if c.CallName == "clone" && !c.Paused {
		tree.Ptree[c.Pid] = append(tree.Ptree[c.Pid], c.Ret)
	}
	return c
}

func (tree *TraceTree) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Root: %d\n", tree.RootPid))
	buf.WriteString(fmt.Sprintf("Pids: %d\n", len(tree.TraceMap)))
	return buf.String()
}

//Trace is just a list of system calls
type Trace struct {
	Calls []*Syscall
}

//newTrace initializes a new trace
func newTrace() (trace *Trace) {
	trace = &Trace{Calls: make([]*Syscall, 0)}
	return
}

func (trace *Trace) Add(call *Syscall) (ret *Syscall) {
	if call.Resumed {
		lastCall := trace.Calls[len(trace.Calls)-1]
		lastCall.Args = append(lastCall.Args, call.Args...)
		lastCall.Paused = false
		lastCall.Ret = call.Ret
		ret = lastCall
	} else {
		trace.Calls = append(trace.Calls, call)
		ret = call
	}
	return
}

//Syscall struct is the IR type for any system call
type Syscall struct {
	CallName string
	Args     []IrType
	Pid      int64
	Ret      int64
	Cover    []uint64
	Paused   bool
	Resumed  bool
}

//NewSyscall - constructor
func NewSyscall(pid int64, name string, args []IrType, ret int64, paused, resumed bool) (sys *Syscall) {
	sys = new(Syscall)
	sys.CallName = name
	sys.Args = args
	sys.Pid = pid
	sys.Ret = ret
	sys.Paused = paused
	sys.Resumed = resumed
	return
}

//String
func (s *Syscall) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Pid: %d-", s.Pid))
	buf.WriteString(fmt.Sprintf("Name: %s-", s.CallName))
	for _, typ := range s.Args {
		buf.WriteString("-")
		buf.WriteString(typ.String())
		buf.WriteString("-")
	}
	buf.WriteString(fmt.Sprintf("-Ret: %d\n", s.Ret))
	return buf.String()
}

type IrType interface {
	Name() string
	String() string
}

type Call struct {
	CallName string
	Args     []IrType
}

func NewCallType(name string, args []IrType) (typ *Call) {
	typ = new(Call)
	typ.CallName = name
	typ.Args = args
	return
}

func (c *Call) Name() string {
	return "Call Type"
}

func (c *Call) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + c.CallName + "\n")
	for _, arg := range c.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

type DynamicType struct {
	BeforeCall Expression
	AfterCall Expression
}

type MacroType struct {
	ExpressionCommon
	MacroName string
	Args      []IrType
}

type Expression interface {
	IrType
	Eval(*prog.Target) uint64
}

type ExpressionCommon struct {
}

func (e *ExpressionCommon) Name() string{
	return "Expression Type"
}

type BinOp struct {
	ExpressionCommon
	LeftOperand Expression
	Op Operation
	RightOperand Expression
}

type UnOp struct {
	ExpressionCommon
	Operand Expression
	Op Operation
}


func (b *BinOp) Eval(target *prog.Target) uint64 {
	op1Eval := b.LeftOperand.Eval(target)
	op2Eval := b.RightOperand.Eval(target)
	switch b.Op {
	case ANDop:
		return op1Eval & op2Eval
	case ORop:
		return op1Eval | op2Eval
	case XORop:
		return op1Eval ^ op2Eval
	case LSHIFTop:
		return op1Eval << op2Eval
	case RSHIFTop:
		return op1Eval >> op2Eval
	case TIMESop:
		return op1Eval * op2Eval
	default:
		panic("Operator Not handled")
	}
}

func (b *BinOp) String() string {
	return fmt.Sprintf("Relation Expression is Binop. "+
		"Op 1: %s, Operation: %v, "+
		"Op 2: %s\n", b.LeftOperand, b.Op, b.RightOperand)
}

type parenthetical struct {
	tmp string
}

func newParenthetical() *parenthetical {
	return &parenthetical{tmp: "tmp"}
}


func NewMacroType(name string, args []IrType) (typ *MacroType) {
	typ = new(MacroType)
	typ.MacroName = name
	typ.Args = args
	return
}


func (m *MacroType) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + m.MacroName + "\n")
	for _, arg := range m.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

func (m *MacroType) Eval(target *prog.Target) uint64 {
	switch m.MacroName {
	case "KERNEL_VERSION":
		arg1 := m.Args[0].(Expression)
		arg2 := m.Args[1].(Expression)
		arg3 := m.Args[2].(Expression)
		return (arg1.Eval(target) << 16) + (arg2.Eval(target) << 8) + arg3.Eval(target)
	}
	panic("Eval called on macro type")
}

type Field struct {
	Key string
	Val IrType
}

func NewField(key string, val IrType) (f *Field) {
	f = new(Field)
	f.Key = key
	f.Val = val
	return
}

func (f *Field) Name() string {
	return "Field Type"
}

func (f *Field) String() string {
	return f.Val.String()
}

type intType struct {
	Val int64
}

func newIntsType(vals []int64) ints {
	ints := make([]*intType, 0)
	for _, v := range vals {
		ints = append(ints, newIntType(v))
	}
	return ints
}

func newIntType(val int64) (typ *intType) {
	typ = new(intType)
	typ.Val = val
	return
}

func (i *intType) Eval(target *prog.Target) uint64 {
	return uint64(i.Val)
}

func (i *intType) Name() string {
	return "Int Type"
}

func (i *intType) String() string {
	return strconv.FormatInt(i.Val, 10)
}

type flags []*flagType

type ints []*intType

func (f flags) Eval(target *prog.Target) uint64 {
	if len(f) > 1 {
		var val uint64
		for _, flag := range f {
			val |= flag.Eval(target)
		}
		return val
	} else if len(f) == 1 {
		return f[0].Eval(target)
	} else {
		return 0
	}
}

func (f flags) Name() string {
	return "Flags Type"
}

func (f flags) String() string {
	if len(f) > 1 {
		panic("Cannot get string for set")
	} else if len(f) == 1 {
		return f[0].String()
	} else {
		return ""
	}
}
func (i ints) Eval(target *prog.Target) uint64 {
	if len(i) > 1 {
		panic("Unable to Evaluate Set")
	} else if len(i) == 1 {
		return i[0].Eval(target)
	} else {
		return 0
	}
}

func (i ints) Name() string {
	return "Flags Type"
}

func (i ints) String() string {
	if len(i) > 1 {
		panic("Cannot get string for set")
	} else if len(i) == 1 {
		return i[0].String()
	} else {
		return ""
	}
}

type flagType struct {
	Val string
}

func newFlagType(val string) (typ *flagType) {
	typ = new(flagType)
	typ.Val = val
	return
}

func (f *flagType) Eval(target *prog.Target) uint64 {
	if val, ok := target.ConstMap[f.String()]; ok {
		return val
	} else if val, ok := specialConsts[f.String()]; ok {
		return val
	}
	panic(fmt.Sprintf("Failed to eval flag: %s\n", f.String()))
}

func (f *flagType) Name() string {
	return "Flag Type"
}

func (f *flagType) String() string {
	return f.Val
}

type set struct {
	Exprs []*expression
}

func (b *set) Name() string {
	return "Set Type"
}

func (b *set) String() string {
	return ""
}

func (b *set) Eval(target *prog.Target) uint64 {
	panic("Eval called for set type\n")
}

type bufferType struct {
	Val string
}

func newBufferType(val string) (typ *bufferType) {
	typ = new(bufferType)
	typ.Val = val
	return
}

func (b *bufferType) Name() string {
	return "Buffer Type"
}

func (b *bufferType) String() string {
	return fmt.Sprintf("String Type: %d\n", len(b.Val))
}

func (b *bufferType) Eval(target *prog.Target) uint64 {
	panic("Eval called for buffer type")
}

type pointerType struct {
	Address uint64
	Res     irType
}

func newPointerType(addr uint64, res irType) (typ *pointerType) {
	typ = new(pointerType)
	typ.Res = res
	typ.Address = addr
	return
}

func nullPointer() (typ *pointerType) {
	typ = new(pointerType)
	typ.Address = 0
	typ.Res = newBufferType("")
	return
}

func (p *pointerType) IsNull() bool {
	return p.Address == 0
}

func (p *pointerType) Name() string {
	return "Pointer Type"
}

func (p *pointerType) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Address: %d\n", p.Address))
	buf.WriteString(fmt.Sprintf("Res: %s\n", p.Res.String()))
	return buf.String()
}

func (p *pointerType) Eval(target *prog.Target) uint64 {
	panic("Eval called for PointerType")
}

type structType struct {
	Fields []irType
}

func newStructType(types []irType) (typ *structType) {
	typ = new(structType)
	typ.Fields = types
	return
}

func (s *structType) Name() string {
	return "Struct Type"
}

func (s *structType) String() string {
	var buf bytes.Buffer

	buf.WriteString("{")
	for _, field := range s.Fields {
		buf.WriteString(field.String())
		buf.WriteString(",")
	}
	buf.WriteString("}")
	return buf.String()
}

func (s *structType) Eval(target *prog.Target) uint64 {
	panic("Eval Called For Struct Type")
}

type arrayType struct {
	Elems []irType
	Len   int
}

func newArrayType(elems []irType) (typ *arrayType) {
	typ = new(arrayType)
	typ.Elems = elems
	typ.Len = len(elems)
	return
}

func (a *arrayType) Name() string {
	return "Array Type"
}

func (a *arrayType) String() string {
	var buf bytes.Buffer

	buf.WriteString("[")
	for _, elem := range a.Elems {
		buf.WriteString(elem.String())
		buf.WriteString(",")
	}
	buf.WriteString("]")
	return buf.String()
}

func (a *arrayType) Eval(target *prog.Target) uint64 {
	panic("Eval called for Array Type")
}

type ipType struct {
	Str string
}

func newIPType(val string) (typ *ipType) {
	typ = new(ipType)
	typ.Str = val
	return
}

func (i *ipType) Name() string {
	return "Ip Type"
}

func (i *ipType) String() string {
	return fmt.Sprintf("Ip type :%s", i.Str)
}

func (i *ipType) Eval(target *prog.Target) uint64 {
	panic("Eval called for ip type")
}
