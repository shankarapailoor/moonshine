package strace_types

import (
	"fmt"
	"strconv"
	"bytes"
	"github.com/google/syzkaller/prog"
)

type Operation int
const (
	OR = iota
	AND
	XOR
	NOT
	LSHIFT
	RSHIFT
	ONESCOMP
	TIMES
	LAND
	LOR
	LEQUAL
)

var (
	Strace_ExpressionType = "Expression Type"
	Strace_CallType = "Call Type"
	Strace_IntType = "Int Type"
	Strace_FieldType = "Field Type"
	Strace_StructType = "Struct Type"
	Strace_ArrayType = "Array Type"
	Strace_PointerType = "Pointer Type"
	Strace_BufferType = "Buffer Type"
	Strace_FlagType = "Flag Type"
	Strace_Ipv4Type = "Ipv4 Type"

)

type TraceTree struct {
	TraceMap map[int64]*Trace
	Ptree map[int64][]int64
	RootPid int64
	Filename string
}

func NewTraceTree() (tree *TraceTree) {
	tree = &TraceTree {
		TraceMap: make(map[int64]*Trace),
		Ptree : make(map[int64][]int64),
		RootPid: -1,
	}
	return
}

func (tree *TraceTree) Contains(pid int64) bool {
	if _, ok := tree.TraceMap[pid]; ok {
		return true
	}
	return false
}


func (tree *TraceTree) Add(call *Syscall) (*Syscall){
	if tree.RootPid < 0 {
		tree.RootPid = call.Pid
	}
	if !call.Resumed {
		if !tree.Contains(call.Pid) {
			tree.TraceMap[call.Pid] = NewTrace()
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


type Trace struct {
	Calls []*Syscall
}

func NewTrace() (trace *Trace) {
	trace = &Trace{Calls: make([]*Syscall, 0)}
	return
}

func (trace *Trace) Add(call *Syscall) (ret *Syscall){
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



type Syscall struct {
	CallName string
	Args []Type
	Pid int64
	Ret int64
	Cover []uint64
	Paused bool
	Resumed bool
}

func NewSyscall(pid int64, name string,
			args []Type,
			ret int64,
			paused bool,
			resumed bool) (sys *Syscall) {
	sys = new(Syscall)
	sys.CallName = name
	sys.Args = args
	sys.Pid = pid
	sys.Ret = ret
	sys.Paused = paused
	sys.Resumed = resumed
	return
}

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

type Type interface {
	Name() string
	String() string
	Eval(*prog.Target) uint64
}

type DynamicType struct {
	BeforeCall *Expression
	AfterCall *Expression
}

func NewDynamicType(before, after Type) *DynamicType {
	return &DynamicType{BeforeCall:  before.(*Expression), AfterCall: after.(*Expression)}
}

func (d *DynamicType) String() string {
	return d.BeforeCall.String()
}

func (d *DynamicType) Name() string {
	return "Dynamic Type"
}

func (d *DynamicType) Eval(target *prog.Target) uint64 {
	panic("Eval called on DynamicType")
}

type Expression struct {
	BinOp *Binop
	Unop *Unop
	FlagType *FlagType
	FlagsType Flags
	IntType *IntType
	MacroType *Macro
	SetType *Set
	IntsType Ints
}

func NewExpression(typ Type) (exp *Expression) {
	exp = new(Expression)
	switch a := typ.(type) {
	case *Binop:
		exp.BinOp = a
	case *Unop:
		exp.Unop = a
	case *IntType:
		exp.IntType = a
	case *FlagType:
		exp.FlagType = a
	case Flags:
		exp.FlagsType = a
	case Ints:
		exp.IntsType = a
	case *Macro:
		exp.MacroType = a
	case *Set:
		exp.SetType = a
	default:
		panic(fmt.Sprintf("Expression received wrong type: %s", typ.Name()))
	}
	return
}

func (r *Expression) Name() string {
	return Strace_ExpressionType
}

func (r *Expression) String() string {
	if r.BinOp != nil {
		return fmt.Sprintf("Relation Expression is Binop. Op 1: %s, Operation: %v, Op 2: %s\n", r.BinOp.Operand1, r.BinOp.Op, r.BinOp.Operand2)
	} else if r.Unop != nil {
		return fmt.Sprintf("Relation Expression is Unop. Operand is: %v, op: %v\n", r.Unop.Operand, r.Unop.Op)

	} else if r.FlagType != nil {
		return r.FlagType.String()
	} else if r.FlagsType != nil {
		return r.FlagsType.String()
	} else if r.IntType != nil {
		return r.IntType.String()
	}
	return ""
}

func (e *Expression) Eval(target *prog.Target) uint64 {
	if e.BinOp != nil {
		return e.BinOp.Eval(target)
	} else if e.Unop != nil {
		return e.Unop.Eval(target)
	} else if e.FlagType != nil {
		return e.FlagType.Eval(target)
	} else if e.FlagsType != nil {
		return e.FlagsType.Eval(target)
	} else if e.IntType != nil {
		return e.IntType.Eval(target)
	} else if e.MacroType != nil {
		return e.MacroType.Eval(target)
	} else if e.IntsType != nil {
		return e.IntsType.Eval(target)
	}
	panic("Failed to eval expression")
}

type Parenthetical struct {
	tmp string
}

func NewParenthetical() *Parenthetical {
	return &Parenthetical{tmp:"tmp"};
}

type Macro struct {
	MacroName string
	Args []Type
}

func NewMacroType(name string, args []Type) (typ *Macro) {
	typ = new(Macro)
	typ.MacroName = name
	typ.Args = args
	return
}

func (m *Macro) Name() string {
	return "Macro"
}

func (m *Macro) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + m.MacroName + "\n")
	for _, arg := range m.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

func (m *Macro) Eval(target *prog.Target) uint64 {
	switch m.MacroName {
	case "KERNEL_VERSION":
		return (m.Args[0].Eval(target) << 16) + (m.Args[1].Eval(target) << 8) + m.Args[2].Eval(target)
	}
	panic("Eval called on macro type")
}

type Call struct {
	CallName string
	Args []Type
}

func NewCallType(name string, args []Type) (typ *Call){
	typ = new(Call)
	typ.CallName = name
	typ.Args = args
	return
}

func (c *Call) Name() string {
	return Strace_CallType
}

func (c *Call) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + c.CallName + "\n")
	for _, arg := range c.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

func (c *Call) Eval(target *prog.Target) uint64 {
	panic("Eval called on call type")
	return 0
}

type Binop struct {
	Operand1 *Expression
	Op Operation
	Operand2 *Expression
}

func NewBinop(operand1 Type, op Operation, operand2 Type) (b *Binop){
	b = new(Binop)
	b.Operand1 = operand1.(*Expression)
	b.Op = op
	b.Operand2 = operand2.(*Expression)
	return
}

func (b *Binop) Eval(target *prog.Target) uint64 {
	op1Eval := b.Operand1.Eval(target)
	op2Eval := b.Operand2.Eval(target)
	switch b.Op {
	case AND:
		return op1Eval & op2Eval
	case OR:
		return op1Eval | op2Eval
	case XOR:
		return op1Eval ^ op2Eval
	case LSHIFT:
		return op1Eval << op2Eval
	case RSHIFT:
		return op1Eval >> op2Eval
	case TIMES:
		return op1Eval * op2Eval
	default:
		panic("Operator Not handled")
	}
}

func (b *Binop) String() string{
	return fmt.Sprintf("op1: %s op2: %s, operand: %v\n", b.Operand1.String(), b.Operand2.String(), b.Op)
}

func (b *Binop) Name() string{
	return "Binop"
}

type Unop struct {
	Operand *Expression
	Op Operation
}

func NewUnop(operand Type, op Operation) (u *Unop) {
	u = new(Unop)
	u.Operand = operand.(*Expression)
	u.Op = op
	return
}

func (u *Unop) Eval(target *prog.Target) uint64 {
	opEval := u.Operand.Eval(target)
	switch u.Op {
	case ONESCOMP:
		return ^opEval
	default:
		panic("Unsupported Unop Op")
	}
}

func (u *Unop) String() string{
	return fmt.Sprintf("op1: %v operand: %v\n", u.Operand, u.Op)
}

func (u *Unop) Name() string{
	return "Unop"
}

type Field struct {
	Key string
	Val Type
}

func NewField(key string, val Type) (f *Field) {
	f = new(Field)
	f.Key = key
	f.Val = val
	return
}

func (f *Field) Name() string {
	return Strace_FieldType
}

func (f *Field) String() string {
	return f.Val.String()
}

func (f *Field) Eval(target *prog.Target) uint64 {
	return f.Val.Eval(target)
}

type IntType struct {
	Val int64
}

func NewIntsType(vals []int64) Ints {
	ints := make([]*IntType, 0)
	for _, v := range(vals) {
		ints = append(ints, NewIntType(v))
	}
	return ints
}

func NewIntType(val int64) (typ *IntType) {
	typ = new(IntType)
	typ.Val = val
	return
}

func (i *IntType) Eval(target *prog.Target) uint64 {
	return uint64(i.Val)
}

func (i *IntType) Name() string {
	return Strace_IntType
}

func (i *IntType) String() string {
	v := strconv.FormatInt(i.Val, 10)
 	return fmt.Sprintf("%s", v)
}

type Flags []*FlagType

type Ints []*IntType

func (f Flags) Eval(target *prog.Target) uint64 {
	if len(f) > 1 {
		panic("Unable to Evaluate Set")
	} else if len(f) == 1 {
		return f[0].Eval(target)
	} else {
		return 0
	}
}

func (f Flags) Name() string {
	return "Flags Type"
}

func (f Flags) String() string {
	if len(f) > 1 {
		panic("Cannot get string for set")
	} else if len(f) == 1 {
		return f[0].String()
	} else {
		return ""
	}
}
func (i Ints) Eval(target *prog.Target) uint64 {
	if len(i) > 1 {
		panic("Unable to Evaluate Set")
	} else if len(i) == 1 {
		return i[0].Eval(target)
	} else {
		return 0
	}
}

func (i Ints) Name() string {
	return "Flags Type"
}

func (i Ints) String() string {
	if len(i) > 1 {
		panic("Cannot get string for set")
	} else if len(i) == 1 {
		return i[0].String()
	} else {
		return ""
	}
}

type FlagType struct {
	Val string
}

func NewFlagType(val string) (typ *FlagType) {
	typ = new(FlagType)
	typ.Val = val
	return
}

func (f *FlagType) Eval(target *prog.Target) uint64 {
	if val, ok := target.ConstMap[f.String()]; ok {
		return val
	} else if val, ok := Special_Consts[f.String()]; ok {
		return val
	}
	panic(fmt.Sprintf("Failed to eval flag: %s\n", f.String()))
}


func (f *FlagType) Name() string {
	return Strace_FlagType
}

func (f *FlagType) String() string {
	return fmt.Sprintf("%s", f.Val)
}

type Set struct {
	Exprs []*Expression
}

func NewSet(exprs []*Expression) *Set{
	return &Set{
		Exprs: exprs,
	}
}

func (b *Set) Name() string {
	return "Set Type"
}

func (b *Set) String() string {
	return ""
}

func (b *Set) Eval(target *prog.Target) uint64 {
	panic("Eval called for set type\n")
}

type BufferType struct {
	Val string
}

func NewBufferType(val string) (typ *BufferType) {
	typ = new(BufferType)
	typ.Val = val
	return
}

func (b *BufferType) Name() string {
	return Strace_BufferType
}

func (b *BufferType) String() string {
	return fmt.Sprintf("String Type: %d\n", len(b.Val))
}

func (b *BufferType) Eval(target *prog.Target) uint64 {
	panic("Eval called for buffer type")
}

type PointerType struct {
	Address uint64
	Res Type
}

func NewPointerType(addr uint64, res Type) (typ *PointerType) {
	typ = new(PointerType)
	typ.Res = res
	typ.Address = addr
	return
}

func NullPointer() (typ *PointerType) {
	typ = new(PointerType)
	typ.Address = 0
	typ.Res = NewBufferType("")
	return
}

func (typ *PointerType) IsNull() bool {
	if typ.Address == 0 {
		return true
	}
	return false
}

func (p *PointerType) Name() string {
	return Strace_PointerType
}

func (p *PointerType) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Address: %d\n", p.Address))
	buf.WriteString(fmt.Sprintf("Res: %s\n", p.Res.String()))
	return buf.String()
}

func (p *PointerType) Eval(target *prog.Target) uint64 {
	panic("Eval called for PointerType")
}


type StructType struct {
	Fields []Type
}

func NewStructType(types []Type) (typ *StructType) {
	typ = new(StructType)
	typ.Fields = types
	return
}

func (s *StructType) Name() string {
	return Strace_StructType
}

func (s *StructType) String() string {
	var buf bytes.Buffer

	buf.WriteString("{")
	for _, field := range s.Fields {
		buf.WriteString(field.String())
		buf.WriteString(",")
	}
	buf.WriteString("}")
	return buf.String()
}

func (s *StructType) Eval(target *prog.Target) uint64 {
	panic("Eval Called For Struct Type")
}

type ArrayType struct {
	Elems []Type
	Len int
}

func NewArrayType(elems []Type) (typ *ArrayType) {
	typ = new(ArrayType)
	typ.Elems = elems
	typ.Len = len(elems)
	return
}

func (a *ArrayType) Name() string {
	return Strace_ArrayType
}

func (a *ArrayType) String() string {
	var buf bytes.Buffer

	buf.WriteString("[")
	for _, elem := range a.Elems {
		buf.WriteString(elem.String())
		buf.WriteString(",")
	}
	buf.WriteString("]")
	return buf.String()
}

func (a *ArrayType) Eval(target *prog.Target) uint64 {
	panic("Eval called for Array Type")
}

type IpType struct {
	Str string
}

func NewIpType(val string) (typ *IpType) {
	typ = new(IpType)
	typ.Str = val
	return
}

func (i *IpType) Name() string {
	return "Ip Type"
}

func (i *IpType) String() string {
	return fmt.Sprintf("Ip type :%s", i.Str)
}

func (i *IpType) Eval(target *prog.Target) uint64 {
	panic("Eval called for ip type")
}