package trace2syz

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"testing"
)

var (
	OS   = "linux"
	Arch = "amd64"
	rev  = sys.GitRevision
)

func testParseSingleTrace(t *testing.T, data string) *Context {
	var err error
	var target *prog.Target

	target, err = prog.GetTarget(OS, Arch)
	if err != nil {
		goto err
	}
	scanner := initialize(data)
	traceTree := parseLoop(scanner, Strace)
	ctx, err := ParseTrace(traceTree.TraceMap[traceTree.RootPid], target)
	if err != nil {
		goto err
	}
	if err = ctx.FillOutMemory(); err != nil {
		goto err
	}
	if err = ctx.Prog.Validate(); err != nil {
		goto err
	}
	return ctx
err:
	t.Fatalf("Failed to parse trace: %s", err.Error())
	return nil
}

func TestParseTraceBasic(t *testing.T) {
	test := `open("file", O_CREAT|O_RDWR) = 3` + "\n" +
		`write(3, "somedata", 8) = 8`
	ctx := testParseSingleTrace(t, test)
	p := ctx.Prog
	if len(p.Calls) < 3 {
		t.Fatalf("Expected three calls. Got: %d\n", len(p.Calls))
	}
	if p.Calls[0].Meta.CallName != "mmap" {
		t.Fatalf("Expected first call to be mmap. Got: %s\n", p.Calls[0].Meta.CallName)
	}
	if p.Calls[1].Meta.CallName != "open" {
		t.Fatalf("Expected second call to be open. Got: %s\n", p.Calls[1].Meta.CallName)
	}
	if p.Calls[2].Meta.CallName != "write" {
		t.Fatalf("Expected third call to be fstat. Got: %s\n", p.Calls[2].Meta.CallName)
	}
	switch a := p.Calls[2].Args[0].(type) {
	case *prog.ResultArg:
	default:
		t.Fatalf("Expected result arg. Got: %s\n", a.Type().Name())
	}
}

func TestParseTraceInnerResource(t *testing.T) {
	test := `pipe([5,6]) = 0` + "\n" +
		`write(6, "\xff\xff\xfe\xff", 4) = 4`

	p := testParseSingleTrace(t, test).Prog
	if len(p) < 3 {
		t.Fatalf("Expected three calls. Got: %d\n", len(p.Calls))
	}
	switch a := p.Calls[2].Args[0].(type) {
	case *prog.ResultArg:
	default:
		t.Fatalf("Expected result arg. Got: %s\n", a.Type().Name())
	}
}
