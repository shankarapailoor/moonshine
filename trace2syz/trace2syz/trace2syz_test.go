package trace2syz

import (
	"fmt"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"testing"
)

var (
	OS   = "linux"
	Arch = "amd64"
	rev  = sys.GitRevision
)

func testParseSingleTrace(data string) (*Context, error) {
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		return nil, fmt.Errorf("error getting target: %s", rev)
	}
	scanner := initialize(data)
	traceTree := parseLoop(scanner, Strace)
	ctx, err := ParseTrace(traceTree.TraceMap[traceTree.RootPid], target)
	if err != nil {
		return nil, err
	}
	if err = ctx.FillOutMemory(); err != nil {
		return nil, err
	}
	return ctx, nil
}

func TestParseTrace(t *testing.T) {
	test := `open("file", O_CREAT|O_RDWR) = 3` + "\n" +
		`fstat() = 0`
	ctx, err := testParseSingleTrace(test)
	if err != nil {
		t.Fatalf("Failed to parse trace: %s", err.Error())
	}
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
	if p.Calls[2].Meta.CallName != "fstat" {
		t.Fatalf("Expected third call to be fstat. Got: %s\n", p.Calls[2].Meta.CallName)
	}
}
