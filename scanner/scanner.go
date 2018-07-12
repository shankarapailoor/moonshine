package scanner

import (
	"fmt"
	"io/ioutil"
	"bufio"
	"strings"
	"strconv"
	"github.com/shankarapailoor/moonshine/strace_types"
	"os"
)

const(
	maxBufferSize = 64*1024*1024
	CoverDelim = ","
	CoverID = "Cover:"
	SYSRESTART = "ERESTARTSYS"
	SignalPlus = "+++"
	SignalMinus = "---"
)

func parseIps(line string) []uint64 {
	line = line[1: len(line)-1] //Remove quotes
	ips := strings.Split(strings.Split(line, CoverID)[1], CoverDelim)
	cover_set := make(map[uint64]bool, 0)
	cover := make([]uint64, 0)
	for _, ins := range ips {
		if strings.TrimSpace(ins) == "" {
			continue
		} else {
			ip, err := strconv.ParseUint(strings.TrimSpace(ins), 0, 64)
			if err != nil {
				panic(fmt.Sprintf("failed parsing ip: %s", ins))
			}
			if _, ok := cover_set[ip]; !ok {
				cover_set[ip] = true
				cover = append(cover, ip)
			}
		}
	}
	return cover
}

func parseLoop(scanner *bufio.Scanner) (tree *strace_types.TraceTree) {
	tree = strace_types.NewTraceTree()
	//Creating the process tree
	var lastCall *strace_types.Syscall
	for scanner.Scan() {
		line := scanner.Text()
		restart := strings.Contains(line, SYSRESTART)
		signalPlus := strings.Contains(line, SignalPlus)
		signalMinus := strings.Contains(line, SignalMinus)
		shouldSkip := restart || signalPlus || signalMinus
		if shouldSkip {
			continue
		} else if strings.Contains(line, CoverID) {
			cover := parseIps(line)
			//fmt.Printf("Cover: %d\n", len(cover))
			lastCall.Cover = cover
			continue

		} else {
			fmt.Printf("line: %s\n", line)
			lex := newLexer(scanner.Bytes())
			StraceParse(lex)
			call := lex.result
			if call == nil {
				panic("CALL IS NIL")
			}
			if call.Pid == -1 {
				continue
			}
			lastCall = tree.Add(call)
			//trace.Calls = append(trace.Calls, call)
			//fmt.Printf("result: %v\n", lex.result.CallName)
		}
	}
	if len(tree.Ptree) == 0 {
		return nil
	}
	return
}

func Parse(filename string) *strace_types.TraceTree {
	var data []byte
	var err error

	fmt.Fprintf(os.Stderr, "Scanning file: %s\n", filename)
	if data, err = ioutil.ReadFile(filename); err != nil {
		panic(fmt.Sprintf("error reading file: %s\n", err.Error()))
	}
	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(buf, maxBufferSize)

	tree := parseLoop(scanner)
	if tree != nil {
		tree.Filename = filename
	}
	return tree
}
