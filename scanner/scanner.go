package scanner

import (
	"bufio"
	"fmt"
	"github.com/shankarapailoor/moonshine/logging"
	"github.com/shankarapailoor/moonshine/straceTypes"
	"io/ioutil"
	"strconv"
	"strings"
)

const (
	maxBufferSize = 64 * 1024 * 1024
	CoverDelim    = ","
	CoverID       = "Cover:"
	SYSRESTART    = "ERESTART"
	SignalPlus    = "+++"
	SignalMinus   = "---"
)

func parseIps(line string) []uint64 {
	line = line[1 : len(line)-1] //Remove quotes
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

func parseLoop(scanner *bufio.Scanner) (tree *straceTypes.TraceTree) {
	tree = straceTypes.NewTraceTree()
	//Creating the process tree
	var lastCall *straceTypes.Syscall
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
			lex := newLexer(scanner.Bytes())
			if ret := StraceParse(lex); ret != 0 {
				fmt.Printf("Error parsing line: %s\n", line)
			}
			call := lex.result
			if call == nil {
				logging.Failf("Failed to parse line: %s\n", line)
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

func Scan(filename string) *straceTypes.TraceTree {
	var data []byte
	var err error

	if data, err = ioutil.ReadFile(filename); err != nil {
		logging.Failf("error reading file: %s\n", err.Error())
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
