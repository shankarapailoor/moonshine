default:
	ragel -Z -G2 -o trace2syz/lex.go trace2syz/straceLex.rl
	goyacc -o trace2syz/strace.go -p Strace trace2syz/strace.y
	mkdir -p bin deserialized
	go build -o ./bin/moonshine main.go
clean:
	rm -f trace2syz/lex.go
	rm -f trace2syz/strace.go
