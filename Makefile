default:
	ragel -Z -G2 -o scanner/lex.go scanner/lex.rl
	goyacc -o scanner/strace.go -p Strace scanner/strace.y
	mkdir -p bin deserialized
	go build -o ./bin/moonshine main.go
clean:
	rm -f scanner/lex.go
	rm -f scanner/strace.go
