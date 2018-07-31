package logging

import "fmt"

func Failf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}