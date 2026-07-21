// Package deferutil holds small helpers meant to be deferred at the top of a
// function or goroutine.
package deferutil

import (
	"runtime/debug"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("deferutil")

// Recover recovers from a panic in the current goroutine, reporting the panic
// value and stack trace rather than letting it crash the whole process. Defer
// it as the first statement of every goroutine entry point.
func Recover() {
	if value := recover(); value != nil {
		log.Errorf("recovered from panic: %v\n%s", value, debug.Stack())
	}
}
