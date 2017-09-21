package caaWorker

import (
	"testing"

	"github.com/mozilla/tls-observatory/worker"
)

func TestRun(t *testing.T) {
	in := worker.Input{Target: "google.com"}
	ch := make(chan worker.Result, 1)

	e := eval{}
	e.Run(in, ch)
	res := <-ch
	if !res.Success {
		t.Fail()
	}
}
