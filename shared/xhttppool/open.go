package xhttppool

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

const OpenTimeout = 30 * time.Second

var errOpenTimeout = fmt.Errorf("XHTTP response headers: %w", context.DeadlineExceeded)

// Open waits for acceptance before the caller can send application data. The
// timer covers setup only, so a healthy long-lived stream can stay open.
func (l *Lease) Open(req *http.Request, cancel context.CancelCauseFunc) (*http.Response, error) {
	return open(req, cancel, OpenTimeout, l.entry.transport, l.Retire)
}

func open(req *http.Request, cancel context.CancelCauseFunc, timeout time.Duration, transport http.RoundTripper, retire func()) (*http.Response, error) {
	expired := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		cancel(errOpenTimeout)
		close(expired)
	})
	resp, err := transport.RoundTrip(req)
	if !timer.Stop() {
		<-expired
	}
	if cause := context.Cause(req.Context()); cause != nil {
		if cause == errOpenTimeout {
			retire()
		}
		err = cause
	} else if err != nil {
		var stream http2.StreamError
		if !errors.As(err, &stream) && !errors.Is(err, context.Canceled) {
			retire()
		}
	} else if resp.StatusCode == http.StatusOK {
		return resp, nil
	} else {
		err = fmt.Errorf("server returned %s", resp.Status)
	}
	cancel(err)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return nil, fmt.Errorf("open XHTTP stream: %w", err)
}
