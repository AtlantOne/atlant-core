package xhttppool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestOpenWaitsForHTTP2AcceptanceAndBoundsSetupOnly(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stall":
			<-r.Context().Done()
		case "/deny":
			w.WriteHeader(http.StatusForbidden)
		default:
			var preamble [3]byte
			if _, err := io.ReadFull(r.Body, preamble[:]); err != nil || string(preamble[:]) != "hdr" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = io.Copy(w, r.Body)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport := server.Client().Transport

	for _, path := range []string{"/stall", "/deny", "/ok"} {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			pr, pw := io.Pipe()
			defer pw.Close()
			req, err := http.NewRequestWithContext(ctx, "POST", server.URL+path, struct {
				io.Reader
				io.Closer
			}{io.MultiReader(strings.NewReader("hdr"), pr), pr})
			if err != nil {
				t.Fatal(err)
			}
			retired := false
			timeout := 500 * time.Millisecond
			resp, err := open(req, cancel, timeout, transport, func() { retired = true })
			switch path {
			case "/stall":
				if !errors.Is(err, context.DeadlineExceeded) || !retired {
					t.Fatalf("stall result: %v, retired=%v", err, retired)
				}
			case "/deny":
				if err == nil || !strings.Contains(err.Error(), "403") || retired {
					t.Fatalf("rejection result: %v, retired=%v", err, retired)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				time.Sleep(timeout + 20*time.Millisecond)
				if _, err := fmt.Fprint(pw, "payload"); err != nil {
					t.Fatal(err)
				}
				_ = pw.Close()
				data, err := io.ReadAll(resp.Body)
				if err != nil || string(data) != "payload" {
					t.Fatalf("accepted stream lost data: %q, %v", data, err)
				}
			}
		})
	}
}

func TestRetireKeepsActiveLeasesAndMakesRoomForReplacement(t *testing.T) {
	var pool Pool
	key := Key("test")
	var leases []*Lease
	for range MaxCarriers {
		lease, err := pool.Acquire(key, factory)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
		defer lease.Release()
	}
	leases[0].Retire()
	replacement, err := pool.Acquire(key, factory)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Release()
	for _, lease := range leases {
		if replacement.Transport() == lease.Transport() {
			t.Fatal("failed to open a replacement slot")
		}
	}
	if leases[0].entry.active != 1 || len(pool.entries) != MaxCarriers+1 {
		t.Fatal("retirement interrupted the active lease")
	}
}

func TestOpenDoesNotRetireCarrierOnStreamReset(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://example.test", nil)
	retired := false
	_, err := open(req, cancel, time.Second, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, http2.StreamError{StreamID: 1, Code: http2.ErrCodeCancel}
	}), func() { retired = true })
	if err == nil || retired {
		t.Fatalf("stream reset result: %v, retired=%v", err, retired)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
