package wire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestPacedConnDeadlineInterruptsAlreadyQueuedWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, right := net.Pipe()
		defer right.Close()
		p := NewFairPacer(1)
		defer p.Close()
		c := PaceConn(left, nil, p, false, nil)
		defer c.Close()
		go io.Copy(io.Discard, right)
		done := make(chan error, 1)
		go func() { _, err := c.Write(make([]byte, 65536)); done <- err }()
		synctest.Wait()
		c.SetWriteDeadline(time.Now().Add(time.Millisecond))
		if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("queued write ignored updated deadline: %v", err)
		}
		c.SetWriteDeadline(time.Time{})
		if n, err := c.Write([]byte("later")); err != nil || n != 5 {
			t.Fatalf("cleared deadline poisoned later write: %v", err)
		}
	})
}

func TestPacedConnCloseCancelsPacing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, right := net.Pipe()
		defer right.Close()
		p := NewFairPacer(1)
		defer p.Close()
		c := PaceConn(left, nil, p, false, nil)
		go io.Copy(io.Discard, right)
		done := make(chan error, 1)
		go func() { _, err := c.Write(make([]byte, 65536)); done <- err }()
		synctest.Wait()
		c.Close()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal("close left pacing blocked", err)
		}
	})
}

func TestPacedReadKeepsBytesWhenDeadlineInterruptsBudgetWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, right := net.Pipe()
		defer right.Close()
		p := NewFairPacer(1)
		defer p.Close()
		c := PaceConn(left, p, nil, false, nil)
		defer c.Close()
		payload := bytes.Repeat([]byte{0x5a}, 32768)
		go right.Write(payload)
		c.SetReadDeadline(time.Now().Add(time.Millisecond))
		got := make([]byte, len(payload))
		n, err := c.Read(got)
		if !errors.Is(err, os.ErrDeadlineExceeded) || n != len(payload) || !bytes.Equal(got[:n], payload) {
			t.Fatalf("read consumed bytes without returning them: n=%d err=%v", n, err)
		}
	})
}

func TestPacedUDPDoesNotSplitOrTruncatePackets(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	peer, err := net.Dial("udp4", socket.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	p := NewFairPacer(1000)
	defer p.Close()
	c := PaceConn(peer, p, p, true, nil)
	defer c.Close()
	payload := bytes.Repeat([]byte{7}, 60000)
	go func() {
		buf := make([]byte, 65535)
		n, addr, err := socket.ReadFrom(buf)
		if err == nil {
			socket.WriteTo(buf[:n], addr)
		}
	}()
	c.SetDeadline(time.Now().Add(time.Second))
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	got := make([]byte, 65535)
	n, err := c.Read(got)
	if err != nil || !bytes.Equal(got[:n], payload) {
		t.Fatal("UDP boundaries changed", n, err)
	}
}

func TestSustainedUDPDoesNotKeepInteractivePriority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &PacedConn{packet: true}
		if !c.priority(false, 100) {
			t.Fatal("sparse UDP was not prioritized")
		}
		if c.priority(false, 65535) {
			t.Fatal("bulk UDP claimed interactive priority")
		}
		time.Sleep(110 * time.Millisecond)
		if c.priority(false, 100) {
			t.Fatal("sustained UDP immediately reclaimed priority")
		}
		time.Sleep(110 * time.Millisecond)
		if !c.priority(false, 100) {
			t.Fatal("idle UDP did not recover interactive priority")
		}
	})
}
