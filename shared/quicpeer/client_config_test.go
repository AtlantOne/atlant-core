package quicpeer

import "testing"

func TestClientConfigIsNotSharedMutableState(t *testing.T) {
	a, b := ClientConfig(), ClientConfig()
	a.InitialStreamReceiveWindow = 1
	a.EnableDatagrams = false
	if b.InitialStreamReceiveWindow != 8*1024*1024 || !b.EnableDatagrams {
		t.Fatal("one tunnel changed another tunnel's configuration")
	}
}
