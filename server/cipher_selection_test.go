package main

import "testing"

func TestRealityNeverSelectsUnofferedOrUnimplementedSuite(t *testing.T) {
	for _, test := range []struct {
		offered []uint16
		modern  bool
		want    uint16
		ok      bool
	}{
		{[]uint16{0x1302, 0x1301, 0x1303}, true, 0x1301, true},
		{[]uint16{0x1302, 0x1303}, true, 0x1303, true},
		{[]uint16{0x1302}, true, 0, false},
		{[]uint16{0x1301}, false, 0, false},
		{nil, true, 0, false},
	} {
		got, ok := chooseRealityCipher(test.offered, test.modern)
		if got != test.want || ok != test.ok {
			t.Fatalf("suite negotiation got %x/%v", got, ok)
		}
	}
}
