package main

import "testing"

func TestExplicitGUILaunchDoesNotReadProtectedConfig(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false}, {[]string{"-server", "127.0.0.1:1"}, false},
		{[]string{"-no-config"}, true}, {[]string{"--no-config=true"}, true},
		{[]string{"-no-config", "-no-config=false"}, false},
	} {
		if got := skipAutomaticConfig(tc.args); got != tc.want {
			t.Fatalf("%v: %v", tc.args, got)
		}
	}
}
