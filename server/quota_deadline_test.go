package main

import (
	"testing"
	"time"
)

func TestQuotaAuthorizationLatencyIsNotCountedTwice(t *testing.T) {
	started := time.Unix(1700000000, 250000000)
	finished := started.Add(3 * time.Second)
	deadline := quotaAuthorizationDeadline(started, started.Unix(), 6)
	if !deadline.After(finished.Add(2 * time.Second)) {
		t.Fatal("a three-second refresh prematurely expired a six-second authorization")
	}
	if deadline.After(started.Add(6 * time.Second)) {
		t.Fatal("refresh extended the authorization beyond its lifetime")
	}
}

func TestQuotaAuthorizationCachedReplyCannotRenewOldRequest(t *testing.T) {
	started := time.Unix(1700000010, 0)
	issued := started.Add(-10 * time.Second).Unix()
	deadline := quotaAuthorizationDeadline(started, issued, 6)
	if !deadline.Before(started) {
		t.Fatal("a cached reply revived an expired request")
	}
}

func TestQuotaAuthorizationZeroValidityRemainsDenied(t *testing.T) {
	started := time.Now()
	if quotaAuthorizationDeadline(started, started.Unix(), 0).After(started) {
		t.Fatal("a denied response granted authorization time")
	}
}
