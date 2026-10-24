package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWire6SubscriptionNeedsNoTicketState(t *testing.T) {
	s, link := subscriptionFixture(t)
	usersMu.Lock()
	_, err := currentUsersStore.db.Exec(`UPDATE subscription_nodes SET wire_version=6 WHERE subscription_id=?`, s.ID)
	usersMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var previous string
	for i := 0; i < 70; i++ {
		response := getSubscription(link)
		if response.Code != 200 {
			t.Fatalf("GET %d failed: %d", i, response.Code)
		}
		body := response.Body.String()
		if !strings.Contains(body, "wire_version=6") || strings.Contains(body, "admission_tickets") {
			t.Fatal("wrong subscription", body)
		}
		if i > 0 && body != previous {
			t.Fatal("subscription unexpectedly changed")
		}
		previous = body
	}
	head := httptest.NewRecorder()
	publicSubscriptionHandler(head, httptest.NewRequest(http.MethodHead, link, nil))
	if head.Code != 200 || head.Body.Len() != 0 {
		t.Fatal("HEAD failed")
	}
	var count int
	if err := currentUsersStore.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('admission_tickets','subscription_ticket_seeds')`).Scan(&count); err != nil || count != 0 {
		t.Fatal("ticket tables unexpectedly required", count, err)
	}
}
