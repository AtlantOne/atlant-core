package main

import (
	"strings"
	"testing"
	"time"
)

func TestQuotaPruningUsesExpiryIndexes(t *testing.T) {
	quotaFixture(t, 0)
	db := currentUsersStore.db
	for _, tc := range []struct {
		query string
		index string
	}{
		{"DELETE FROM quota_requests WHERE expires_at<?", "quota_requests_expiry"},
		{"DELETE FROM quota_grants WHERE closed=1 AND updated_at<?", "quota_closed_grants_expiry"},
	} {
		rows, err := db.Query("EXPLAIN QUERY PLAN "+tc.query, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			found = found || strings.Contains(detail, tc.index)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || !found {
			t.Fatalf("pruning does not use %s: %v", tc.index, err)
		}
	}
}

func TestQuotaExpiryIndexesUpgradeExistingSchema(t *testing.T) {
	quotaFixture(t, 0)
	db := currentUsersStore.db
	if _, err := db.Exec("DROP INDEX quota_requests_expiry; DROP INDEX quota_closed_grants_expiry"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := createQuotaTables(db); err != nil {
			t.Fatal("existing database migration is not idempotent", err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN ('quota_requests_expiry','quota_closed_grants_expiry')").Scan(&count); err != nil || count != 2 {
		t.Fatal("existing databases did not receive pruning indexes", count, err)
	}
}
