package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func groupRequest(method string, input any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(input)
	w := httptest.NewRecorder()
	handleAPIClientGroups(w, httptest.NewRequest(method, "/api/groups", bytes.NewReader(body)))
	return w
}

func groupFixture(t *testing.T) ClientGroup {
	t.Helper()
	isolateUsers(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: strings.Repeat("ab", 32), Enabled: true, UpBytes: 17, DownBytes: 23}
		db.Users["bob"] = &userRecord{Name: "bob", PBK: strings.Repeat("cd", 32), Enabled: true, UpBytes: 3, DownBytes: 7}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := groupRequest("POST", map[string]any{"name": "Family", "note": "personal", "users": []string{"alice"}})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	groups, err := readClientGroups(context.Background(), currentUsersStore)
	if err != nil || len(groups) != 1 {
		t.Fatal("created group missing", err)
	}
	return groups[0]
}

func TestClientGroupsCRUDRealtimeCountersAndStaleRevision(t *testing.T) {
	group := groupFixture(t)
	if group.Up != 17 || group.Down != 23 || len(group.Users) != 1 {
		t.Fatal("wrong group accounting", group)
	}
	if !recordUserTraffic("alice", 5, 6) {
		t.Fatal("traffic rejected")
	}
	groups, _ := readClientGroups(context.Background(), currentUsersStore)
	if groups[0].Up != 22 || groups[0].Down != 29 {
		t.Fatal("group statistics read stale SQL counters")
	}
	input := map[string]any{"id": group.ID, "name": "Updated", "note": "", "revision": group.Revision, "users": []string{"alice", "bob"}}
	if w := groupRequest("PUT", input); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := groupRequest("PUT", input); w.Code != 409 {
		t.Fatal("stale editor overwrote current membership", w.Code)
	}
	groups, _ = readClientGroups(context.Background(), currentUsersStore)
	input["revision"] = groups[0].Revision
	if w := groupRequest("DELETE", input); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(usersDB.Users) != 2 || usersDB.Users["alice"].PBK != strings.Repeat("ab", 32) {
		t.Fatal("deleting a group changed accounts or credentials")
	}
}

func TestClientGroupMoveInvalidatesPreviousEditorAndRejectsUnknownUsers(t *testing.T) {
	first := groupFixture(t)
	if w := groupRequest("POST", map[string]any{"name": "Work", "note": "", "users": []string{"alice"}}); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := groupRequest("PUT", map[string]any{"id": first.ID, "name": first.Name, "note": first.Note, "revision": first.Revision, "users": []string{"alice"}}); w.Code != 409 {
		t.Fatal("moving member did not invalidate old form", w.Code)
	}
	if w := groupRequest("POST", map[string]any{"name": "Bad", "note": "", "users": []string{"missing"}}); w.Code != 400 {
		t.Fatal("unknown member accepted", w.Code)
	}
	if w := groupRequest("POST", map[string]any{"name": "family", "note": ""}); w.Code != 409 {
		t.Fatal("case-insensitive duplicate group accepted", w.Code)
	}
}

func TestClientGroupsRequireCompleteBackupAndRollback(t *testing.T) {
	group := groupFixture(t)
	w := httptest.NewRecorder()
	handleAPIBackup(w, httptest.NewRequest("GET", "/api/backup", nil))
	if w.Code != 409 {
		t.Fatal("incomplete JSON backup silently omitted groups", w.Code)
	}
	if _, err := currentUsersStore.db.Exec(`CREATE TRIGGER reject_group_member BEFORE INSERT ON client_group_members WHEN NEW.user_name='bob' BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	w = groupRequest("PUT", map[string]any{"id": group.ID, "name": "Must rollback", "note": "", "revision": group.Revision, "users": []string{"bob"}})
	if w.Code != 500 {
		t.Fatal("injected member failure did not fail transaction", w.Code)
	}
	groups, _ := readClientGroups(context.Background(), currentUsersStore)
	if groups[0].Name != group.Name || len(groups[0].Users) != 1 || groups[0].Users[0] != "alice" || groups[0].Revision != group.Revision {
		t.Fatal("group mutation partly committed")
	}
}

func TestAPIUserCreateNeverOverwritesExistingAccount(t *testing.T) {
	_ = groupFixture(t)
	w := httptest.NewRecorder()
	handleAPIUserCreate(w, httptest.NewRequest("POST", "/api/user/create", strings.NewReader(`{"name":"alice","total_limit":100,"enabled":false,"note":"overwrite"}`)))
	if w.Code != 409 || !usersDB.Users["alice"].Enabled || usersDB.Users["alice"].Note != "" || usersDB.Users["alice"].TotalLimit != 0 {
		t.Fatal("create-only endpoint overwrote existing account", w.Code)
	}
}

func TestClientGroupsSurviveCompleteSQLiteSnapshot(t *testing.T) {
	group := groupFixture(t)
	w := httptest.NewRecorder()
	handleAPISQLiteBackup(w, httptest.NewRequest("GET", "/api/backup/sqlite", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var snapshot struct{ Database []byte }
	if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recovered.db")
	if err := os.WriteFile(path, snapshot.Database, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name, note, member string
	var revision int64
	if err := db.QueryRow(`SELECT g.name,g.note,g.revision,m.user_name FROM client_groups g JOIN client_group_members m ON m.group_id=g.id WHERE g.id=?`, group.ID).Scan(&name, &note, &revision, &member); err != nil {
		t.Fatal(err)
	}
	if name != group.Name || note != group.Note || revision != group.Revision || member != "alice" {
		t.Fatal("SQLite recovery lost group metadata or membership")
	}
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("invalid recovered database", err)
	}
}
