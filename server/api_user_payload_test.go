package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func apiFixture(t *testing.T) {
	t.Helper()
	isolateUsers(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: strings.Repeat("ab", 32), Enabled: false, TotalLimit: 9, IPLimit: 2, ExpiresAt: 1234, Note: "kept"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAPIUpsertWithoutFieldsPreservesDisabledIdentity(t *testing.T) {
	apiFixture(t)
	w := httptest.NewRecorder()
	handleAPIUserAdd(w, httptest.NewRequest(http.MethodPost, "/api/user/add", strings.NewReader(`{"name":"alice"}`)))
	if w.Code != http.StatusCreated {
		t.Fatal(w.Code, w.Body.String())
	}
	r := usersDB.Users["alice"]
	if r.Enabled || r.PBK != strings.Repeat("ab", 32) || r.TotalLimit != 9 || r.IPLimit != 2 || r.ExpiresAt != 1234 || r.Note != "kept" {
		t.Fatal("omitted fields mutated existing account")
	}
}

func TestAPIUpdateExplicitZeroClearsConstraints(t *testing.T) {
	apiFixture(t)
	w := httptest.NewRecorder()
	handleAPIUserUpdate(w, httptest.NewRequest(http.MethodPost, "/api/user/update", strings.NewReader(`{"name":"alice","total_limit":0,"ip_limit":0,"expires_at":0,"note":""}`)))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	r := usersDB.Users["alice"]
	if r.TotalLimit != 0 || r.IPLimit != 0 || r.ExpiresAt != 0 || r.Note != "" || r.Enabled || r.PBK != strings.Repeat("ab", 32) {
		t.Fatal("zero update lost or identity changed")
	}
}

func TestAPIFractionalQuota(t *testing.T) {
	apiFixture(t)
	w := httptest.NewRecorder()
	handleAPIUserUpdate(w, httptest.NewRequest(http.MethodPost, "/api/user/update", strings.NewReader(`{"name":"alice","limit_gb":0.1}`)))
	if w.Code != 200 || usersDB.Users["alice"].TotalLimit != 107374182 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	handleAPIUserUpdate(w, httptest.NewRequest(http.MethodPost, "/api/user/update", strings.NewReader(`{"name":"alice","limit_gb":0.00000000001}`)))
	if w.Code != 400 || usersDB.Users["alice"].TotalLimit != 107374182 {
		t.Fatal("tiny positive quota became unlimited")
	}
}

func TestAPIRejectsMalformedAmbiguousAndUnboundedUserPayloads(t *testing.T) {
	apiFixture(t)
	for _, body := range []string{
		`null`, `[]`, `{"name":"alice","name":"bob"}`, `{"name":"alice","Enabled":true}`,
		`{"name":"alice","enabled":null}`, `{"name":"alice","unknown":true}`,
		`{"name":"alice","pbk":"bad"}`, `{"name":"alice","limit_gb":-1}`,
		`{"name":"alice","limit_gb":1e30}`, `{"name":"alice","expire_days":2147483647}`,
		`{"name":"alice","ip_limit":-1}`, `{"name":"alice","expires_at":-1}`,
		`{"name":"alice","limit_gb":1,"total_limit":4}`,
		`{"name":"alice","expire_days":1,"expires_at":4}`,
		`{"name":"alice"} {}`, `{"name":"alice","note":"` + strings.Repeat("x", (1<<20)+1) + `"}`,
	} {
		w := httptest.NewRecorder()
		handleAPIUserUpdate(w, httptest.NewRequest(http.MethodPost, "/api/user/update", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("accepted invalid payload prefix %.60q: %d", body, w.Code)
		}
	}
	if usersDB.Users["alice"].Enabled || usersDB.Users["alice"].TotalLimit != 9 {
		t.Fatal("invalid request mutated account")
	}
}

func TestAPIFormValidationAndExplicitZero(t *testing.T) {
	for _, body := range []string{"name=alice&limit_gb=NaN", "name=alice&limit_gb=Inf", "name=alice&limit_gb=-1", "name=alice&enabled=perhaps", "name=alice&name=bob"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		var p UserPayload
		if decodeUserPayload(w, r, &p) || w.Code != 400 {
			t.Fatal("invalid form accepted")
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("name=alice&limit_gb=0&note="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var p UserPayload
	if !decodeUserPayload(w, r, &p) || !p.present["total_limit"] || !p.present["note"] {
		t.Fatal("zero form lost")
	}
}

func FuzzUserPayload(f *testing.F) {
	f.Add([]byte(`{"name":"alice","total_limit":0}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var p UserPayload
		if json.Unmarshal(data, &p) == nil {
			_ = p.validate()
		}
	})
}
