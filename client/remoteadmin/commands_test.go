package remoteadmin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNativeManagementOperations(t *testing.T) {
	var preparations, commits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "http://"+r.Host {
			t.Error("missing same-origin header")
		}
		if r.URL.Path == "/private/control/session" {
			fmt.Fprint(w, `{"csrf":"fresh-session-token"}`)
			return
		}
		if r.Header.Get("X-CSRF-Token") != "fresh-session-token" {
			t.Error("missing CSRF token")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/private/control/prepare":
			preparations.Add(1)
			command := body["command"].(string)
			if strings.HasPrefix(command, "usercreate ") || strings.HasPrefix(command, "delete ") {
				fmt.Fprint(w, `{"confirmation":"once"}`)
			} else if command == "status" {
				fmt.Fprint(w, `{"result":{"online":3}}`)
			} else {
				w.WriteHeader(409)
				fmt.Fprint(w, `{"error":"revision changed"}`)
			}
		case "/private/control/commit":
			commits.Add(1)
			if body["confirmation"] != "once" || body["confirm"] != true {
				t.Error("bad commit")
			}
			fmt.Fprint(w, `{"result":{"ok":true}}`)
		default:
			t.Error("unexpected route", r.URL.Path)
		}
	}))
	defer server.Close()
	id := "native-command-test"
	jobs.Lock()
	jobs.items[id] = &job{state: State{ID: id, Phase: "ready", URL: server.URL + "/private/"}}
	jobs.Unlock()
	defer func() { jobs.Lock(); delete(jobs.items, id); jobs.Unlock() }()
	result, err := Call(id, `{"command":"status"}`)
	if err != nil || !strings.Contains(result, `"online":3`) {
		t.Fatal(result, err)
	}
	result, err = Call(id, `{"command":"delete alice"}`)
	if err != nil || !strings.Contains(result, "confirmation_required") || preparations.Load() != 1 {
		t.Fatal("destructive action prepared before confirmation", result, err)
	}
	_, err = Call(id, `{"command":"delete alice","confirmed":true}`)
	if err != nil || commits.Load() != 1 {
		t.Fatal(err)
	}
	_, err = Call(id, `{"command":"usercreate {\"name\":\"alice\"}"}`)
	if err != nil || commits.Load() != 2 {
		t.Fatal(err)
	}
	before := preparations.Load()
	_, err = Call(id, `{"command":"inbounds"}`)
	if err == nil || err.Error() != "revision changed" || preparations.Load() != before+1 || commits.Load() != 2 {
		t.Fatal("failed request was retried", err)
	}
}

func TestNativeManagementRejectsMissingSessionsAndMalformedRequests(t *testing.T) {
	for _, raw := range []string{`{}`, `{"command":""}`, `{"command":"status","url":"http://external"}`, strings.Repeat("x", (128<<10)+1)} {
		if _, err := Call("missing", raw); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if _, err := Call("missing", `{"command":"status"}`); err == nil {
		t.Fatal("missing connection accepted")
	}
}

func TestGroupActionsUseExistingAPIsAndRenewSessionWithoutReplayingCommit(t *testing.T) {
	var sessions, commits int
	token := "first"
	expired := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/session") {
			sessions++
			token = fmt.Sprint(sessions)
			fmt.Fprintf(w, `{"csrf":%q}`, token)
			return
		}
		if expired {
			expired = false
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"expired"}`)
			return
		}
		if r.Header.Get("X-CSRF-Token") != token {
			t.Error("wrong session token")
		}
		var input map[string]any
		_ = json.NewDecoder(r.Body).Decode(&input)
		if strings.HasSuffix(r.URL.Path, "/commit") {
			commits++
			fmt.Fprint(w, `{"result":{"ok":true}}`)
			return
		}
		switch input["command"] {
		case "groups":
			fmt.Fprint(w, `{"result":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","revision":2,"users":["alice","bob"]}]}`)
		case "bulk disable alice bob", "bulk enable alice bob":
			fmt.Fprint(w, `{"confirmation":"once"}`)
		default:
			t.Error("unexpected backend command", input["command"])
		}
	}))
	defer server.Close()
	id := "group-action-test"
	jobs.Lock()
	jobs.items[id] = &job{state: State{ID: id, Phase: "ready", URL: server.URL + "/"}}
	jobs.Unlock()
	defer func() { jobs.Lock(); delete(jobs.items, id); jobs.Unlock() }()
	command := `{"command":"groupaccess aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa {\"revision\":2,\"enabled\":false}"}`
	result, err := Call(id, command)
	if err != nil || !strings.Contains(result, "confirmation_required") || commits != 0 {
		t.Fatal(result, err)
	}
	result, err = Call(id, strings.TrimSuffix(command, "}")+`,"confirmed":true}`)
	if err != nil || !strings.Contains(result, `"affected":2`) || commits != 1 || sessions != 1 {
		t.Fatal(result, err, commits, sessions)
	}
	expired = true
	_, err = Call(id, `{"command":"groupaccess aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa {\"revision\":2,\"enabled\":true}"}`)
	if err != nil || commits != 2 || sessions != 2 {
		t.Fatal("session renewal failed", err, commits, sessions)
	}
	_, err = Call(id, `{"command":"groupaccess aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa {\"revision\":1,\"enabled\":true}"}`)
	if err == nil || err.Error() != "group_changed" || commits != 2 {
		t.Fatal("stale group action accepted", err)
	}
}
