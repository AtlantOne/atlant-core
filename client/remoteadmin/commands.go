package remoteadmin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type managementHTTPError struct {
	status  int
	message string
}

func (e *managementHTTPError) Error() string { return e.message }

// Call executes a management API operation over the existing pinned SSH session.
// It never invokes a shell or exposes the panel session cookie to either GUI.
func Call(id, raw string) (string, error) {
	if len(raw) > 128<<10 {
		return "", errors.New("request too large")
	}
	var input struct {
		Command   string `json:"command"`
		Confirmed bool   `json:"confirmed"`
		Reveal    bool   `json:"reveal"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || strings.TrimSpace(input.Command) == "" {
		return "", errors.New("invalid management operation")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return "", errors.New("invalid management operation")
	}
	jobs.Lock()
	j := jobs.items[id]
	jobs.Unlock()
	if j == nil {
		return "", errors.New("management connection unavailable")
	}
	j.operationMu.Lock()
	defer j.operationMu.Unlock()
	j.mu.Lock()
	state := j.state
	j.mu.Unlock()
	if state.Phase != "ready" {
		return "", errors.New("management connection is not ready")
	}
	base, err := url.Parse(state.URL)
	if err != nil || base.Hostname() != "127.0.0.1" {
		return "", errors.New("invalid local API endpoint")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path string, body any, csrf string) (map[string]json.RawMessage, error) {
		method := http.MethodGet
		var data []byte
		if body != nil {
			method = http.MethodPost
			data, _ = json.Marshal(body)
		}
		req, e := http.NewRequestWithContext(ctx, method, state.URL+"control/"+path, bytes.NewReader(data))
		if e != nil {
			return nil, e
		}
		req.Header.Set("Origin", base.Scheme+"://"+base.Host)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		response, e := client.Do(req)
		if e != nil {
			return nil, errors.New("SSH management API unavailable")
		}
		defer response.Body.Close()
		content, e := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
		if e != nil || len(content) > 2<<20 {
			return nil, errors.New("management response too large")
		}
		var result map[string]json.RawMessage
		if json.Unmarshal(content, &result) != nil {
			return nil, fmt.Errorf("invalid management response (%d)", response.StatusCode)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			var message string
			_ = json.Unmarshal(result["error"], &message)
			if message == "" {
				message = http.StatusText(response.StatusCode)
			}
			return nil, &managementHTTPError{response.StatusCode, message}
		}
		return result, nil
	}
	csrf := j.csrf
	refresh := func() error {
		session, e := request("session", nil, "")
		if e != nil {
			return e
		}
		_ = json.Unmarshal(session["csrf"], &csrf)
		if csrf == "" {
			return errors.New("management session unavailable")
		}
		j.csrf = csrf
		return nil
	}
	if csrf == "" {
		if err = refresh(); err != nil {
			return "", err
		}
	}
	// Ask before preparing destructive operations; an abandoned prompt creates no server token.
	verb := strings.Fields(input.Command)[0]
	var groupChange struct {
		Revision int64 `json:"revision"`
		Enabled  *bool `json:"enabled"`
	}
	var groupID string
	if verb == "groupaccess" {
		parts := strings.SplitN(strings.TrimSpace(input.Command), " ", 3)
		if len(parts) != 3 {
			return "", errors.New("invalid group action")
		}
		groupID = parts[1]
		decoded, e := hex.DecodeString(groupID)
		if e != nil || len(decoded) != 16 {
			return "", errors.New("invalid group ID")
		}
		decoder := json.NewDecoder(strings.NewReader(parts[2]))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&groupChange) != nil || groupChange.Enabled == nil || groupChange.Revision < 1 {
			return "", errors.New("invalid group action")
		}
		if !*groupChange.Enabled && !input.Confirmed {
			return `{"confirmation_required":true}`, nil
		}
	}
	critical := map[string]bool{"delete": true, "subdelete": true, "groupdelete": true, "inbounddelete": true, "reset": true, "subreset": true, "rekey": true, "subrekey": true, "subrotate": true, "kick": true, "subkick": true, "disable": true}
	if (critical[verb] || input.Command == "service stop" || input.Command == "service restart") && !input.Confirmed {
		return `{"confirmation_required":true}`, nil
	}
	execute := func(command string) (map[string]json.RawMessage, error) {
		result, err := request("prepare", map[string]any{"command": command, "reveal": input.Reveal}, csrf)
		var authError *managementHTTPError
		if errors.As(err, &authError) && (authError.status == 401 || authError.status == 403) {
			// These rejections precede preparation. Never retry a commit after an ambiguous response.
			if err = refresh(); err == nil {
				result, err = request("prepare", map[string]any{"command": command, "reveal": input.Reveal}, csrf)
			}
		}
		if err != nil {
			return nil, err
		}
		if token, ok := result["confirmation"]; ok {
			var confirmation string
			_ = json.Unmarshal(token, &confirmation)
			result, err = request("commit", map[string]any{"confirmation": confirmation, "confirm": true}, csrf)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	}
	var result map[string]json.RawMessage
	if verb == "groupaccess" {
		groups, e := execute("groups")
		if e != nil {
			return "", e
		}
		var records []struct {
			ID       string   `json:"id"`
			Revision int64    `json:"revision"`
			Users    []string `json:"users"`
		}
		if json.Unmarshal(groups["result"], &records) != nil {
			return "", errors.New("invalid group response")
		}
		var members []string
		found := false
		for _, record := range records {
			if record.ID == groupID {
				if record.Revision != groupChange.Revision {
					return "", errors.New("group_changed")
				}
				members = record.Users
				found = true
				break
			}
		}
		if !found {
			return "", errors.New("group_changed")
		}
		updated := 0
		operation := "enable"
		if !*groupChange.Enabled {
			operation = "disable"
		}
		for offset := 0; offset < len(members); offset += 100 {
			end := min(offset+100, len(members))
			batch := members[offset:end]
			for _, name := range batch {
				if name == "" || strings.ContainsAny(name, " \r\n\t'\"") {
					return "", errors.New("invalid group member")
				}
			}
			if _, e = execute("bulk " + operation + " " + strings.Join(batch, " ")); e != nil {
				return "", fmt.Errorf("group_partial_update (%d): %w", updated, e)
			}
			updated += len(batch)
		}
		payload, _ := json.Marshal(map[string]any{"affected": updated, "enabled": *groupChange.Enabled})
		result = map[string]json.RawMessage{"result": payload}
	} else {
		result, err = execute(input.Command)
		if err != nil {
			return "", err
		}
	}
	encoded, err := json.Marshal(result)
	return string(encoded), err
}
