package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type QuotaConfig struct {
	Coordinator bool   `json:"coordinator"`
	Endpoint    string `json:"endpoint,omitempty"`
	NodeID      string `json:"node_id,omitempty"`
	NodeKeyFile string `json:"node_key_file,omitempty"`
}

type quotaCall func(context.Context, quotaRequest) (quotaReply, error)

type nodeBudget struct {
	mu                    sync.Mutex
	subscription, session string
	grant                 string
	capacity, up, down    int64
	deadline              time.Time
	allowed               bool
	retired               atomic.Bool
	authorization         atomic.Pointer[quotaAuthorization]
	retryAfter            time.Time
	pending               *quotaRequest
	call                  quotaCall
}

type quotaAuthorization struct {
	allowed  bool
	deadline time.Time
}

func (b *nodeBudget) valid() bool {
	a := b.authorization.Load()
	return !b.retired.Load() && a != nil && a.allowed && time.Now().Before(a.deadline)
}

// Called without usersMu. Network/SQLite work happens once per reservation,
// not on each packet; only this subscription waits during its refill.
func (b *nodeBudget) syncLocked(closeGrant bool, want int64) error {
	if b.pending == nil {
		r := quotaRequest{ID: quotaID(), Session: b.session, Subscription: b.subscription, Grant: b.grant, Up: b.up, Down: b.down, Want: want, Close: closeGrant, IssuedAt: time.Now().Unix()}
		if r.ID == "" {
			return errors.New("entropy unavailable")
		}
		b.pending = &r
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	reply, err := b.call(ctx, *b.pending)
	if err != nil {
		if errors.Is(err, errQuotaClock) {
			b.pending.ID = quotaID()
			b.pending.IssuedAt = time.Now().Unix()
		}
		return err
	}
	// A cached response must not extend a stale authorization for another six
	// seconds after a slow/lost request. Use the original request's age too.
	remaining := time.Duration(reply.ValidSeconds)*time.Second - time.Since(started)
	age := time.Now().Unix() - b.pending.IssuedAt
	if age > 0 {
		remaining -= time.Duration(age) * time.Second
	}
	if b.pending.Close || b.grant == "" {
		b.up, b.down = 0, 0
	}
	b.grant, b.capacity, b.allowed = reply.Grant, reply.Capacity, reply.Allowed
	b.deadline = time.Now().Add(remaining)
	b.authorization.Store(&quotaAuthorization{allowed: b.allowed, deadline: b.deadline})
	if !b.allowed {
		b.retryAfter = time.Now().Add(2 * time.Second)
	}
	b.pending = nil
	return nil
}

func (b *nodeBudget) consume(up, down uint64) bool {
	if up > uint64(quotaMaxValue) || down > uint64(quotaMaxValue) || up > uint64(quotaMaxValue)-down {
		return false
	}
	amount := int64(up + down)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.retired.Load() {
		return false
	}
	if !b.allowed && time.Now().Before(b.retryAfter) {
		return false
	}
	if b.pending != nil && (b.pending.Close || b.grant == "" || !time.Now().Before(b.deadline)) {
		if b.syncLocked(false, quotaChunk) != nil {
			return false
		}
	}
	if !b.allowed || !time.Now().Before(b.deadline) {
		want := int64(0)
		if b.grant == "" {
			want = quotaChunk
		}
		if b.syncLocked(false, want) != nil || !b.allowed || !time.Now().Before(b.deadline) {
			return false
		}
	}
	if b.capacity-b.up-b.down < amount {
		if b.pending != nil {
			if b.syncLocked(false, 0) != nil {
				return false
			}
		}
		if b.syncLocked(b.grant != "", quotaChunk) != nil || !b.allowed || b.capacity-b.up-b.down < amount {
			return false
		}
	}
	b.up += int64(up)
	b.down += int64(down)
	return true
}

type quotaWorker struct {
	mu       sync.RWMutex
	users    map[string]*nodeBudget
	budgets  map[string]*nodeBudget
	call     quotaCall
	session  string
	store    *sqliteUserStore
	stop     chan struct{}
	done     chan struct{}
	running  atomic.Bool
	stopping atomic.Bool
}

var quotaState struct {
	sync.RWMutex
	worker *quotaWorker
}

func quotaBudgetLocked(name string) *nodeBudget {
	quotaState.RLock()
	w := quotaState.worker
	quotaState.RUnlock()
	if w == nil || w.store != currentUsersStore {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.users[name]
}

func reloadQuotaBindingsLocked() error {
	if err := reloadSubscriptionAccessLocked(); err != nil {
		return err
	}
	quotaState.RLock()
	w := quotaState.worker
	quotaState.RUnlock()
	if w == nil || w.store != currentUsersStore {
		return nil
	}
	rows, err := w.store.db.Query(`SELECT user_name,subscription_id FROM quota_bindings`)
	if err != nil {
		return err
	}
	defer rows.Close()
	w.mu.Lock()
	defer w.mu.Unlock()
	users := map[string]*nodeBudget{}
	for rows.Next() {
		var name, sub string
		if err = rows.Scan(&name, &sub); err != nil {
			return err
		}
		b := w.budgets[sub]
		if b == nil {
			b = &nodeBudget{subscription: sub, session: w.session, call: w.call}
			w.budgets[sub] = b
		}
		users[name] = b
	}
	if err = rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if err = loadRemoteBudgets(w, users); err != nil {
		return err
	}
	active := map[*nodeBudget]bool{}
	for _, b := range users {
		active[b] = true
	}
	for _, b := range w.budgets {
		b.retired.Store(!active[b])
	}
	w.users = users
	return nil
}

// Prime a newly created/re-enabled subscriber without putting database or
// coordinator calls on the authentication/packet fast path. Never hold usersMu.
func primeQuotaUser(name string) {
	usersMu.RLock()
	budget := quotaBudgetLocked(name)
	usersMu.RUnlock()
	if budget == nil || budget.valid() {
		return
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.retired.Load() || budget.valid() {
		return
	}
	want := int64(0)
	if budget.grant == "" {
		want = quotaChunk
	}
	_ = budget.syncLocked(false, want)
}

func makeQuotaCall(c QuotaConfig, store *sqliteUserStore) (quotaCall, error) {
	if c.Coordinator {
		return func(ctx context.Context, r quotaRequest) (quotaReply, error) {
			return processQuota(ctx, store.db, "local", r, time.Now())
		}, nil
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !quotaNodeName(c.NodeID) {
		return nil, errors.New("quota endpoint must use HTTPS and a dedicated node identity")
	}
	info, err := os.Lstat(c.NodeKeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 64 || info.Size() > 66 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("quota node key must be a private regular file (0600)")
	}
	secret, err := os.ReadFile(c.NodeKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read quota node key: %w", err)
	}
	token := strings.TrimSpace(string(secret))
	clear(secret)
	if len(token) != 64 || !isValidHex(token) {
		return nil, errors.New("invalid quota node key file")
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := strings.TrimRight(c.Endpoint, "/") + "/quota/v1/budget"
	return remoteQuotaCall(endpoint, c.NodeID, token, client), nil
}

func remoteQuotaCall(endpoint, node, token string, client *http.Client) quotaCall {
	return func(ctx context.Context, r quotaRequest) (quotaReply, error) {
		var reply quotaReply
		body, _ := json.Marshal(r)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return reply, err
		}
		req.Header.Set("X-Atlant-Node", node)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return reply, errors.New("quota coordinator unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			var failure struct {
				Code string `json:"code"`
			}
			if resp.StatusCode == 409 && json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&failure) == nil && failure.Code == "clock" {
				return reply, errQuotaClock
			}
			return reply, fmt.Errorf("quota coordinator HTTP %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
		if err != nil || len(data) > 8192 {
			return reply, errors.New("invalid quota reply")
		}
		err = json.Unmarshal(data, &reply)
		if err == nil && (reply.Capacity < 0 || reply.Capacity > quotaChunk || reply.ValidSeconds < 0 || reply.ValidSeconds > 6 || (reply.Grant != "" && !validQuotaID(reply.Grant))) {
			err = errors.New("invalid quota reply fields")
		}
		return reply, err
	}
}

func initQuotaWorker(c QuotaConfig) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	store := currentUsersStore
	if store == nil {
		return errors.New("quota requires an open SQLite store")
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM quota_bindings`).Scan(&count); err != nil {
		return err
	}
	if !c.Coordinator && c.Endpoint == "" {
		if count > 0 {
			return errors.New("quota bindings exist but coordinator is not configured")
		}
	}
	var call quotaCall
	var err error
	if !c.Coordinator && c.Endpoint == "" {
		call = func(context.Context, quotaRequest) (quotaReply, error) {
			return quotaReply{}, errors.New("local quota coordinator not configured")
		}
	} else {
		call, err = makeQuotaCall(c, store)
	}
	if err != nil {
		return err
	}
	w := &quotaWorker{users: map[string]*nodeBudget{}, budgets: map[string]*nodeBudget{}, call: call, session: quotaID(), store: store, stop: make(chan struct{}), done: make(chan struct{})}
	if w.session == "" {
		return errors.New("entropy unavailable")
	}
	quotaState.Lock()
	quotaState.worker = w
	quotaState.Unlock()
	return reloadQuotaBindingsLocked()
}

func runQuotaWorker() {
	quotaState.RLock()
	initial := quotaState.worker
	quotaState.RUnlock()
	if initial == nil || !initial.running.CompareAndSwap(false, true) {
		return
	}
	defer close(initial.done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		quotaState.RLock()
		w := quotaState.worker
		quotaState.RUnlock()
		if w == nil || w != initial || w.stopping.Load() {
			return
		}
		w.mu.RLock()
		budgets := make([]*nodeBudget, 0, len(w.budgets))
		for _, b := range w.budgets {
			budgets = append(budgets, b)
		}
		w.mu.RUnlock()
		var wg sync.WaitGroup
		slots := make(chan struct{}, 8)
		for _, b := range budgets {
			if w.stopping.Load() {
				break
			}
			slots <- struct{}{}
			wg.Add(1)
			go func(b *nodeBudget) {
				defer wg.Done()
				defer func() { <-slots }()
				b.mu.Lock()
				defer b.mu.Unlock()
				if b.retired.Load() {
					if b.pending != nil {
						if b.syncLocked(false, 0) != nil {
							return
						}
					}
					if b.grant != "" {
						_ = b.syncLocked(true, 0)
					}
					return
				}
				want := int64(0)
				if b.grant == "" {
					want = quotaChunk
				}
				_ = b.syncLocked(false, want)
				if b.pending == nil && !b.allowed && b.grant != "" {
					_ = b.syncLocked(true, 0)
				}
			}(b)
		}
		wg.Wait()
		select {
		case <-ticker.C:
		case <-w.stop:
			return
		}
	}
}

func stopQuotaWorker() {
	quotaState.RLock()
	w := quotaState.worker
	quotaState.RUnlock()
	if w == nil || !w.stopping.CompareAndSwap(false, true) {
		return
	}
	close(w.stop)
	if w.running.Load() {
		<-w.done
	}
	w.mu.RLock()
	budgets := make([]*nodeBudget, 0, len(w.budgets))
	for _, b := range w.budgets {
		b.retired.Store(true)
		budgets = append(budgets, b)
	}
	w.mu.RUnlock()
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for _, b := range budgets {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(b *nodeBudget) {
			defer wg.Done()
			defer func() { <-slots }()
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.pending != nil {
				if b.syncLocked(false, 0) != nil {
					return
				}
			}
			if b.grant != "" {
				_ = b.syncLocked(true, 0)
			}
		}(b)
	}
	wg.Wait()
}
