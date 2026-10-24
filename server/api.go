package main

import (
	"atlant.local/protocol/settings"
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var serverStartTime = time.Now()

var errMissingUser = errors.New("user not found")
var errExistingUser = errors.New("user already exists")

func apiWrite(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
			w.Header().Set("Allow", "POST, PUT, DELETE")
			http.Error(w, `{"error":"write method required"}`, http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

func apiUserMutation(w http.ResponseWriter, mutate func(*userDB) error) bool {
	if err := updateUsers(cfg.UsersFile, mutate); err != nil {
		if errors.Is(err, errMissingUser) {
			http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		} else if errors.Is(err, errExistingUser) {
			http.Error(w, `{"error":"user already exists"}`, http.StatusConflict)
		} else {
			log.Printf("[API] User mutation not committed: %v", err)
			http.Error(w, `{"error":"failed to commit user change"}`, http.StatusInternalServerError)
		}
		return false
	}
	return true
}

type UserResponse struct {
	SubscriptionID string `json:"subscription_id,omitempty"`
	Name           string `json:"name"`
	PBK            string `json:"pbk"`
	Enabled        bool   `json:"enabled"`
	UpBytes        uint64 `json:"up_bytes"`
	DownBytes      uint64 `json:"down_bytes"`
	TotalBytes     uint64 `json:"total_bytes"`
	TotalLimit     uint64 `json:"total_limit"`     // in bytes, 0 = unlimited
	RemainingBytes int64  `json:"remaining_bytes"` // -1 = unlimited, or bytes remaining
	ExpiresAt      int64  `json:"expires_at"`      // Unix timestamp, 0 = never
	CreatedAt      int64  `json:"created_at"`
	LastSeen       int64  `json:"last_seen"`
	LastIP         string `json:"last_ip,omitempty"`
	Online         bool   `json:"online"`
	ActiveConns    int32  `json:"active_conns"`
	IPLimit        int    `json:"ip_limit,omitempty"`
	Link           string `json:"link"`
	Note           string `json:"note,omitempty"`
}

type UserPayload struct {
	Name       string   `json:"name"`
	Names      []string `json:"names,omitempty"` // For bulk operations
	PBK        string   `json:"pbk,omitempty"`
	TotalLimit uint64   `json:"total_limit,omitempty"` // bytes
	LimitGB    float64  `json:"limit_gb,omitempty"`    // GB convenience input
	ExpiresAt  int64    `json:"expires_at,omitempty"`  // Unix timestamp
	ExpireDays int      `json:"expire_days,omitempty"` // Days convenience input
	IPLimit    int      `json:"ip_limit,omitempty"`
	Enabled    *bool    `json:"enabled,omitempty"`
	Note       string   `json:"note,omitempty"`
	present    map[string]bool
}

type SystemStatsResponse struct {
	Status            string  `json:"status"`
	Version           string  `json:"version"`
	Protocol          string  `json:"protocol"`
	UptimeSec         int64   `json:"uptime_sec"`
	UptimeStr         string  `json:"uptime_str"`
	ServerAddr        string  `json:"server_addr"`
	SNI               string  `json:"sni"`
	ServerPubKey      string  `json:"server_pub_key"`
	TotalUsers        int     `json:"total_users"`
	ActiveUsers       int     `json:"active_users"`
	OnlineUsers       int     `json:"online_users"`
	DisabledUsers     int     `json:"disabled_users"`
	ExpiredUsers      int     `json:"expired_users"`
	TotalUpBytes      uint64  `json:"total_up_bytes"`
	TotalDownBytes    uint64  `json:"total_down_bytes"`
	TotalBytes        uint64  `json:"total_bytes"`
	CurrentUpBps      uint64  `json:"current_up_bps"`
	CurrentDownBps    uint64  `json:"current_down_bps"`
	ActiveConnections int32   `json:"active_connections"`
	Goroutines        int     `json:"goroutines"`
	MemoryAllocMB     float64 `json:"memory_alloc_mb"`
	MemorySysMB       float64 `json:"memory_sys_mb"`
}

func startAPIServer(c *Config) {
	if c.APIAddr != "" && c.APIAddr != "none" && c.APIAddr != "disabled" {
		host, _, err := net.SplitHostPort(c.APIAddr)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			log.Print("[API] Refusing non-loopback plaintext management listener; use an SSH tunnel")
			return
		}
	}
	if c.APIAddr == "" || c.APIAddr == "none" || c.APIAddr == "disabled" {
		log.Printf("[API] Server disabled by config")
		return
	}

	if c.APISecret == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			log.Printf("[API-SECURITY] Cannot generate management secret; API not started")
			return
		}
		c.APISecret = hex.EncodeToString(b[:])
		log.Printf("[API-SECURITY] Temporary management secret generated; configure api_secret for access (secret omitted from logs)")
	}

	mux := http.NewServeMux()
	mux.Handle("/panel/", managementPanelHandler())

	// System & Metrics
	mux.HandleFunc("/api/status", handleAPIStatus)
	mux.HandleFunc("/api/system", handleAPIStatus)
	mux.HandleFunc("/api/online", handleAPIOnlineSessions)

	// User CRUD & Operations
	mux.HandleFunc("/api/users", handleAPIUsers)
	mux.HandleFunc("/api/user", handleAPIUserSingle)
	mux.HandleFunc("/api/user/add", apiWrite(handleAPIUserAdd))
	mux.HandleFunc("/api/user/create", apiWrite(handleAPIUserCreate))
	mux.HandleFunc("/api/user/update", apiWrite(handleAPIUserUpdate))
	mux.HandleFunc("/api/user/delete", apiWrite(handleAPIUserDelete))
	mux.HandleFunc("/api/user/enable", apiWrite(handleAPIUserEnable))
	mux.HandleFunc("/api/user/disable", apiWrite(handleAPIUserDisable))
	mux.HandleFunc("/api/user/kick", apiWrite(handleAPIUserKick))
	mux.HandleFunc("/api/user/reset-traffic", apiWrite(handleAPIUserResetTraffic))
	mux.HandleFunc("/api/user/regenerate-key", apiWrite(handleAPIUserRegenerateKey))

	// Bulk Operations
	mux.HandleFunc("/api/users/bulk-delete", apiWrite(handleAPIBulkDelete))
	mux.HandleFunc("/api/users/bulk-enable", apiWrite(handleAPIBulkEnable))
	mux.HandleFunc("/api/users/bulk-disable", apiWrite(handleAPIBulkDisable))
	mux.HandleFunc("/api/users/bulk-reset-traffic", apiWrite(handleAPIBulkResetTraffic))

	// Node / Config & Management
	mux.HandleFunc("/api/config", handleAPIGetConfig)
	mux.HandleFunc("/api/config/update", handleAPIUpdateConfig)
	mux.HandleFunc("/api/inbounds", handleAPIInbounds)
	mux.HandleFunc("/api/inbounds/applied", handleAPIAppliedInbounds)
	mux.HandleFunc("/api/control/catalogs", handleAPIRemoteCatalogs)
	mux.HandleFunc("/api/control/remote-account", handleAPIRemoteAccount)
	mux.HandleFunc("/api/inbounds/apply", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		handleInboundMutation(w, r)
	})
	mux.HandleFunc("/api/server/reload", apiWrite(handleAPIReload))
	mux.HandleFunc("/api/backup", handleAPIBackup)
	mux.HandleFunc("/api/backup/sqlite", handleAPISQLiteBackup)
	mux.HandleFunc("/api/restore", handleAPIRestore)
	mux.HandleFunc("/api/logs", handleAPILogs)

	// Subscription & Client Links
	mux.HandleFunc("/api/sub", handleAPISub)
	mux.HandleFunc("/sub/", handleAPISubPath)
	mux.HandleFunc("/api/export", handleAPIExport)
	mux.HandleFunc("/api/subscriptions", handleAPISubscriptions)
	mux.HandleFunc("/api/subscriptions/migrate", handleAPISubscriptionMigration)
	mux.HandleFunc("/api/subscription-account", handleAPISubscriptionAccount)
	mux.HandleFunc("/api/groups", handleAPIClientGroups)
	mux.HandleFunc("/api/quota/nodes", handleAPIQuotaNodes)
	mux.HandleFunc("/api/quota/bindings", handleAPIQuotaBindings)
	mux.HandleFunc("/api/subscription-service", handleAPISubscriptionService)

	// Stealth mode: root & unknown paths return standard 404 (no HTML, no dashboard, no fingerprinting)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Requested-With")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Security: check secret token (skip only for user subscriptions if needed)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/sub" {
			token := r.Header.Get("X-API-Key")
			if token == "" {
				authHdr := r.Header.Get("Authorization")
				if strings.HasPrefix(authHdr, "Bearer ") {
					token = strings.TrimPrefix(authHdr, "Bearer ")
				}
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(c.APISecret)) != 1 {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized","status":401}`))
				return
			}
		}

		mux.ServeHTTP(w, r)
	})

	log.Printf("[API] Pure REST Management API listening on %s (Auth: %v, Web UI: disabled)", c.APIAddr, c.APISecret != "")
	server := &http.Server{
		Addr:              c.APIAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Printf("[API] Server failed on %s: %v", c.APIAddr, err)
	}
}

func buildUserResponse(rec *userRecord) UserResponse {
	usersMu.RLock()
	defer usersMu.RUnlock()
	return buildUserResponseLocked(rec)
}

func buildUserResponseLocked(rec *userRecord) UserResponse {
	up := atomic.LoadUint64(&rec.UpBytes)
	down := atomic.LoadUint64(&rec.DownBytes)
	tot := totalTraffic(up, down)
	var rem int64 = -1
	if rec.TotalLimit > 0 {
		if rec.TotalLimit >= tot {
			remaining := rec.TotalLimit - tot
			if remaining > math.MaxInt64 {
				rem = math.MaxInt64
			} else {
				rem = int64(remaining)
			}
		} else {
			rem = 0
		}
	}
	conns := getUserActiveConns(rec.Name)
	link := generateAtlantLink(rec.Name, rec.PBK)

	response := UserResponse{
		Name:           rec.Name,
		PBK:            rec.PBK,
		Enabled:        rec.Enabled,
		UpBytes:        up,
		DownBytes:      down,
		TotalBytes:     tot,
		TotalLimit:     rec.TotalLimit,
		RemainingBytes: rem,
		ExpiresAt:      rec.ExpiresAt,
		CreatedAt:      rec.CreatedAt,
		LastSeen:       atomic.LoadInt64(&rec.LastSeen),
		LastIP:         rec.LastIP,
		Online:         conns > 0,
		ActiveConns:    conns,
		IPLimit:        rec.IPLimit,
		Link:           link,
		Note:           rec.Note,
	}
	if budget := quotaBudgetLocked(rec.Name); budget != nil {
		response.SubscriptionID = budget.subscription
		response.TotalLimit = 0
		response.RemainingBytes = -1
	}
	return response
}

func handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	usersMu.RLock()
	totalUsers := len(usersDB.Users)
	var activeUsers, onlineUsers, disabledUsers, expiredUsers int
	var totalUp, totalDown uint64
	var totalConns int32
	now := time.Now().Unix()

	for _, u := range usersDB.Users {
		if !u.Enabled {
			disabledUsers++
		} else if u.ExpiresAt > 0 && now > u.ExpiresAt {
			expiredUsers++
		} else {
			activeUsers++
		}
		c := getUserActiveConns(u.Name)
		if c > 0 {
			onlineUsers++
			totalConns += c
		}
		totalUp += atomic.LoadUint64(&u.UpBytes)
		totalDown += atomic.LoadUint64(&u.DownBytes)
	}
	usersMu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	upBps, downBps := getRealtimeSpeed()
	uptime := int64(time.Since(serverStartTime).Seconds())

	res := SystemStatsResponse{
		Status:            "online",
		Version:           "2.0.2",
		Protocol:          "atlant-reality-v2",
		UptimeSec:         uptime,
		UptimeStr:         formatDuration(time.Since(serverStartTime)),
		ServerAddr:        cfg.ServerAddr,
		SNI:               cfg.GetSNI(),
		ServerPubKey:      getServerStaticPubHex(),
		TotalUsers:        totalUsers,
		ActiveUsers:       activeUsers,
		OnlineUsers:       onlineUsers,
		DisabledUsers:     disabledUsers,
		ExpiredUsers:      expiredUsers,
		TotalUpBytes:      totalUp,
		TotalDownBytes:    totalDown,
		TotalBytes:        totalUp + totalDown,
		CurrentUpBps:      upBps,
		CurrentDownBps:    downBps,
		ActiveConnections: totalConns,
		Goroutines:        runtime.NumGoroutine(),
		MemoryAllocMB:     float64(m.Alloc) / 1024 / 1024,
		MemorySysMB:       float64(m.Sys) / 1024 / 1024,
	}

	json.NewEncoder(w).Encode(res)
}

func handleAPIOnlineSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	sessions := getOnlineSessions()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":    len(sessions),
		"sessions": sessions,
	})
}

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method == http.MethodPost {
		handleAPIUserAdd(w, r)
		return
	}

	qStatus := strings.ToLower(r.URL.Query().Get("status"))
	qSearch := strings.ToLower(r.URL.Query().Get("search"))
	qSort := strings.ToLower(r.URL.Query().Get("sort"))
	qOrder := strings.ToLower(r.URL.Query().Get("order"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	usersMu.RLock()
	list := make([]UserResponse, 0, len(usersDB.Users))
	now := time.Now().Unix()

	for _, rec := range usersDB.Users {
		resp := buildUserResponseLocked(rec)

		// Filter by status
		if qStatus != "" && qStatus != "all" {
			switch qStatus {
			case "active":
				if !rec.Enabled || (rec.ExpiresAt > 0 && now > rec.ExpiresAt) || (rec.TotalLimit > 0 && resp.TotalBytes >= rec.TotalLimit) {
					continue
				}
			case "disabled":
				if rec.Enabled {
					continue
				}
			case "expired":
				if rec.ExpiresAt == 0 || now <= rec.ExpiresAt {
					continue
				}
			case "depleted":
				if rec.TotalLimit == 0 || resp.TotalBytes < rec.TotalLimit {
					continue
				}
			case "online":
				if !resp.Online {
					continue
				}
			}
		}

		// Filter by search query
		if qSearch != "" {
			if !strings.Contains(strings.ToLower(rec.Name), qSearch) && !strings.Contains(strings.ToLower(rec.Note), qSearch) {
				continue
			}
		}

		list = append(list, resp)
	}
	usersMu.RUnlock()

	// Sort
	if qSort != "" {
		sort.Slice(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if qOrder == "desc" {
				a, b = b, a
			}
			switch qSort {
			case "name":
				return a.Name < b.Name
			case "created":
				return a.CreatedAt < b.CreatedAt
			case "traffic":
				return a.TotalBytes < b.TotalBytes
			case "expiry":
				return a.ExpiresAt < b.ExpiresAt
			case "last_seen":
				return a.LastSeen < b.LastSeen
			default:
				return a.Name < b.Name
			}
		})
	}

	total := len(list)
	if offset > 0 {
		if offset >= len(list) {
			list = []UserResponse{}
		} else {
			list = list[offset:]
		}
	}
	if limit > 0 && limit < len(list) {
		list = list[:limit]
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total": total,
		"users": list,
	})
}

func handleAPIUserSingle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, `{"error":"name parameter required"}`, http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodDelete {
		handleDeleteUserInternal(w, name)
		return
	}

	usersMu.RLock()
	rec, exists := usersDB.Users[name]
	if !exists || rec == nil {
		usersMu.RUnlock()
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		return
	}
	resp := buildUserResponseLocked(rec)
	usersMu.RUnlock()

	json.NewEncoder(w).Encode(resp)
}

func handleAPIUserAdd(w http.ResponseWriter, r *http.Request) {
	handleAPIUserAddMode(w, r, false)
}

func handleAPIUserCreate(w http.ResponseWriter, r *http.Request) {
	handleAPIUserAddMode(w, r, true)
}

func handleAPIUserAddMode(w http.ResponseWriter, r *http.Request, createOnly bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var p UserPayload
	if !decodeUserPayload(w, r, &p) {
		return
	}

	name := strings.TrimSpace(p.Name)
	if !isValidUsername(name) {
		http.Error(w, `{"error":"invalid username (1-64 alphanumeric, underscore or hyphen)"}`, http.StatusBadRequest)
		return
	}

	pbk := strings.TrimSpace(p.PBK)
	if pbk == "" {
		rnd := make([]byte, 32)
		if _, err := rand.Read(rnd); err != nil {
			http.Error(w, `{"error":"key generation failed"}`, http.StatusInternalServerError)
			return
		}
		pbk = hex.EncodeToString(rnd)
	} else if len(pbk) != 64 || !isValidHex(pbk) {
		http.Error(w, `{"error":"invalid pbk: must be 64 hex characters"}`, http.StatusBadRequest)
		return
	}

	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}

	var rec *userRecord
	if !apiUserMutation(w, func(db *userDB) error {
		var exists bool
		rec, exists = db.Users[name]
		if createOnly && exists {
			return errExistingUser
		}
		if !exists || rec == nil {
			rec = &userRecord{
				Name:       name,
				PBK:        pbk,
				Enabled:    enabled,
				TotalLimit: p.TotalLimit,
				ExpiresAt:  p.ExpiresAt,
				CreatedAt:  time.Now().Unix(),
				IPLimit:    p.IPLimit,
				Note:       p.Note,
			}
			db.Users[name] = rec
		} else {
			applyUserPayload(rec, &p)
		}
		return nil
	}) {
		return
	}
	log.Printf("[API] User '%s' added/updated via API", name)
	go kickUserSessions(name)

	resp := buildUserResponse(rec)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func handleAPIUserUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var p UserPayload
	if !decodeUserPayload(w, r, &p) {
		return
	}

	name := strings.TrimSpace(p.Name)
	if name == "" {
		http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
		return
	}

	var rec *userRecord
	if !apiUserMutation(w, func(db *userDB) error {
		var exists bool
		rec, exists = db.Users[name]
		if !exists || rec == nil {
			return errMissingUser
		}

		applyUserPayload(rec, &p)
		return nil
	}) {
		return
	}
	if !rec.Enabled || p.PBK != "" {
		go kickUserSessions(name)
	}
	resp := buildUserResponse(rec)
	json.NewEncoder(w).Encode(resp)
}

func handleDeleteUserInternal(w http.ResponseWriter, name string) {
	if !apiUserMutation(w, func(db *userDB) error { delete(db.Users, name); return nil }) {
		return
	}

	go kickUserSessions(name)
	log.Printf("[API] User '%s' deleted", name)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "deleted": name})
}

func handleAPIUserDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		name = strings.TrimSpace(p.Name)
	}
	if name == "" {
		http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
		return
	}
	handleDeleteUserInternal(w, name)
}

func handleAPIUserKick(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
		return
	}
	closed := kickUserSessions(name)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "success",
		"user":         name,
		"closed_conns": closed,
	})
}

func handleAPIUserRegenerateKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
		return
	}

	rnd := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		http.Error(w, `{"error":"key generation failed"}`, http.StatusInternalServerError)
		return
	}
	newPBK := hex.EncodeToString(rnd)

	var rec *userRecord
	if !apiUserMutation(w, func(db *userDB) error {
		var exists bool
		rec, exists = db.Users[name]
		if !exists || rec == nil {
			return errMissingUser
		}
		rec.PBK = newPBK
		return nil
	}) {
		return
	}

	go kickUserSessions(name)

	resp := buildUserResponse(rec)
	json.NewEncoder(w).Encode(resp)
}

func handleAPIUserResetTraffic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		name = strings.TrimSpace(p.Name)
	}

	all := name == "all" || name == "*"
	var rec *userRecord
	if !apiUserMutation(w, func(db *userDB) error {
		if all {
			for _, u := range db.Users {
				u.UpBytes, u.DownBytes = 0, 0
			}
			return nil
		}
		var exists bool
		rec, exists = db.Users[name]
		if !exists || rec == nil {
			return errMissingUser
		}
		rec.UpBytes, rec.DownBytes = 0, 0
		return nil
	}) {
		return
	}
	if all {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "reset": "all"})
		return
	}
	resp := buildUserResponse(rec)
	json.NewEncoder(w).Encode(resp)
}

func handleAPIUserEnable(w http.ResponseWriter, r *http.Request) {
	handleAPIUserSetEnabled(w, r, true)
}

func handleAPIUserDisable(w http.ResponseWriter, r *http.Request) {
	handleAPIUserSetEnabled(w, r, false)
}

func handleAPIUserSetEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	var rec *userRecord
	if !apiUserMutation(w, func(db *userDB) error {
		var exists bool
		rec, exists = db.Users[name]
		if !exists || rec == nil {
			return errMissingUser
		}
		rec.Enabled = enabled
		return nil
	}) {
		return
	}
	if !enabled {
		go kickUserSessions(name)
	}
	resp := buildUserResponse(rec)
	json.NewEncoder(w).Encode(resp)
}

func handleAPIBulkDelete(w http.ResponseWriter, r *http.Request) {
	handleAPIBulkMutation(w, r, "deleted_count")
}

func handleAPIBulkEnable(w http.ResponseWriter, r *http.Request) {
	handleAPIBulkMutation(w, r, "enabled_count")
}

func handleAPIBulkDisable(w http.ResponseWriter, r *http.Request) {
	handleAPIBulkMutation(w, r, "disabled_count")
}

func handleAPIBulkResetTraffic(w http.ResponseWriter, r *http.Request) {
	handleAPIBulkMutation(w, r, "reset_count")
}

func handleAPIBulkMutation(w http.ResponseWriter, r *http.Request, operation string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var p UserPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil || len(p.Names) > 1000 {
		http.Error(w, `{"error":"invalid or oversized user selection"}`, http.StatusBadRequest)
		return
	}
	count := 0
	var kick []string
	if !apiUserMutation(w, func(db *userDB) error {
		seen := make(map[string]bool)
		for _, n := range p.Names {
			if seen[n] {
				continue
			}
			seen[n] = true
			u := db.Users[n]
			if u == nil {
				continue
			}
			switch operation {
			case "deleted_count":
				delete(db.Users, n)
				kick = append(kick, n)
			case "enabled_count":
				u.Enabled = true
			case "disabled_count":
				u.Enabled = false
				kick = append(kick, n)
			case "reset_count":
				u.UpBytes, u.DownBytes = 0, 0
			}
			count++
		}
		return nil
	}) {
		return
	}
	for _, name := range kick {
		go kickUserSessions(name)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", operation: count})
}

func handleAPIGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	runtime := cfg.Runtime()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"listen":           cfg.ServerAddr,
		"advertise_addr":   runtime.AdvertiseAddr,
		"sni":              runtime.SNI,
		"server_pub_key":   getServerStaticPubHex(),
		"transport":        cfg.Transport,
		"wire_version":     cfg.WireVersion,
		"up_mbps":          runtime.UpMbps,
		"down_mbps":        runtime.DownMbps,
		"api_addr":         cfg.APIAddr,
		"inbounds_managed": activeInboundSet.Load() != nil || activeInboundController.Load() != nil,
	})
}

func handleAPIUpdateConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if activeInboundSet.Load() != nil || activeInboundController.Load() != nil {
		http.Error(w, `{"error":"connection settings belong to the inbound catalog"}`, http.StatusConflict)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var p struct {
		SNI           string  `json:"sni"`
		AdvertiseAddr string  `json:"advertise_addr"`
		UpMbps        *uint64 `json:"up_mbps"`
		DownMbps      *uint64 `json:"down_mbps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if strings.ContainsAny(p.SNI+p.AdvertiseAddr, "\r\n\t") {
		http.Error(w, `{"error":"invalid configuration value"}`, http.StatusBadRequest)
		return
	}
	if p.SNI != "" {
		p.SNI = strings.TrimSpace(p.SNI)
		if err := settings.ServerName(p.SNI); err != nil {
			http.Error(w, `{"error":"invalid server name"}`, http.StatusBadRequest)
			return
		}
	}
	if p.AdvertiseAddr != "" {
		p.AdvertiseAddr = strings.TrimSpace(p.AdvertiseAddr)
		if err := settings.Endpoint(p.AdvertiseAddr); err != nil {
			http.Error(w, `{"error":"invalid advertised endpoint"}`, http.StatusBadRequest)
			return
		}
	}
	configMu.Lock()
	if p.SNI != "" {
		cfg.SNI = strings.TrimSpace(p.SNI)
	}
	if p.AdvertiseAddr != "" {
		cfg.AdvertiseAddr = strings.TrimSpace(p.AdvertiseAddr)
	}
	if p.UpMbps != nil {
		cfg.UpMbps = *p.UpMbps
		cfg.Bandwidth.UpMbps = *p.UpMbps
	}
	if p.DownMbps != nil {
		cfg.DownMbps = *p.DownMbps
		cfg.Bandwidth.DownMbps = *p.DownMbps
	}
	updated := map[string]interface{}{"sni": cfg.SNI, "advertise_addr": cfg.AdvertiseAddr, "up_mbps": cfg.UpMbps, "down_mbps": cfg.DownMbps}
	configMu.Unlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"config": updated,
	})
}

func handleAPIReload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := loadUsers(cfg.UsersFile); err != nil {
		http.Error(w, `{"error":"failed to load persistent users database"}`, http.StatusInternalServerError)
		return
	}
	usersMu.RLock()
	count := len(usersDB.Users)
	usersMu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "reloaded", "users_count": count})
}

func handleAPIBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=users_backup.json")
	usersMu.Lock()
	snapshot := cloneUserDBLocked(usersDB)
	store, err := usersStoreLocked(cfg.UsersFile)
	if err == nil {
		var quotaAccounts int
		if err = store.db.QueryRow(`SELECT (SELECT count(*) FROM quota_accounts)+(SELECT count(*) FROM client_groups)+(SELECT count(*) FROM remote_inbound_catalogs)+(SELECT count(*) FROM remote_accounts)+(SELECT initialized FROM inbound_catalog_meta WHERE id=1)`).Scan(&quotaAccounts); err == nil && quotaAccounts > 0 {
			usersMu.Unlock()
			http.Error(w, "extended accounting, group and inbound metadata require a full SQLite backup", http.StatusConflict)
			return
		}
	}
	if err == nil {
		snapshot.Subscriptions, err = readSubscriptions(r.Context(), store)
	}
	var data []byte
	if err == nil {
		data, err = json.MarshalIndent(snapshot, "", "  ")
	}
	usersMu.Unlock()
	if err != nil {
		http.Error(w, `{"error":"failed to serialize"}`, http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func handleAPIRestore(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	const maxRestoreSize = 10 << 20
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRestoreSize))
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}
	var db userDB
	if err := json.Unmarshal(body, &db); err != nil {
		http.Error(w, `{"error":"malformed json"}`, http.StatusBadRequest)
		return
	}
	if err := validateUserDB(&db); err != nil {
		http.Error(w, `{"error":"invalid users database"}`, http.StatusBadRequest)
		return
	}
	usersMu.Lock()
	if currentUsersStore != nil {
		var count int
		if err := currentUsersStore.db.QueryRow(`SELECT (SELECT count(*) FROM quota_accounts)+(SELECT count(*) FROM client_groups)+(SELECT count(*) FROM remote_inbound_catalogs)+(SELECT count(*) FROM remote_accounts)+(SELECT initialized FROM inbound_catalog_meta WHERE id=1)`).Scan(&count); err != nil || count > 0 {
			usersMu.Unlock()
			http.Error(w, "extended quota/group/inbound data require a complete offline SQLite recovery", http.StatusConflict)
			return
		}
	}
	for _, sub := range db.Subscriptions {
		if sub.TotalLimit != nil {
			usersMu.Unlock()
			http.Error(w, "global quota ledger is absent from JSON restore", http.StatusConflict)
			return
		}
	}
	if err := saveUsersLocked(cfg.UsersFile, &db); err != nil {
		usersMu.Unlock()
		http.Error(w, `{"error":"failed to persist users database"}`, http.StatusInternalServerError)
		return
	}
	db.Subscriptions = nil // extension tables are not a stale RAM authority
	usersDB = &db
	syncStorageFromDBLocked()
	usersDirty.Store(false)
	usersMu.Unlock()
	go kickUserSessions("all")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "restored", "users_count": len(db.Users)})
}

func handleAPILogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	linesStr := r.URL.Query().Get("lines")
	lines := 50
	if linesStr != "" {
		if l, err := strconv.Atoi(linesStr); err == nil && l > 0 && l <= 1000 {
			lines = l
		}
	}
	cmd := exec.Command("tail", "-n", strconv.Itoa(lines), "/root/atlant.log")
	out, err := cmd.Output()
	if err != nil {
		// Portable fallback for systems without the tail utility.
		b, rErr := readLastLogLines("/root/atlant.log", lines)
		if rErr != nil {
			w.Write([]byte(fmt.Sprintf("Logs not available: %v", err)))
			return
		}
		w.Write(b)
		return
	}
	w.Write(out)
}

func readLastLogLines(path string, count int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ring := make([]string, count)
	seen := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		ring[seen%count] = scanner.Text()
		seen++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	start := 0
	length := seen
	if seen > count {
		start = seen % count
		length = count
	}
	result := make([]string, 0, length)
	for i := 0; i < length; i++ {
		result = append(result, ring[(start+i)%count])
	}
	return []byte(strings.Join(result, "\n") + "\n"), nil
}

func serveSubResponse(w http.ResponseWriter, r *http.Request, name string) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-API-Key")
	}
	key := r.URL.Query().Get("key")

	usersMu.RLock()
	rec, exists := usersDB.Users[name]
	if !exists || rec == nil {
		usersMu.RUnlock()
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// Security: Require either APISecret or the user's secret PBK to fetch subscription link
	isAdmin := cfg.APISecret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(cfg.APISecret)) == 1
	isUserAuth := (token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(rec.PBK)) == 1) ||
		(key != "" && subtle.ConstantTimeCompare([]byte(key), []byte(rec.PBK)) == 1)

	if !isAdmin && !isUserAuth {
		usersMu.RUnlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","status":401}`))
		return
	}

	link := generateAtlantLink(rec.Name, rec.PBK)

	// Standard Marzban / VLESS profile headers for client apps
	up := atomic.LoadUint64(&rec.UpBytes)
	down := atomic.LoadUint64(&rec.DownBytes)
	w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		up, down, rec.TotalLimit, rec.ExpiresAt))
	w.Header().Set("Profile-Update-Interval", "1")
	usersMu.RUnlock()

	if r.URL.Query().Get("b64") == "1" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(link))))
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(link))
}

func handleAPISub(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	serveSubResponse(w, r, name)
}

func handleAPISubPath(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/sub/")
	name = strings.TrimSpace(name)
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	serveSubResponse(w, r, name)
}

func handleAPIExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	usersMu.RLock()
	var links []string
	for _, u := range usersDB.Users {
		if u.Enabled {
			links = append(links, generateAtlantLink(u.Name, u.PBK))
		}
	}
	usersMu.RUnlock()

	body := strings.Join(links, "\n")
	if r.URL.Query().Get("b64") == "1" {
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(body))))
		return
	}
	w.Write([]byte(body))
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}
