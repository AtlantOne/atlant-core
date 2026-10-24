package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
	_ "modernc.org/sqlite"
)

const usersApplicationID = 0x41544c55 // ATLU, not a network/wire marker.

type sqliteUserStore struct {
	db        *sql.DB
	lock      *flock.Flock
	path      string
	persisted map[string]userRecord
}

// Guarded by usersMu. Exactly one Atlant writer owns the cache and this store.
// SQLite readers/backups remain possible; external direct writes are unsupported.
var currentUsersStore *sqliteUserStore

func resolveUsersPath(path string) (database, legacy string, err error) {
	if strings.TrimSpace(path) == "" {
		return "", "", errors.New("users database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	ext := filepath.Ext(abs)
	if strings.EqualFold(ext, ".json") {
		return strings.TrimSuffix(abs, ext) + ".db", abs, nil
	}
	if strings.EqualFold(ext, ".db") || strings.EqualFold(ext, ".sqlite") || strings.EqualFold(ext, ".sqlite3") {
		return abs, strings.TrimSuffix(abs, ext) + ".json", nil
	}
	return abs, "", nil
}

func openSQLiteUsers(path string) (*sqliteUserStore, error) {
	database, legacy, err := resolveUsersPath(path)
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(database); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("users database must be a regular file, not a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	lock := flock.New(database+".lock", flock.SetPermissions(0600))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		_ = lock.Close()
		return nil, errors.New("users database already owned by another Atlant process; use the running management API")
	}
	ok := false
	defer func() {
		if !ok {
			_ = lock.Close()
		}
	}()
	file, err := os.OpenFile(database, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(database)
	if filepath.VolumeName(database) != "" {
		uriPath = "/" + uriPath
	}
	u := &url.URL{Scheme: "file", Path: uriPath}
	q := u.Query()
	for _, pragma := range []string{"busy_timeout(5000)", "foreign_keys(1)", "synchronous(FULL)"} {
		q.Add("_pragma", pragma)
	}
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &sqliteUserStore{db: db, lock: lock, path: database}
	defer func() {
		if !ok {
			_ = db.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var appID, version int
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return nil, fmt.Errorf("read users database: %w", err)
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if appID != 0 && appID != usersApplicationID {
		return nil, errors.New("not an Atlant users database")
	}
	if version != 0 && version != 1 {
		return nil, errors.New("unsupported users SQLite schema version")
	}
	if appID == 0 {
		var tables int
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			return nil, err
		}
		if tables != 0 {
			return nil, errors.New("refusing to initialize an unrelated SQLite database")
		}
	}
	if err = os.Chmod(database, 0600); err != nil {
		return nil, err
	}
	var journal string
	if err = db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil {
		return nil, err
	}
	if journal != "wal" {
		return nil, errors.New("users database requires WAL on a local filesystem")
	}
	if appID == 0 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		for _, query := range []string{
			`CREATE TABLE users(name TEXT PRIMARY KEY NOT NULL,pbk TEXT NOT NULL,enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),up_bytes TEXT NOT NULL,down_bytes TEXT NOT NULL,total_limit TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,last_seen INTEGER NOT NULL,last_ip TEXT NOT NULL,note TEXT NOT NULL,ip_limit INTEGER NOT NULL)`,
			`CREATE TABLE user_store_meta(id INTEGER PRIMARY KEY CHECK(id=1),initialized INTEGER NOT NULL CHECK(initialized IN(0,1)),legacy_sha256 TEXT NOT NULL)`,
			`INSERT INTO user_store_meta VALUES(1,0,'')`,
			`PRAGMA application_id=0x41544c55`, `PRAGMA user_version=1`,
		} {
			if _, err := tx.ExecContext(ctx, query); err != nil {
				return nil, err
			}
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
	}
	var initialized int
	if err = createSubscriptionTables(db); err != nil {
		return nil, err
	}
	if err = createQuotaTables(db); err != nil {
		return nil, err
	}
	if err = createClientGroupTables(db); err != nil {
		return nil, err
	}
	if err = createInboundTables(db); err != nil {
		return nil, err
	}
	if err = db.QueryRowContext(ctx, "SELECT initialized FROM user_store_meta WHERE id=1").Scan(&initialized); err != nil {
		return nil, err
	}
	if initialized == 0 {
		snapshot := &userDB{Version: 1, Users: map[string]*userRecord{}}
		digest := ""
		if legacy != "" {
			data, readErr := readLegacyUsers(legacy)
			if readErr == nil {
				var parsed *userDB
				if err = json.Unmarshal(data, &parsed); err != nil {
					return nil, fmt.Errorf("invalid legacy users JSON: %w", err)
				}
				if parsed == nil {
					return nil, errors.New("legacy users object is required")
				}
				snapshot = parsed
				if err = validateUserDB(snapshot); err != nil {
					return nil, err
				}
				if err = backupLegacyUsers(legacy+".pre-sqlite", data); err != nil {
					return nil, err
				}
				h := sha256.Sum256(data)
				digest = hex.EncodeToString(h[:])
			} else if !os.IsNotExist(readErr) || strings.EqualFold(filepath.Ext(path), ".json") {
				return nil, fmt.Errorf("read legacy users: %w", readErr)
			}
		}
		if err = s.save(ctx, snapshot, digest); err != nil {
			return nil, err
		}
	}
	if _, err = s.load(ctx); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func readLegacyUsers(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const max = 10 << 20
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, errors.New("legacy users JSON exceeds 10 MiB")
	}
	return data, nil
}

func backupLegacyUsers(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(err) {
		old, e := readLegacyUsers(path)
		if e != nil {
			return e
		}
		if !bytes.Equal(data, old) {
			return errors.New("existing migration backup differs; refusing to overwrite")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err = writeFull(f, data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (s *sqliteUserStore) load(ctx context.Context) (*userDB, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,pbk,enabled,up_bytes,down_bytes,total_limit,expires_at,created_at,last_seen,last_ip,note,ip_limit FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &userDB{Version: 1, Users: map[string]*userRecord{}}
	for rows.Next() {
		r := &userRecord{}
		var enabled int
		var up, down, limit string
		if err = rows.Scan(&r.Name, &r.PBK, &enabled, &up, &down, &limit, &r.ExpiresAt, &r.CreatedAt, &r.LastSeen, &r.LastIP, &r.Note, &r.IPLimit); err != nil {
			return nil, err
		}
		if r.UpBytes, err = strconv.ParseUint(up, 10, 64); err != nil {
			return nil, errors.New("invalid stored upload counter")
		}
		if r.DownBytes, err = strconv.ParseUint(down, 10, 64); err != nil {
			return nil, errors.New("invalid stored download counter")
		}
		if r.TotalLimit, err = strconv.ParseUint(limit, 10, 64); err != nil {
			return nil, errors.New("invalid stored traffic limit")
		}
		r.Enabled = enabled == 1
		result.Users[r.Name] = r
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = validateUserDB(result); err != nil {
		return nil, err
	}
	s.persisted = make(map[string]userRecord, len(result.Users))
	for name, record := range result.Users {
		s.persisted[name] = *record
	}
	return result, nil
}

// Caller holds usersMu exclusively, so atomic traffic counters cannot change
// while a complete point-in-time snapshot is committed. No SQL on packet path.
func (s *sqliteUserStore) save(ctx context.Context, snapshot *userDB, legacyHash string) error {
	if err := validateUserDB(snapshot); err != nil {
		return err
	}
	if snapshot.Subscriptions != nil {
		if len(snapshot.Subscriptions) > 10000 {
			return errors.New("too many subscriptions")
		}
		seen := make(map[string]bool)
		for _, sub := range snapshot.Subscriptions {
			if sub.TotalLimit != nil {
				return errors.New("global quota restoration requires a complete coordinated SQLite snapshot")
			}
			if validateSubscription(&sub) != nil || snapshot.Users[sub.User] == nil || seen[sub.ID] {
				return errors.New("invalid subscription backup")
			}
			seen[sub.ID] = true
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if snapshot.Subscriptions != nil {
		var accounts int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM quota_accounts`).Scan(&accounts); err != nil {
			return err
		}
		if accounts > 0 {
			return errors.New("cannot replace subscriptions while a global quota ledger exists")
		}
	}
	var deleted []string
	for name := range s.persisted {
		if _, exists := snapshot.Users[name]; !exists {
			var accounts int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM quota_accounts q JOIN subscriptions s ON s.id=q.subscription_id WHERE s.user_name=?`, name).Scan(&accounts); err != nil {
				return err
			}
			if accounts > 0 {
				return errors.New("disable the global quota owner instead of deleting its ledger")
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM users WHERE name=?`, name); err != nil {
				return err
			}
			deleted = append(deleted, name)
		}
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO users(name,pbk,enabled,up_bytes,down_bytes,total_limit,expires_at,created_at,last_seen,last_ip,note,ip_limit) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET pbk=excluded.pbk,enabled=excluded.enabled,up_bytes=excluded.up_bytes,down_bytes=excluded.down_bytes,total_limit=excluded.total_limit,expires_at=excluded.expires_at,created_at=excluded.created_at,last_seen=excluded.last_seen,last_ip=excluded.last_ip,note=excluded.note,ip_limit=excluded.ip_limit`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	changed := make(map[string]userRecord)
	for name, r := range snapshot.Users {
		if previous, exists := s.persisted[name]; exists && previous == *r {
			continue
		}
		if _, err = stmt.ExecContext(ctx, name, r.PBK, r.Enabled, strconv.FormatUint(r.UpBytes, 10), strconv.FormatUint(r.DownBytes, 10), strconv.FormatUint(r.TotalLimit, 10), r.ExpiresAt, r.CreatedAt, r.LastSeen, r.LastIP, r.Note, r.IPLimit); err != nil {
			return err
		}
		changed[name] = *r
	}
	if legacyHash != "" {
		_, err = tx.ExecContext(ctx, `UPDATE user_store_meta SET initialized=1,legacy_sha256=? WHERE id=1`, legacyHash)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE user_store_meta SET initialized=1 WHERE id=1`)
	}
	if err != nil {
		return err
	}
	if snapshot.Subscriptions != nil {
		if _, err = tx.ExecContext(ctx, `DELETE FROM subscriptions`); err != nil {
			return err
		}
		for _, sub := range snapshot.Subscriptions {
			if err = writeSubscription(ctx, tx, sub); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if s.persisted == nil {
		s.persisted = make(map[string]userRecord)
	}
	for _, name := range deleted {
		delete(s.persisted, name)
	}
	for name, record := range changed {
		s.persisted[name] = record
	}
	return nil
}

func (s *sqliteUserStore) Close() error {
	err := s.db.Close()
	unlockErr := s.lock.Close()
	if err != nil {
		return err
	}
	return unlockErr
}

func usersStoreLocked(path string) (*sqliteUserStore, error) {
	database, _, err := resolveUsersPath(path)
	if err != nil {
		return nil, err
	}
	if currentUsersStore != nil {
		if currentUsersStore.path != database {
			return nil, errors.New("cannot switch users database in a running process")
		}
		return currentUsersStore, nil
	}
	store, err := openSQLiteUsers(path)
	if err == nil {
		currentUsersStore = store
	}
	return store, err
}

func closeUsersStore() {
	usersMu.Lock()
	defer usersMu.Unlock()
	if currentUsersStore != nil {
		_ = currentUsersStore.Close()
		currentUsersStore = nil
	}
}

func cloneUserDBLocked(source *userDB) *userDB {
	copyDB := &userDB{Version: source.Version, Users: make(map[string]*userRecord, len(source.Users))}
	for name, record := range source.Users {
		if record != nil {
			copyRecord := *record
			copyDB.Users[name] = &copyRecord
		}
	}
	return copyDB
}

// The candidate is private until its SQL transaction commits. A failed write
// cannot publish new credentials/limits to the authentication caches.
func updateUsers(path string, mutate func(*userDB) error) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	candidate := cloneUserDBLocked(usersDB)
	if err := mutate(candidate); err != nil {
		return err
	}
	if err := saveUsersLocked(path, candidate); err != nil {
		return err
	}
	usersDB = candidate
	syncStorageFromDBLocked()
	if err := reloadQuotaBindingsLocked(); err != nil {
		return err
	}
	usersDirty.Store(false)
	return nil
}
