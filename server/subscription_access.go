package main

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync/atomic"
	"time"
)

type subscriptionUserAccess struct {
	ID           string
	Enabled      bool
	Expires      int64
	IPLimit      int
	Inbounds     map[string]bool
	RequireQuota bool
}
type subscriptionAccessIndex struct {
	Users   map[string]subscriptionUserAccess
	Blocked bool
}

var subscriptionAccess atomic.Pointer[subscriptionAccessIndex]

func writeNativeSubscriptionOwner(ctx context.Context, tx *sql.Tx, s SubscriptionRecord) error {
	var remote int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM remote_accounts WHERE user_name=?`, s.User).Scan(&remote); err != nil {
		return err
	}
	if remote != 0 {
		return errors.New("remote account cannot own a local subscription")
	}
	var owner string
	err := tx.QueryRowContext(ctx, `SELECT user_name FROM subscription_native_owners WHERE subscription_id=?`, s.ID).Scan(&owner)
	if err == nil {
		if owner != s.User {
			return errors.New("native subscription owner is immutable")
		}
		return writeSubscriptionClientPolicy(ctx, tx, s)
	}
	if err != sql.ErrNoRows {
		return err
	}
	var bound string
	err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM subscription_native_owners WHERE user_name=?`, s.User).Scan(&bound)
	if err == nil && bound != s.ID {
		return errors.New("account belongs to another native subscription")
	}
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if len(s.InboundRefs) == 0 {
		if s.IPLimit != 0 || s.Note != "" {
			return errors.New("client policy requires a native subscription")
		}
		return nil
	}
	var others int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscriptions WHERE user_name=? AND id<>?`, s.User, s.ID).Scan(&others); err != nil {
		return err
	}
	if others > 0 {
		return errors.New("native subscription needs a dedicated account")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO subscription_native_owners VALUES(?,?)`, s.ID, s.User)
	if err != nil {
		return err
	}
	return writeSubscriptionClientPolicy(ctx, tx, s)
}

func writeSubscriptionClientPolicy(ctx context.Context, tx *sql.Tx, s SubscriptionRecord) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO subscription_client_policy VALUES(?,?,?) ON CONFLICT(subscription_id) DO UPDATE SET ip_limit=excluded.ip_limit,note=excluded.note`, s.ID, s.IPLimit, s.Note)
	return err
}

func insertSubscriptionOwner(ctx context.Context, tx *sql.Tx, u *userRecord) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO users(name,pbk,enabled,up_bytes,down_bytes,total_limit,expires_at,created_at,last_seen,last_ip,note,ip_limit) VALUES(?,?,1,'0','0','0',0,?,0,'','',0)`, u.Name, u.PBK, u.CreatedAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE user_store_meta SET initialized=1 WHERE id=1`)
	return err
}

// Call with usersMu held. No SQL or mutable maps are read from packet handlers.
func reloadSubscriptionAccessLocked() (err error) {
	if currentUsersStore == nil {
		return nil
	}
	defer func() {
		if err != nil {
			subscriptionAccess.Store(&subscriptionAccessIndex{Blocked: true})
		}
	}()
	ctx := context.Background()
	local, err := localControlServerID(ctx, currentUsersStore.db)
	if err != nil {
		return err
	}
	rows, err := currentUsersStore.db.QueryContext(ctx, `SELECT s.user_name,s.id,s.enabled,s.expires_at,r.inbound_id,COALESCE(p.ip_limit,0) FROM subscription_native_owners m JOIN subscriptions s ON s.id=m.subscription_id LEFT JOIN subscription_inbound_refs r ON r.subscription_id=s.id AND r.server_id=? LEFT JOIN subscription_client_policy p ON p.subscription_id=s.id`, local)
	if err != nil {
		return err
	}
	defer rows.Close()
	index := &subscriptionAccessIndex{Users: make(map[string]subscriptionUserAccess)}
	for rows.Next() {
		var name, id string
		var enabled bool
		var expires int64
		var ipLimit int
		var inbound sql.NullString
		if err = rows.Scan(&name, &id, &enabled, &expires, &inbound, &ipLimit); err != nil {
			return err
		}
		access, exists := index.Users[name]
		if !exists {
			access = subscriptionUserAccess{ID: id, Enabled: enabled, Expires: expires, IPLimit: ipLimit, Inbounds: make(map[string]bool)}
		}
		if access.ID != id {
			return errors.New("ambiguous native subscription owner")
		}
		if inbound.Valid {
			access.Inbounds[inbound.String] = true
		}
		index.Users[name] = access
	}
	if err = rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if err = loadRemoteAccess(ctx, currentUsersStore, index); err != nil {
		return err
	}
	subscriptionAccess.Store(index)
	return nil
}

func subscriptionRequiresQuota(name string) bool {
	index := subscriptionAccess.Load()
	if index == nil {
		return false
	}
	return index.Blocked || index.Users[name].RequireQuota
}

func subscriptionUserAllowed(name string) bool {
	index := subscriptionAccess.Load()
	if index == nil {
		return true
	}
	if index.Blocked {
		return false
	}
	access, managed := index.Users[name]
	return !managed || (access.Enabled && (access.Expires == 0 || time.Now().Unix() < access.Expires))
}

func subscriptionIPLimit(name string, fallback int) int {
	if index := subscriptionAccess.Load(); index != nil {
		if access, managed := index.Users[name]; managed {
			return access.IPLimit
		}
	}
	return fallback
}

func inboundUserAllowed(id, name string) bool {
	index := subscriptionAccess.Load()
	if index == nil {
		return true
	}
	if index.Blocked {
		return false
	}
	access, managed := index.Users[name]
	return !managed || (access.Enabled && (access.Expires == 0 || time.Now().Unix() < access.Expires) && access.Inbounds[id])
}

func changedSubscriptionAccess(old, next *subscriptionAccessIndex) []string {
	if old == next {
		return nil
	}
	var names []string
	if old != nil {
		for name, previous := range old.Users {
			if next == nil || next.Blocked || !reflect.DeepEqual(previous, next.Users[name]) {
				names = append(names, name)
			}
		}
	}
	if next != nil && !next.Blocked {
		for name := range next.Users {
			if old == nil {
				names = append(names, name)
				continue
			}
			if _, previouslyManaged := old.Users[name]; !previouslyManaged {
				names = append(names, name)
			}
		}
	}
	return names
}
