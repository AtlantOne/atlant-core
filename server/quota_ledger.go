package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const quotaChunk = int64(4 << 20)
const quotaMaxValue = int64(1 << 60)

var errQuotaClock = errors.New("quota request clock mismatch")

// A reservation is not a VPN ticket. It only authorizes a trusted server to
// account bytes locally; no identifier is added to the VPN wire format.
type quotaRequest struct {
	ID           string `json:"id"`
	Session      string `json:"session"`
	Subscription string `json:"subscription"`
	Grant        string `json:"grant,omitempty"`
	Up           int64  `json:"up"`
	Down         int64  `json:"down"`
	Want         int64  `json:"want"`
	Close        bool   `json:"close"`
	IssuedAt     int64  `json:"issued_at"`
}

type quotaReply struct {
	Grant        string `json:"grant,omitempty"`
	Capacity     int64  `json:"capacity"`
	Allowed      bool   `json:"allowed"`
	ValidSeconds int64  `json:"valid_seconds"`
}

type quotaSnapshot struct {
	Total    int64 `json:"total_limit"`
	Up       int64 `json:"upload"`
	Down     int64 `json:"download"`
	Reserved int64 `json:"reserved"`
}

func createQuotaTables(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS quota_accounts(subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,total INTEGER NOT NULL CHECK(total>=0),up INTEGER NOT NULL CHECK(up>=0),down INTEGER NOT NULL CHECK(down>=0),reserved INTEGER NOT NULL CHECK(reserved>=0));
CREATE TABLE IF NOT EXISTS quota_nodes(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,enabled INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS quota_node_subscriptions(node_id TEXT NOT NULL REFERENCES quota_nodes(id) ON DELETE CASCADE,subscription_id TEXT NOT NULL REFERENCES quota_accounts(subscription_id) ON DELETE CASCADE,PRIMARY KEY(node_id,subscription_id));
CREATE TABLE IF NOT EXISTS quota_bindings(user_name TEXT PRIMARY KEY REFERENCES users(name) ON DELETE CASCADE,subscription_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS quota_grants(id TEXT PRIMARY KEY,subscription_id TEXT NOT NULL REFERENCES quota_accounts(subscription_id) ON DELETE CASCADE,node_id TEXT NOT NULL,session TEXT NOT NULL,capacity INTEGER NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,closed INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS quota_one_active ON quota_grants(subscription_id,node_id,session) WHERE closed=0;
CREATE TABLE IF NOT EXISTS quota_requests(node_id TEXT NOT NULL,id TEXT NOT NULL,digest TEXT NOT NULL,response BLOB NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(node_id,id));
CREATE INDEX IF NOT EXISTS quota_requests_expiry ON quota_requests(expires_at);
CREATE INDEX IF NOT EXISTS quota_closed_grants_expiry ON quota_grants(updated_at) WHERE closed=1;`)
	return err
}

func quotaID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

func validQuotaID(s string) bool { return len(s) == 32 && isValidHex(s) }

func readQuota(ctx context.Context, db *sql.DB, id string) (quotaSnapshot, error) {
	var q quotaSnapshot
	err := db.QueryRowContext(ctx, `SELECT total,up,down,reserved FROM quota_accounts WHERE subscription_id=?`, id).Scan(&q.Total, &q.Up, &q.Down, &q.Reserved)
	return q, err
}

// Called inside the same transaction as subscription edits. Existing counters
// never come from an API payload and cannot be reset by a stale panel form.
func writeSubscriptionQuota(ctx context.Context, tx *sql.Tx, s SubscriptionRecord, owner *userRecord) error {
	if s.TotalLimit == nil {
		return nil
	}
	if *s.TotalLimit > uint64(quotaMaxValue) {
		return errors.New("quota too large")
	}
	var other string
	err := tx.QueryRowContext(ctx, `SELECT subscription_id FROM quota_bindings WHERE user_name=?`, s.User).Scan(&other)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil && other != s.ID {
		return errors.New("use a separate connection account for each subscription")
	}
	up, down := int64(0), int64(0)
	// Preserve usage when moving an existing capped account to a subscription.
	if owner != nil {
		if owner.UpBytes > uint64(quotaMaxValue) || owner.DownBytes > uint64(quotaMaxValue) || totalTraffic(owner.UpBytes, owner.DownBytes) > uint64(quotaMaxValue) {
			return errors.New("usage outside quota range")
		}
		up, down = int64(owner.UpBytes), int64(owner.DownBytes)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO quota_accounts VALUES(?,?,?,?,0) ON CONFLICT(subscription_id) DO UPDATE SET total=excluded.total`, s.ID, int64(*s.TotalLimit), up, down); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO quota_bindings VALUES(?,?) ON CONFLICT(user_name) DO UPDATE SET subscription_id=excluded.subscription_id`, s.User, s.ID)
	return err
}

// The SQLite owner uses one connection. A transaction serializes reports and
// reservations across all nodes, including concurrent requests after a restart.
func processQuota(ctx context.Context, db *sql.DB, node string, r quotaRequest, now time.Time) (quotaReply, error) {
	var reply quotaReply
	if !validQuotaID(r.ID) || !validQuotaID(r.Session) || !validQuotaID(r.Subscription) || (r.Grant != "" && !validQuotaID(r.Grant)) || r.Up < 0 || r.Down < 0 || r.Up > quotaMaxValue || r.Down > quotaMaxValue || r.Up > quotaMaxValue-r.Down || r.Want < 0 || r.Want > quotaChunk {
		return reply, errors.New("invalid quota request")
	}
	raw, _ := json.Marshal(r)
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return reply, err
	}
	defer tx.Rollback()
	var previous string
	var saved []byte
	err = tx.QueryRowContext(ctx, `SELECT digest,response FROM quota_requests WHERE node_id=? AND id=?`, node, r.ID).Scan(&previous, &saved)
	if err == nil {
		if previous != digest {
			return reply, errors.New("conflicting quota request ID")
		}
		err = json.Unmarshal(saved, &reply)
		return reply, err
	}
	if err != sql.ErrNoRows {
		return reply, err
	}
	// Expired request IDs cannot allocate again after response-cache pruning.
	if r.IssuedAt < now.Unix()-120 || r.IssuedAt > now.Unix()+120 {
		return reply, errQuotaClock
	}
	if node != "local" {
		var allowed int
		if err = tx.QueryRowContext(ctx, `SELECT 1 FROM quota_node_subscriptions a JOIN quota_nodes n ON n.id=a.node_id WHERE a.node_id=? AND a.subscription_id=? AND n.enabled=1`, node, r.Subscription).Scan(&allowed); err != nil {
			return reply, errors.New("node not assigned to subscription")
		}
	}
	var q quotaSnapshot
	var enabled bool
	var expires int64
	var ownerEnabled bool
	var ownerExpires int64
	err = tx.QueryRowContext(ctx, `SELECT q.total,q.up,q.down,q.reserved,s.enabled,s.expires_at,u.enabled,u.expires_at FROM quota_accounts q JOIN subscriptions s ON s.id=q.subscription_id JOIN users u ON u.name=s.user_name WHERE q.subscription_id=?`, r.Subscription).Scan(&q.Total, &q.Up, &q.Down, &q.Reserved, &enabled, &expires, &ownerEnabled, &ownerExpires)
	if err != nil {
		return reply, err
	}
	if ownerExpires > 0 && (expires == 0 || ownerExpires < expires) {
		expires = ownerExpires
	}
	valid := enabled && ownerEnabled && (expires == 0 || now.Unix() < expires)
	if r.Grant != "" {
		var capacity, up, down int64
		var closed bool
		var sub, owner, session string
		err = tx.QueryRowContext(ctx, `SELECT subscription_id,node_id,session,capacity,up,down,closed FROM quota_grants WHERE id=?`, r.Grant).Scan(&sub, &owner, &session, &capacity, &up, &down, &closed)
		if err != nil || sub != r.Subscription || owner != node || session != r.Session || closed || r.Up < up || r.Down < down || r.Up+r.Down > capacity {
			return reply, errors.New("invalid cumulative grant report")
		}
		delta := r.Up - up + r.Down - down
		if delta > q.Reserved || q.Up > quotaMaxValue-(r.Up-up) || q.Down > quotaMaxValue-(r.Down-down) {
			return reply, errors.New("quota counter overflow")
		}
		q.Reserved -= delta
		q.Up += r.Up - up
		q.Down += r.Down - down
		if r.Close {
			q.Reserved -= capacity - r.Up - r.Down
		} else {
			reply.Grant = r.Grant
			reply.Capacity = capacity
		}
		if q.Reserved < 0 {
			return reply, errors.New("invalid reservation balance")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE quota_grants SET up=?,down=?,closed=?,updated_at=? WHERE id=?`, r.Up, r.Down, r.Close, now.Unix(), r.Grant); err != nil {
			return reply, err
		}
	} else if r.Up != 0 || r.Down != 0 || r.Close {
		return reply, errors.New("report without grant")
	}
	if valid && reply.Grant == "" && r.Want > 0 {
		// A lost response is retried with the same ID. A process restart uses a
		// new session, never reuses a reservation whose usage was lost from RAM.
		var active string
		err = tx.QueryRowContext(ctx, `SELECT id FROM quota_grants WHERE subscription_id=? AND node_id=? AND session=? AND closed=0`, r.Subscription, node, r.Session).Scan(&active)
		if err == nil {
			return reply, errors.New("active grant must be settled first")
		}
		if err != sql.ErrNoRows {
			return reply, err
		}
		available := quotaMaxValue - q.Up - q.Down - q.Reserved
		if q.Total > 0 {
			available = q.Total - q.Up - q.Down - q.Reserved
		}
		amount := r.Want
		if amount > available {
			amount = available
		}
		if amount > 0 {
			reply.Grant = quotaID()
			if reply.Grant == "" {
				return reply, errors.New("entropy unavailable")
			}
			reply.Capacity = amount
			q.Reserved += amount
			if _, err = tx.ExecContext(ctx, `INSERT INTO quota_grants VALUES(?,?,?,?,?,0,0,0,?)`, reply.Grant, r.Subscription, node, r.Session, amount, now.Unix()); err != nil {
				return reply, err
			}
		}
	}
	reply.Allowed = valid && reply.Grant != "" && (q.Total == 0 || (q.Up+q.Down < q.Total && q.Up+q.Down+q.Reserved <= q.Total))
	if reply.Allowed {
		reply.ValidSeconds = 6
		if expires > 0 && expires-now.Unix() < 6 {
			reply.ValidSeconds = expires - now.Unix()
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE quota_accounts SET up=?,down=?,reserved=? WHERE subscription_id=?`, q.Up, q.Down, q.Reserved, r.Subscription); err != nil {
		return reply, err
	}
	// Bound replay-cache size by time; old requests have an expired IssuedAt.
	if _, err = tx.ExecContext(ctx, `DELETE FROM quota_requests WHERE expires_at<?`, now.Unix()); err != nil {
		return reply, err
	}
	data, _ := json.Marshal(reply)
	retention := int64(300)
	if r.Close || (r.Grant == "" && r.Want > 0) {
		retention = 7 * 86400
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO quota_requests VALUES(?,?,?,?,?)`, node, r.ID, digest, data, now.Unix()+retention); err != nil {
		return reply, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM quota_grants WHERE closed=1 AND updated_at<?`, now.Unix()-7*86400); err != nil {
		return reply, err
	}
	return reply, tx.Commit()
}

func quotaNodeName(s string) bool {
	if len(s) < 1 || len(s) > 64 || s == "local" {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-", c) {
			return false
		}
	}
	return true
}
