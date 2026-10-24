package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var errInboundConflict = errors.New("inbound catalog changed; reload before saving")
var errInboundNotFound = errors.New("inbound not found")
var errInboundExists = errors.New("inbound already exists")
var errInboundReferenced = errors.New("inbound is referenced by a subscription")

type inboundRecord struct {
	Settings  InboundSpec `json:"settings"`
	PublicKey string      `json:"server_pub_key"`
	identity  *ecdh.PrivateKey
}

type inboundCatalog struct {
	Initialized bool            `json:"initialized"`
	Revision    int64           `json:"revision"`
	Inbounds    []inboundRecord `json:"inbounds"`
}

func createInboundTables(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS inbound_catalog_meta(id INTEGER PRIMARY KEY CHECK(id=1),initialized INTEGER NOT NULL CHECK(initialized IN(0,1)),revision INTEGER NOT NULL CHECK(revision>=0),migration_backup TEXT NOT NULL);
INSERT OR IGNORE INTO inbound_catalog_meta VALUES(1,0,0,'');
CREATE TABLE IF NOT EXISTS inbounds(id TEXT PRIMARY KEY NOT NULL,settings BLOB NOT NULL CHECK(length(settings)<=32768),private_key BLOB NOT NULL CHECK(length(private_key)=32),created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS inbound_applied_catalog(id INTEGER PRIMARY KEY CHECK(id=1),snapshot BLOB NOT NULL CHECK(length(snapshot)<=16777216));
CREATE TABLE IF NOT EXISTS control_server_identity(id INTEGER PRIMARY KEY CHECK(id=1),server_id TEXT NOT NULL UNIQUE CHECK(length(server_id)=32));
CREATE TABLE IF NOT EXISTS remote_inbound_catalogs(server_id TEXT PRIMARY KEY,peer_id TEXT NOT NULL UNIQUE,revision INTEGER NOT NULL,snapshot BLOB NOT NULL CHECK(length(snapshot)<=4194304));
CREATE TABLE IF NOT EXISTS remote_accounts(owner_panel TEXT NOT NULL,subscription_id TEXT NOT NULL,user_name TEXT NOT NULL UNIQUE REFERENCES users(name) ON DELETE CASCADE,revision INTEGER NOT NULL,enabled INTEGER NOT NULL,expires_at INTEGER NOT NULL,ip_limit INTEGER NOT NULL,endpoint TEXT NOT NULL,node_id TEXT NOT NULL,node_token TEXT NOT NULL,PRIMARY KEY(owner_panel,subscription_id));
CREATE TABLE IF NOT EXISTS remote_account_inbounds(owner_panel TEXT NOT NULL,subscription_id TEXT NOT NULL,inbound_id TEXT NOT NULL REFERENCES inbounds(id),PRIMARY KEY(owner_panel,subscription_id,inbound_id),FOREIGN KEY(owner_panel,subscription_id) REFERENCES remote_accounts(owner_panel,subscription_id) ON DELETE CASCADE);
INSERT OR IGNORE INTO control_server_identity(id,server_id) VALUES(1,lower(hex(randomblob(16))));`)
	return err
}

func readInboundCatalogTx(ctx context.Context, tx *sql.Tx) (inboundCatalog, error) {
	catalog := inboundCatalog{Inbounds: []inboundRecord{}}
	if err := tx.QueryRowContext(ctx, `SELECT initialized,revision FROM inbound_catalog_meta WHERE id=1`).Scan(&catalog.Initialized, &catalog.Revision); err != nil {
		return catalog, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,settings,private_key FROM inbounds ORDER BY id LIMIT 257`)
	if err != nil {
		return catalog, err
	}
	defer rows.Close()
	var specs []InboundSpec
	for rows.Next() {
		var id string
		var settings, private []byte
		if err := rows.Scan(&id, &settings, &private); err != nil {
			return catalog, err
		}
		if len(settings) > 32768 || len(catalog.Inbounds) >= 256 {
			return catalog, errors.New("invalid stored inbound catalog size")
		}
		var spec InboundSpec
		decoder := json.NewDecoder(bytes.NewReader(settings))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&spec); err != nil {
			return catalog, errors.New("invalid stored inbound settings")
		}
		if decoder.Decode(new(any)) != io.EOF || spec.ID != id {
			return catalog, errors.New("invalid stored inbound ID or trailing data")
		}
		identity, err := ecdh.X25519().NewPrivateKey(private)
		clear(private)
		if err != nil {
			return catalog, errors.New("invalid stored inbound identity")
		}
		catalog.Inbounds = append(catalog.Inbounds, inboundRecord{Settings: spec, PublicKey: hex.EncodeToString(identity.PublicKey().Bytes()), identity: identity})
		specs = append(specs, spec)
	}
	if err := rows.Err(); err != nil {
		return catalog, err
	}
	if err := validateInboundSet(specs); err != nil {
		return catalog, fmt.Errorf("invalid stored inbound catalog: %w", err)
	}
	if !catalog.Initialized && (catalog.Revision != 0 || len(catalog.Inbounds) != 0) || catalog.Initialized && catalog.Revision < 1 {
		return catalog, errors.New("inbound initialization marker is inconsistent")
	}
	return catalog, nil
}

func (s *sqliteUserStore) readInboundCatalog(ctx context.Context) (inboundCatalog, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return inboundCatalog{}, err
	}
	defer tx.Rollback()
	return readInboundCatalogTx(ctx, tx)
}

// The directory is private before SQLite creates the file. Keep failed
// migration snapshots for recovery rather than deleting potentially useful data.
func (s *sqliteUserStore) inboundMigrationBackup(ctx context.Context) (string, error) {
	dir, err := os.MkdirTemp(filepath.Dir(s.path), ".atlant-pre-inbounds-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "snapshot.db")
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if runtime.GOOS != "windows" {
		for _, directory := range []string{dir, filepath.Dir(dir)} {
			d, err := os.Open(directory)
			if err != nil {
				return "", err
			}
			err = d.Sync()
			closeErr = d.Close()
			if err != nil {
				return "", err
			}
			if closeErr != nil {
				return "", closeErr
			}
		}
	}
	return path, nil
}

// Called before native listeners start, with the existing writer/store owned by
// this process. An initialized empty catalog is intentional and never imports
// the old config again. Migration keeps the original key and all other tables.
func (s *sqliteUserStore) initializeInboundCatalog(ctx context.Context, legacy *InboundSpec, identity *ecdh.PrivateKey) (string, error) {
	catalog, err := s.readInboundCatalog(ctx)
	if err != nil || catalog.Initialized {
		return "", err
	}
	if legacy != nil {
		if err := legacy.validate(); err != nil {
			return "", err
		}
		if identity == nil {
			return "", errors.New("legacy inbound identity is required")
		}
	}
	// Persistent backups require an explicit request; migration stays atomic in SQL.
	backup := ""
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	catalog, err = readInboundCatalogTx(ctx, tx)
	if err != nil {
		return "", err
	}
	if catalog.Initialized {
		return "", nil
	}
	if legacy != nil {
		settings, err := json.Marshal(legacy)
		if err != nil {
			return "", err
		}
		private := identity.Bytes()
		defer clear(private)
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, `INSERT INTO inbounds VALUES(?,?,?,?,?)`, legacy.ID, settings, private, now, now); err != nil {
			return "", err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inbound_catalog_meta SET initialized=1,revision=1,migration_backup=? WHERE id=1 AND initialized=0`, backup); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return backup, nil
}

func checkInboundRevision(catalog inboundCatalog, expected int64) error {
	if !catalog.Initialized {
		return errors.New("inbound catalog must be initialized before editing")
	}
	if expected != catalog.Revision {
		return errInboundConflict
	}
	if expected == math.MaxInt64 {
		return errors.New("inbound catalog revision exhausted")
	}
	return nil
}

func bumpInboundRevision(ctx context.Context, tx *sql.Tx, expected int64) error {
	result, err := tx.ExecContext(ctx, `UPDATE inbound_catalog_meta SET revision=revision+1 WHERE id=1 AND initialized=1 AND revision=?`, expected)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errInboundConflict
	}
	return nil
}

func (s *sqliteUserStore) putInbound(ctx context.Context, spec InboundSpec, expected int64, create bool) (inboundRecord, int64, error) {
	empty := inboundRecord{}
	if err := spec.validate(); err != nil {
		return empty, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, 0, err
	}
	defer tx.Rollback()
	catalog, err := readInboundCatalogTx(ctx, tx)
	if err != nil {
		return empty, 0, err
	}
	if err := checkInboundRevision(catalog, expected); err != nil {
		return empty, 0, err
	}
	var current *inboundRecord
	specs := make([]InboundSpec, 0, len(catalog.Inbounds)+1)
	for i := range catalog.Inbounds {
		record := &catalog.Inbounds[i]
		if record.Settings.ID == spec.ID {
			current = record
		} else {
			specs = append(specs, record.Settings)
		}
	}
	if create && current != nil {
		return empty, 0, errInboundExists
	}
	if !create && current == nil {
		return empty, 0, errInboundNotFound
	}
	specs = append(specs, spec)
	if err := validateInboundSet(specs); err != nil {
		return empty, 0, err
	}
	settings, err := json.Marshal(spec)
	if err != nil {
		return empty, 0, err
	}
	now := time.Now().Unix()
	var identity *ecdh.PrivateKey
	if create {
		identity, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return empty, 0, err
		}
		private := identity.Bytes()
		defer clear(private)
		_, err = tx.ExecContext(ctx, `INSERT INTO inbounds VALUES(?,?,?,?,?)`, spec.ID, settings, private, now, now)
	} else {
		identity = current.identity
		_, err = tx.ExecContext(ctx, `UPDATE inbounds SET settings=?,updated_at=? WHERE id=?`, settings, now, spec.ID)
	}
	if err != nil {
		return empty, 0, err
	}
	if err := bumpInboundRevision(ctx, tx, expected); err != nil {
		return empty, 0, err
	}
	if err := tx.Commit(); err != nil {
		return empty, 0, err
	}
	return inboundRecord{Settings: spec, PublicKey: hex.EncodeToString(identity.PublicKey().Bytes()), identity: identity}, expected + 1, nil
}

func (s *sqliteUserStore) deleteInbound(ctx context.Context, id string, expected int64) (int64, error) {
	if !inboundIDPattern.MatchString(id) {
		return 0, errors.New("invalid inbound ID")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	catalog, err := readInboundCatalogTx(ctx, tx)
	if err != nil {
		return 0, err
	}
	if err := checkInboundRevision(catalog, expected); err != nil {
		return 0, err
	}
	var references int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscription_inbound_refs WHERE server_id=(SELECT server_id FROM control_server_identity WHERE id=1) AND inbound_id=?`, id).Scan(&references); err != nil {
		return 0, err
	}
	if references > 0 {
		return 0, errInboundReferenced
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM inbounds WHERE id=?`, id)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if count != 1 {
		return 0, errInboundNotFound
	}
	if err := bumpInboundRevision(ctx, tx, expected); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return expected + 1, nil
}
