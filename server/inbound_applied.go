package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// This private snapshot is distinct from editable saved settings. A failed
// candidate must not become the boot configuration on the next restart.
type persistedInboundCatalog struct {
	Revision int64                    `json:"revision"`
	Records  []persistedInboundRecord `json:"records"`
}
type persistedInboundRecord struct {
	Settings InboundSpec `json:"settings"`
	Private  []byte      `json:"private"`
}

func (s *sqliteUserStore) saveAppliedInboundCatalog(ctx context.Context, catalog inboundCatalog) error {
	if !catalog.Initialized || catalog.Revision < 1 {
		return errors.New("invalid applied catalog")
	}
	snapshot := persistedInboundCatalog{Revision: catalog.Revision}
	defer func() {
		for _, r := range snapshot.Records {
			clear(r.Private)
		}
	}()
	var specs []InboundSpec
	for _, record := range catalog.Inbounds {
		if record.identity == nil {
			return errors.New("missing applied identity")
		}
		snapshot.Records = append(snapshot.Records, persistedInboundRecord{Settings: record.Settings, Private: record.identity.Bytes()})
		specs = append(specs, record.Settings)
	}
	if err := validateInboundSet(specs); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	defer clear(data)
	_, err = s.db.ExecContext(ctx, `INSERT INTO inbound_applied_catalog(id,snapshot) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot`, data)
	return err
}

func (s *sqliteUserStore) readAppliedInboundCatalog(ctx context.Context) (*inboundCatalog, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT snapshot FROM inbound_applied_catalog WHERE id=1`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if len(data) > 16<<20 {
		return nil, errors.New("applied snapshot too large")
	}
	var stored persistedInboundCatalog
	defer func() {
		for _, r := range stored.Records {
			clear(r.Private)
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF || stored.Revision < 1 {
		return nil, errors.New("invalid applied snapshot")
	}
	catalog := &inboundCatalog{Initialized: true, Revision: stored.Revision, Inbounds: []inboundRecord{}}
	var specs []InboundSpec
	for _, record := range stored.Records {
		identity, err := ecdh.X25519().NewPrivateKey(record.Private)
		if err != nil {
			return nil, err
		}
		catalog.Inbounds = append(catalog.Inbounds, inboundRecord{Settings: record.Settings, identity: identity, PublicKey: hex.EncodeToString(identity.PublicKey().Bytes())})
		specs = append(specs, record.Settings)
	}
	if err := validateInboundSet(specs); err != nil {
		return nil, err
	}
	return catalog, nil
}

func bootNativeInboundCatalog(ctx context.Context, saved *inboundCatalog) (*inboundCatalog, error) {
	if saved == nil {
		return nil, nil
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		return nil, err
	}
	applied, err := store.readAppliedInboundCatalog(ctx)
	if err != nil {
		return nil, err
	}
	if applied == nil {
		return saved, nil
	}
	if applied.Revision > saved.Revision {
		return nil, errors.New("applied revision exceeds saved catalog")
	}
	return applied, nil
}

func persistAppliedInboundCatalog(catalog inboundCatalog) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		return err
	}
	return store.saveAppliedInboundCatalog(context.Background(), catalog)
}
