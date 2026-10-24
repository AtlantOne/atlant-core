package main

import (
	"context"
	"database/sql"
	"errors"
)

type inboundSQLReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func localControlServerID(ctx context.Context, reader inboundSQLReader) (string, error) {
	var id string
	err := reader.QueryRowContext(ctx, `SELECT server_id FROM control_server_identity WHERE id=1`).Scan(&id)
	if err == nil && (len(id) != 32 || !isValidHex(id)) {
		err = errors.New("invalid control server identity")
	}
	return id, err
}

func validateSubscriptionInboundRefs(ctx context.Context, tx *sql.Tx, refs []SubscriptionInboundRef) error {
	if len(refs) == 0 {
		return nil
	}
	if len(refs) > 256 {
		return errors.New("too many subscription inbound references")
	}
	local, err := localControlServerID(ctx, tx)
	if err != nil {
		return err
	}
	catalog, err := readInboundCatalogTx(ctx, tx)
	if err != nil {
		return err
	}
	if !catalog.Initialized {
		return errors.New("inbound catalog not initialized")
	}
	available := make(map[string]bool)
	for _, record := range catalog.Inbounds {
		available[record.Settings.ID] = true
	}
	seen := make(map[SubscriptionInboundRef]bool)
	for _, ref := range refs {
		if ref.ServerID != local || !inboundIDPattern.MatchString(ref.InboundID) || !available[ref.InboundID] || seen[ref] {
			return errors.New("unknown or duplicate subscription inbound reference")
		}
		seen[ref] = true
	}
	return nil
}

func writeSubscriptionInboundRefs(ctx context.Context, tx *sql.Tx, id string, refs []SubscriptionInboundRef) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM subscription_inbound_refs WHERE subscription_id=?`, id); err != nil {
		return err
	}
	for position, ref := range refs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_inbound_refs VALUES(?,?,?,?)`, id, position, ref.ServerID, ref.InboundID); err != nil {
			return err
		}
	}
	return nil
}

func readSubscriptionInboundRefs(ctx context.Context, store *sqliteUserStore, id string) ([]SubscriptionInboundRef, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT server_id,inbound_id FROM subscription_inbound_refs WHERE subscription_id=? ORDER BY position LIMIT 257`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := []SubscriptionInboundRef{}
	for rows.Next() {
		var ref SubscriptionInboundRef
		if err := rows.Scan(&ref.ServerID, &ref.InboundID); err != nil {
			return nil, err
		}
		if !inboundIDPattern.MatchString(ref.ServerID) || !inboundIDPattern.MatchString(ref.InboundID) {
			return nil, errors.New("invalid stored subscription reference")
		}
		refs = append(refs, ref)
	}
	if len(refs) > 256 {
		return nil, errors.New("too many stored subscription references")
	}
	return refs, rows.Err()
}

// The public feed uses the last applied snapshot, not editable saved settings.
// A newly saved inbound therefore appears only after it is successfully applied.
func resolveSubscriptionInboundNodes(ctx context.Context, store *sqliteUserStore, id string) ([]SubscriptionNode, error) {
	refs, err := readSubscriptionInboundRefs(ctx, store, id)
	if err != nil || len(refs) == 0 {
		return nil, err
	}
	local, err := localControlServerID(ctx, store.db)
	if err != nil {
		return nil, err
	}
	catalog, err := store.readAppliedInboundCatalog(ctx)
	if err != nil {
		return nil, err
	}
	if catalog == nil {
		return nil, errors.New("no applied inbound configuration")
	}
	records := make(map[string]inboundRecord)
	for _, record := range catalog.Inbounds {
		records[record.Settings.ID] = record
	}
	result := []SubscriptionNode{}
	for _, ref := range refs {
		if ref.ServerID != local {
			return nil, errors.New("remote inbound catalog is not available")
		}
		record, ok := records[ref.InboundID]
		if !ok || !record.Settings.Enabled {
			continue
		}
		spec := record.Settings
		if spec.AdvertiseAddr == "" {
			return nil, errors.New("public inbound address is required for subscriptions")
		}
		transport := "quic"
		for _, value := range spec.Transports {
			if value == "xhttp" {
				transport = "xhttp"
			}
			if value == "tcp" {
				transport = "reality"
				break
			}
		}
		result = append(result, SubscriptionNode{Name: spec.Name, Server: spec.AdvertiseAddr, SNI: spec.SNI, ServerPubKey: record.PublicKey, Transport: transport, WireVersion: spec.WireVersion, XHTTPPath: spec.XHTTPPath, ServerID: local, InboundID: spec.ID, Transports: append([]string(nil), spec.Transports...)})
	}
	return result, nil
}
