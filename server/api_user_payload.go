package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Presence matters: an omitted quota must not erase it, while explicit zero
// means unlimited. Null and duplicate keys are rejected rather than ambiguous.
func (p *UserPayload) UnmarshalJSON(data []byte) error {
	type plain UserPayload
	var value plain
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return err
	}
	fields := json.NewDecoder(bytes.NewReader(data))
	first, err := fields.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("object required")
	}
	present := make(map[string]bool)
	for fields.More() {
		key, err := fields.Token()
		if err != nil {
			return err
		}
		name := key.(string)
		switch name {
		case "name", "names", "pbk", "total_limit", "limit_gb", "expires_at", "expire_days", "ip_limit", "enabled", "note":
		default:
			return errors.New("unknown or noncanonical field")
		}
		var raw json.RawMessage
		if err := fields.Decode(&raw); err != nil {
			return err
		}
		if present[name] || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("duplicate or null field")
		}
		present[name] = true
	}
	*p = UserPayload(value)
	p.present = present
	return nil
}

func decodeUserPayload(w http.ResponseWriter, r *http.Request, p *UserPayload) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var err error
	if media == "application/x-www-form-urlencoded" {
		err = r.ParseForm()
		if err == nil {
			values := make(map[string]any)
			for key, list := range r.PostForm {
				if len(list) != 1 {
					err = errors.New("duplicate form field")
					break
				}
				s := list[0]
				switch key {
				case "name", "pbk", "note":
					values[key] = s
				case "limit_gb":
					values[key], err = strconv.ParseFloat(s, 64)
				case "total_limit":
					values[key], err = strconv.ParseUint(s, 10, 64)
				case "expire_days", "expires_at", "ip_limit":
					values[key], err = strconv.ParseInt(s, 10, 64)
				case "enabled":
					values[key], err = strconv.ParseBool(s)
				default:
					err = errors.New("unknown form field")
				}
				if err != nil {
					break
				}
			}
			if err == nil {
				var data []byte
				data, err = json.Marshal(values)
				if err == nil {
					err = json.Unmarshal(data, p)
				}
			}
		}
	} else {
		d := json.NewDecoder(r.Body)
		err = d.Decode(p)
		if err == nil {
			var extra any
			if d.Decode(&extra) != io.EOF {
				err = errors.New("trailing JSON")
			}
		}
	}
	if err == nil {
		err = p.validate()
	}
	if err != nil {
		http.Error(w, `{"error":"invalid user payload"}`, http.StatusBadRequest)
		return false
	}
	return true
}

func (p *UserPayload) validate() error {
	p.Name = strings.TrimSpace(p.Name)
	p.PBK = strings.TrimSpace(p.PBK)
	if !isValidUsername(p.Name) || len(p.Note) > 4096 || p.IPLimit < 0 || p.IPLimit > 1000000 || p.ExpiresAt < 0 || p.ExpireDays < 0 || p.ExpireDays > 36500 {
		return errors.New("invalid user fields")
	}
	if p.PBK != "" && (len(p.PBK) != 64 || !isValidHex(p.PBK)) {
		return errors.New("invalid PBK")
	}
	if p.present["limit_gb"] {
		if p.present["total_limit"] || math.IsNaN(p.LimitGB) || math.IsInf(p.LimitGB, 0) || p.LimitGB < 0 || p.LimitGB*1073741824 >= math.Exp2(64) {
			return errors.New("invalid quota")
		}
		p.TotalLimit = uint64(p.LimitGB * 1073741824)
		if p.LimitGB > 0 && p.TotalLimit == 0 {
			return errors.New("quota is smaller than one byte")
		}
		p.present["total_limit"] = true
	}
	if p.present["expire_days"] {
		if p.present["expires_at"] {
			return errors.New("ambiguous expiry")
		}
		if p.ExpireDays > 0 {
			p.ExpiresAt = time.Now().AddDate(0, 0, p.ExpireDays).Unix()
		}
		p.present["expires_at"] = true
	}
	return nil
}

func applyUserPayload(rec *userRecord, p *UserPayload) {
	// An empty/omitted PBK does not rotate a pre-existing account.
	if p.PBK != "" {
		rec.PBK = p.PBK
	}
	if p.Enabled != nil {
		rec.Enabled = *p.Enabled
	}
	if p.present["total_limit"] {
		rec.TotalLimit = p.TotalLimit
	}
	if p.present["expires_at"] {
		rec.ExpiresAt = p.ExpiresAt
	}
	if p.present["ip_limit"] {
		rec.IPLimit = p.IPLimit
	}
	if p.present["note"] {
		rec.Note = p.Note
	}
}
