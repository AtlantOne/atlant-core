package tlsprofiles

import (
	"atlant.local/protocol/tlsaudit"
	"crypto/tls"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	u "github.com/refraction-networking/utls"
	"net"
	"reflect"
	"testing"
)

//go:embed testdata/chrome144.json
var chrome144Reference []byte

func TestChrome144MatchesMeasuredBrowser(t *testing.T) {
	var reference tlsaudit.Summary
	if err := json.Unmarshal(chrome144Reference, &reference); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		spec, err := Chrome144Spec()
		if err != nil {
			t.Fatal(err)
		}
		client, peer := net.Pipe()
		connection := u.UClient(client, &u.Config{ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, u.HelloCustom)
		if err := connection.ApplyPreset(&spec); err != nil {
			t.Fatal(err)
		}
		if err := connection.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		if err := connection.MarshalClientHello(); err != nil {
			t.Fatal(err)
		}
		payload := connection.HandshakeState.Hello.Raw
		record := append([]byte{22, 3, 1, 0, 0}, payload...)
		binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
		summary, err := tlsaudit.Summarize(record)
		_ = client.Close()
		_ = peer.Close()
		if err != nil {
			t.Fatal(err)
		}
		if reference.StructuralKey() != summary.StructuralKey() || !reflect.DeepEqual(reference.CipherSuites, summary.CipherSuites) {
			t.Fatalf("profile differs from measured Chrome 144\nreference: %s\nactual: %s", reference.StructuralKey(), summary.StructuralKey())
		}
	}
}
