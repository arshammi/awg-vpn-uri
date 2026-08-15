package vpnuri

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

const sampleAWG3Conf = `[Interface]
PrivateKey = client-priv-key
Address = 10.66.66.2/32
DNS = 1.1.1.1
MTU = 1280
Jc = 4
Jmin = 35
Jmax = 95
S1 = 146
S2 = 48
S3 = 22
S4 = 26
H1 = 148736594-370455131
H2 = 621025620-1240228083
H3 = 1504827942-1530367889
H4 = 1629521638-1833671031
I1 = <r 128>
HeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
ContentPaddingAddition = 16-64
RekeyAfterTime = 120
RekeyTimeout = 5-8
RejectAfterTime = 180
KeepaliveTimeout = 10
MaxHandshakeAttempts = 15-20

[Peer]
PublicKey = server-pub-key
PresharedKey = psk-key
Endpoint = example.com:443
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

const sampleAWG2Conf = `[Interface]
PrivateKey = client-priv-key
Address = 10.66.66.2/32
DNS = 1.1.1.1
MTU = 1280
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
S3 = 16
S4 = 16
H1 = 100000-800000
H2 = 900000-1600000
H3 = 1700000-2400000
H4 = 2500000-3200000
I1 = <r 128>

[Peer]
PublicKey = server-pub-key
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

func decodeVpnURI(t *testing.T, uri string) map[string]any {
	t.Helper()
	if !strings.HasPrefix(uri, "vpn://") {
		t.Fatalf("missing vpn:// prefix: %q", uri[:min(20, len(uri))])
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "vpn://"))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(raw) < 5 {
		t.Fatalf("payload too short: %d", len(raw))
	}
	wantLen := binary.BigEndian.Uint32(raw[:4])
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		t.Fatalf("zlib: %v", err)
	}
	defer zr.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(zr); err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if uint32(buf.Len()) != wantLen {
		t.Fatalf("length header %d != decompressed %d", wantLen, buf.Len())
	}
	var outer map[string]any
	if err := json.Unmarshal(buf.Bytes(), &outer); err != nil {
		t.Fatalf("json: %v\n%s", err, buf.String())
	}
	return outer
}

func lastConfigFromOuter(t *testing.T, outer map[string]any) map[string]any {
	t.Helper()
	containers, ok := outer["containers"].([]any)
	if !ok || len(containers) == 0 {
		t.Fatal("missing containers")
	}
	c0, ok := containers[0].(map[string]any)
	if !ok {
		t.Fatal("bad container")
	}
	awgObj, ok := c0["awg"].(map[string]any)
	if !ok {
		t.Fatal("missing awg")
	}
	lastStr, ok := awgObj["last_config"].(string)
	if !ok || lastStr == "" {
		t.Fatal("missing last_config string")
	}
	var last map[string]any
	if err := json.Unmarshal([]byte(lastStr), &last); err != nil {
		t.Fatalf("last_config json: %v", err)
	}
	return last
}

func awgMeta(t *testing.T, outer map[string]any) map[string]any {
	t.Helper()
	containers := outer["containers"].([]any)
	c0 := containers[0].(map[string]any)
	return c0["awg"].(map[string]any)
}

func TestParseAndGenerateVpnURIAWG3(t *testing.T) {
	in, err := ParseClientConf(sampleAWG3Conf)
	if err != nil {
		t.Fatal(err)
	}
	in.Description = "peer1"

	uri, err := GenerateVpnURI(in)
	if err != nil {
		t.Fatal(err)
	}
	outer := decodeVpnURI(t, uri)
	meta := awgMeta(t, outer)
	if meta["protocol_version"] != "3" {
		t.Fatalf("protocol_version=%v want 3", meta["protocol_version"])
	}
	if meta["isThirdPartyConfig"] != true {
		t.Fatal("isThirdPartyConfig must be true")
	}
	if meta["port"] != "443" {
		t.Fatalf("outer port=%v want string 443", meta["port"])
	}
	last := lastConfigFromOuter(t, outer)
	if last["HeaderProtectionKey"] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Fatalf("HeaderProtectionKey=%v", last["HeaderProtectionKey"])
	}
	if last["ContentPaddingAddition"] != "16-64" {
		t.Fatalf("ContentPaddingAddition=%v", last["ContentPaddingAddition"])
	}
	if !strings.Contains(last["config"].(string), "HeaderProtectionKey") {
		t.Fatal("raw config must embed HeaderProtectionKey")
	}
	if last["client_priv_key"] != "client-priv-key" {
		t.Fatalf("client_priv_key=%v", last["client_priv_key"])
	}
	if last["server_pub_key"] != "server-pub-key" {
		t.Fatalf("server_pub_key=%v", last["server_pub_key"])
	}
	if port, ok := last["port"].(float64); !ok || int(port) != 443 {
		t.Fatalf("inner port=%v want 443", last["port"])
	}
}

func TestParseAndGenerateVpnURIAWG2(t *testing.T) {
	in, err := ParseClientConf(sampleAWG2Conf)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := GenerateVpnURI(in)
	if err != nil {
		t.Fatal(err)
	}
	outer := decodeVpnURI(t, uri)
	meta := awgMeta(t, outer)
	if meta["protocol_version"] != "2" {
		t.Fatalf("protocol_version=%v want 2", meta["protocol_version"])
	}
	last := lastConfigFromOuter(t, outer)
	if _, ok := last["HeaderProtectionKey"]; ok {
		t.Fatal("AWG2 payload must not include HeaderProtectionKey")
	}
}

func TestParseClientConfRequiresEndpoint(t *testing.T) {
	conf := `[Interface]
PrivateKey = client-priv
Address = 10.0.0.2/32

[Peer]
PublicKey = server-pub
AllowedIPs = 0.0.0.0/0
`
	if _, err := ParseClientConf(conf); err == nil {
		t.Fatal("expected error for missing Endpoint")
	}
}

func TestParseIPv6Endpoint(t *testing.T) {
	conf := `[Interface]
PrivateKey = client-priv
Address = 10.0.0.2/32

[Peer]
PublicKey = server-pub
Endpoint = [2001:db8::1]:51820
AllowedIPs = 0.0.0.0/0
`
	in, err := ParseClientConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if in.HostName != "2001:db8::1" || in.Port != 51820 {
		t.Fatalf("host=%q port=%d", in.HostName, in.Port)
	}
}
