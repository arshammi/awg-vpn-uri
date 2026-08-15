package vpnuri

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// GenerateVpnURI builds an Amnezia-compatible vpn:// URI from structured input.
func GenerateVpnURI(in *VpnURIInput) (string, error) {
	if in == nil {
		return "", fmt.Errorf("nil input")
	}
	if in.RawConf == "" {
		return "", fmt.Errorf("empty raw config")
	}
	if in.HostName == "" || in.Port == 0 {
		return "", fmt.Errorf("missing endpoint host/port")
	}

	dns1 := in.DNS1
	if dns1 == "" {
		dns1 = "1.1.1.1"
	}
	dns2 := in.DNS2
	if dns2 == "" {
		dns2 = "1.0.0.1"
	}
	desc := in.Description
	if desc == "" {
		desc = "AmneziaWG"
	}
	allowed := in.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}

	client := map[string]any{}
	putStr(client, "config", in.RawConf)
	putStr(client, "hostName", in.HostName)
	client["port"] = in.Port
	putStr(client, "client_ip", in.ClientIP)
	putStr(client, "client_priv_key", in.ClientPrivateKey)
	putStr(client, "server_pub_key", in.ServerPublicKey)
	putStr(client, "psk_key", in.PresharedKey)
	putStr(client, "mtu", in.MTU)
	putStr(client, "persistent_keep_alive", in.PersistentKA)
	client["allowed_ips"] = allowed

	putStr(client, "Jc", in.Jc)
	putStr(client, "Jmin", in.Jmin)
	putStr(client, "Jmax", in.Jmax)
	putStr(client, "S1", in.S1)
	putStr(client, "S2", in.S2)
	putStr(client, "S3", in.S3)
	putStr(client, "S4", in.S4)
	putStr(client, "H1", in.H1)
	putStr(client, "H2", in.H2)
	putStr(client, "H3", in.H3)
	putStr(client, "H4", in.H4)
	putStr(client, "I1", in.I1)
	putStr(client, "I2", in.I2)
	putStr(client, "I3", in.I3)
	putStr(client, "I4", in.I4)
	putStr(client, "I5", in.I5)
	putStr(client, "HeaderProtectionKey", in.HeaderProtectionKey)
	putStr(client, "ContentPaddingAddition", in.ContentPaddingAddition)
	putStr(client, "RekeyAfterTime", in.RekeyAfterTime)
	putStr(client, "RekeyTimeout", in.RekeyTimeout)
	putStr(client, "RejectAfterTime", in.RejectAfterTime)
	putStr(client, "KeepaliveTimeout", in.KeepaliveTimeout)
	putStr(client, "MaxHandshakeAttempts", in.MaxHandshakeAttempts)

	lastConfigBytes, err := json.Marshal(client)
	if err != nil {
		return "", fmt.Errorf("marshal last_config: %w", err)
	}

	awgObj := map[string]any{
		"isThirdPartyConfig": true,
		"last_config":        string(lastConfigBytes),
		"port":               strconv.Itoa(in.Port),
		"transport_proto":    "udp",
	}
	if pv := protocolVersion(in); pv != "" {
		awgObj["protocol_version"] = pv
	}

	outer := map[string]any{
		"containers": []any{
			map[string]any{
				"awg":       awgObj,
				"container": "amnezia-awg",
			},
		},
		"defaultContainer": "amnezia-awg",
		"description":      desc,
		"dns1":             dns1,
		"dns2":             dns2,
		"hostName":         in.HostName,
	}

	jsonBytes, err := json.Marshal(outer)
	if err != nil {
		return "", fmt.Errorf("marshal vpn payload: %w", err)
	}

	var zbuf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&zbuf, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(jsonBytes); err != nil {
		_ = zw.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}

	payload := make([]byte, 4+zbuf.Len())
	binary.BigEndian.PutUint32(payload[:4], uint32(len(jsonBytes)))
	copy(payload[4:], zbuf.Bytes())

	return "vpn://" + base64.RawURLEncoding.EncodeToString(payload), nil
}

func protocolVersion(in *VpnURIInput) string {
	if hasAWG3(in) {
		return "3"
	}
	if hasAWG2(in) {
		return "2"
	}
	return ""
}

func hasAWG3(in *VpnURIInput) bool {
	return strings.TrimSpace(in.HeaderProtectionKey) != "" ||
		strings.TrimSpace(in.ContentPaddingAddition) != "" ||
		strings.TrimSpace(in.RekeyAfterTime) != "" ||
		strings.TrimSpace(in.RekeyTimeout) != "" ||
		strings.TrimSpace(in.RejectAfterTime) != "" ||
		strings.TrimSpace(in.KeepaliveTimeout) != "" ||
		strings.TrimSpace(in.MaxHandshakeAttempts) != ""
}

func hasAWG2(in *VpnURIInput) bool {
	if atoiPositive(in.S3) || atoiPositive(in.S4) {
		return true
	}
	for _, h := range []string{in.H1, in.H2, in.H3, in.H4} {
		if strings.Contains(h, "-") {
			return true
		}
	}
	return strings.TrimSpace(in.I1) != ""
}

func atoiPositive(s string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return err == nil && n > 0
}

func putStr(m map[string]any, key, val string) {
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	m[key] = val
}
