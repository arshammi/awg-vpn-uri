package vpnuri

import (
	"fmt"
	"strconv"
	"strings"
)

// VpnURIInput holds the fields needed to build an AmneziaVPN vpn:// link.
// Structured AWG 3.0 keys must be present so AmneziaVPN applies them —
// plain .conf import drops HeaderProtectionKey and related fields.
type VpnURIInput struct {
	Description string
	DNS1        string
	DNS2        string

	HostName string
	Port     int
	MTU      string

	ClientIP         string
	ClientPrivateKey string
	ServerPublicKey  string
	PresharedKey     string
	AllowedIPs       []string
	PersistentKA     string

	Jc, Jmin, Jmax         string
	S1, S2, S3, S4         string
	H1, H2, H3, H4         string
	I1, I2, I3, I4, I5     string
	HeaderProtectionKey    string
	ContentPaddingAddition string
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string

	// RawConf is the native AmneziaWG .conf embedded as "config".
	RawConf string
}

// ParseClientConf parses an AmneziaWG client .conf into VpnURIInput.
// Lines use Amnezia style "Key = value". Section headers are ignored.
func ParseClientConf(conf string) (*VpnURIInput, error) {
	conf = strings.TrimSpace(conf)
	if conf == "" {
		return nil, fmt.Errorf("empty config")
	}

	kv := map[string]string{}
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key != "" {
			kv[key] = val
		}
	}

	in := &VpnURIInput{RawConf: conf}
	in.ClientPrivateKey = kv["PrivateKey"]
	in.ServerPublicKey = kv["PublicKey"]
	in.PresharedKey = kv["PresharedKey"]
	in.MTU = kv["MTU"]
	in.PersistentKA = kv["PersistentKeepalive"]

	if addr := kv["Address"]; addr != "" {
		parts := splitCSV(addr)
		if len(parts) > 0 {
			in.ClientIP = parts[0]
		}
	}
	if dns := kv["DNS"]; dns != "" {
		parts := splitCSV(dns)
		if len(parts) > 0 {
			in.DNS1 = parts[0]
		}
		if len(parts) > 1 {
			in.DNS2 = parts[1]
		}
	}
	if aips := kv["AllowedIPs"]; aips != "" {
		in.AllowedIPs = splitCSV(aips)
	}
	if ep := kv["Endpoint"]; ep != "" {
		host, port, err := splitHostPort(ep)
		if err != nil {
			return nil, fmt.Errorf("Endpoint: %w", err)
		}
		in.HostName = host
		in.Port = port
	}

	in.Jc = kv["Jc"]
	in.Jmin = kv["Jmin"]
	in.Jmax = kv["Jmax"]
	in.S1 = kv["S1"]
	in.S2 = kv["S2"]
	in.S3 = kv["S3"]
	in.S4 = kv["S4"]
	in.H1 = kv["H1"]
	in.H2 = kv["H2"]
	in.H3 = kv["H3"]
	in.H4 = kv["H4"]
	in.I1 = kv["I1"]
	in.I2 = kv["I2"]
	in.I3 = kv["I3"]
	in.I4 = kv["I4"]
	in.I5 = kv["I5"]
	in.HeaderProtectionKey = kv["HeaderProtectionKey"]
	in.ContentPaddingAddition = kv["ContentPaddingAddition"]
	in.RekeyAfterTime = kv["RekeyAfterTime"]
	in.RekeyTimeout = kv["RekeyTimeout"]
	in.RejectAfterTime = kv["RejectAfterTime"]
	in.KeepaliveTimeout = kv["KeepaliveTimeout"]
	in.MaxHandshakeAttempts = kv["MaxHandshakeAttempts"]

	if in.ClientPrivateKey == "" || in.ServerPublicKey == "" {
		return nil, fmt.Errorf("config missing PrivateKey or PublicKey")
	}
	if in.HostName == "" || in.Port == 0 {
		return nil, fmt.Errorf("config missing Endpoint host:port")
	}
	if in.DNS1 == "" {
		in.DNS1 = "1.1.1.1"
	}
	if in.DNS2 == "" {
		in.DNS2 = "1.0.0.1"
	}
	if len(in.AllowedIPs) == 0 {
		in.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	if in.Description == "" {
		in.Description = "AmneziaWG"
	}
	return in, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitHostPort(endpoint string) (string, int, error) {
	endpoint = strings.TrimSpace(endpoint)
	if strings.HasPrefix(endpoint, "[") {
		closeIdx := strings.Index(endpoint, "]")
		if closeIdx < 0 {
			return "", 0, fmt.Errorf("invalid IPv6 endpoint")
		}
		host := endpoint[1:closeIdx]
		rest := endpoint[closeIdx+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("missing port")
		}
		port, err := strconv.Atoi(rest[1:])
		if err != nil || port <= 0 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port")
		}
		return host, port, nil
	}
	host, portStr, ok := strings.Cut(endpoint, ":")
	if !ok || host == "" || portStr == "" {
		return "", 0, fmt.Errorf("expected host:port")
	}
	if strings.Contains(host, ":") {
		return "", 0, fmt.Errorf("IPv6 endpoint must be [addr]:port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	return host, port, nil
}
