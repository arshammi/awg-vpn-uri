// Command awg-vpn-uri converts an AmneziaWG client .conf into an AmneziaVPN vpn:// link.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/arshammi/awg-vpn-uri/vpnuri"
)

const configsDir = "configs"

func main() {
	confPath := flag.String("f", "", "path to client .conf (use - for stdin; omit to batch-convert configs/)")
	outPath := flag.String("o", "", "optional output file for single-file mode (default: stdout)")
	desc := flag.String("d", "", "optional description override")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage:\n")
		fmt.Fprintf(os.Stderr, "  awg-vpn-uri                         # convert all configs/*.conf -> configs/*.txt\n")
		fmt.Fprintf(os.Stderr, "  awg-vpn-uri -f <client.conf|-> [-o out.txt] [-d description]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *confPath == "" {
		os.Exit(runBatch(configsDir, *desc))
	}

	var confBytes []byte
	var err error
	if *confPath == "-" {
		confBytes, err = io.ReadAll(os.Stdin)
	} else {
		confBytes, err = os.ReadFile(*confPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "read config:", err)
		os.Exit(1)
	}

	uri, err := confToURI(string(confBytes), *desc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(uri+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write output:", err)
			os.Exit(1)
		}
		return
	}
	fmt.Println(uri)
}

func confToURI(conf, desc string) (string, error) {
	in, err := vpnuri.ParseClientConf(conf)
	if err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	if desc != "" {
		in.Description = desc
	}
	uri, err := vpnuri.GenerateVpnURI(in)
	if err != nil {
		return "", fmt.Errorf("generate vpn://: %w", err)
	}
	return uri, nil
}

// runBatch converts every *.conf in dir into a sibling *.txt with the vpn:// link.
func runBatch(dir, desc string) int {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "create configs dir:", err)
		return 1
	}

	matches, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "list configs:", err)
		return 1
	}
	if len(matches) == 0 {
		fmt.Printf("no .conf files in %s/\n", dir)
		return 0
	}

	failed := 0
	for _, confFile := range matches {
		confBytes, err := os.ReadFile(confFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: read: %v\n", confFile, err)
			failed++
			continue
		}
		uri, err := confToURI(string(confBytes), desc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", confFile, err)
			failed++
			continue
		}
		base := strings.TrimSuffix(filepath.Base(confFile), ".conf")
		outFile := filepath.Join(dir, base+".txt")
		if err := os.WriteFile(outFile, []byte(uri+"\n"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "%s: write %s: %v\n", confFile, outFile, err)
			failed++
			continue
		}
		fmt.Printf("converted: %s -> %s\n", confFile, outFile)
	}
	if failed > 0 {
		return 1
	}
	return 0
}
