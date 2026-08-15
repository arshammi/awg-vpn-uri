# awg-vpn-uri

Convert an AmneziaWG client `.conf` into an AmneziaVPN `vpn://` link.

## Why

AmneziaVPN **5.0.0.5** drops AWG 3.0 fields (`HeaderProtectionKey`, `ContentPaddingAddition`, rekey/keepalive timers, etc.) when importing a raw `.conf` file. The import succeeds, but the tunnel never handshakes because the server still expects header protection.

Those same values work when carried as structured JSON fields inside a `vpn://` payload.

## Install

```bash
go build -o awg-vpn-uri .
# or
go install github.com/arshammi/awg-vpn-uri@latest
```

Requires Go 1.22+. Stdlib only.

## Quick workflow (recommended)

From the project root (this directory):

1. Drop client `.conf` files into [`configs/`](configs/).
2. Run the program with no arguments:

```bash
go build -o awg-vpn-uri .
./awg-vpn-uri
# Windows: .\awg-vpn-uri.exe
```

Each `configs/foo.conf` becomes `configs/foo.txt` containing the `vpn://…` link. Re-running regenerates all `.txt` files from the current `.conf` files.

Optional description for every file in the batch:

```bash
./awg-vpn-uri -d "phone"
```

## Single-file usage

```bash
# print vpn:// link
awg-vpn-uri -f client.conf

# read from stdin
awg-vpn-uri -f - < client.conf

# write to a file (mode 0600)
awg-vpn-uri -f client.conf -o link.txt

# set Amnezia profile description
awg-vpn-uri -f client.conf -d "phone"
```

Import the printed `vpn://…` string (or the contents of `configs/*.txt`) in AmneziaVPN — paste or QR of the **link**, not of the `.conf` text.

## QR codes

If you generate a QR code, encode the **`vpn://` string**. A QR of the raw `.conf` content has the same import bug as a file import.

## Security

Client configs contain private keys and may include a header-protection key. Do not paste them into untrusted web converters. Prefer running this CLI locally.

## License

MIT.
