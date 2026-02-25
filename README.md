# ja3-probe

**TLS ClientHello Fingerprint Extractor — PoC for AitM Phishing Proxy Detection**

A proof-of-concept tool that demonstrates how JA3 TLS fingerprinting can identify headless browsers, automation frameworks, and reverse-proxy phishing infrastructure such as [Starkiller](https://abnormal.ai/blog/starkiller-phishing-kit), Evilginx, and EvilProxy.

## Why

Modern Adversary-in-the-Middle (AitM) phishing kits proxy legitimate login pages through headless Chrome instances running in Docker containers. While the proxied page is pixel-perfect, the TLS handshake carries a distinct fingerprint that differs from a real user's browser. This tool extracts and classifies those fingerprints.

## What It Does

- Parses raw TLS ClientHello bytes
- Extracts JA3 component fields (version, cipher suites, extensions, curves, point formats)
- Filters GREASE values per spec
- Computes the JA3 hash (MD5)
- Matches against a curated database of known fingerprints
- Falls back to heuristic classification for unknown fingerprints

## What It Doesn't Do

- Capture live traffic (use `tcpdump` / `tshark` and pipe in)
- Replace a production TLS inspection stack
- Handle TLS 1.3 encrypted extensions (JA4 addresses this)

## Usage

```bash
# Run against built-in test vectors
cargo run

# Analyze a hex-encoded ClientHello
cargo run -- --hex 160301...
```

### Capturing Real ClientHello Data

```bash
# Capture TLS handshakes
tcpdump -i eth0 -w capture.pcap 'tcp port 443'

# Extract ClientHello hex with tshark
tshark -r capture.pcap -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.extensions.supported_version
```

## Architecture

```
Raw bytes ──► TLS Record Parser ──► ClientHello Parser ──► JA3 Extractor
                                                                │
                                                          ┌─────▼─────┐
                                                          │ MD5 Hash  │
                                                          └─────┬─────┘
                                                                │
                                              ┌─────────────────▼─────────────────┐
                                              │    Fingerprint Database Lookup     │
                                              │  ┌────────────┬─────────────────┐ │
                                              │  │ Known Hash │  → Classification│ │
                                              │  │ Unknown    │  → Heuristics    │ │
                                              │  └────────────┴─────────────────┘ │
                                              └───────────────────────────────────┘
```

## Fingerprint Categories

| Category | Icon | Meaning |
|----------|------|---------|
| Real Browser | 🟢 | Standard desktop/mobile browser |
| Headless Browser | 🟡 | Potential AitM proxy (Puppeteer, Playwright, Docker Chrome) |
| Automation | 🔴 | Bot framework (Selenium, PhantomJS) |
| Proxy Infra | 🔴 | Known AitM tooling (Evilginx, Modlishka, Muraena) |
| CLI Tool | 🟡 | Context-dependent (curl, Python requests) |

## Zero Dependencies

The PoC is intentionally zero-dependency — it includes a minimal inline MD5 implementation to keep the build self-contained. For production use, swap in the `md5` crate and add `pcap` for live capture.

## Related Work

- [JA3 by Salesforce](https://github.com/salesforce/ja3) — Original JA3 specification
- [ja3er.com](https://ja3er.com) — JA3 fingerprint database
- [JA4+](https://github.com/FoxIO-LLC/ja4) — Next-generation TLS fingerprinting

## Part of the Sabbath Stones Ecosystem

This tool is part of RevEng3's security research toolkit. See also:
- [0tH (Zero the Hero)](https://zero-the-hero.run) — Mach-O parser
- [Aradia](https://aradia.zone) — Semantic WAF

## License

MIT — RevEng3 Ltd, 2026
