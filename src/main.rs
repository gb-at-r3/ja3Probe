// ja3-probe — JA3 TLS ClientHello Fingerprint Extractor
// =====================================================
//
// A proof-of-concept tool that demonstrates how to extract JA3 fingerprints
// from TLS ClientHello messages to identify headless browsers, automation
// frameworks, and reverse-proxy phishing infrastructure (e.g., Starkiller,
// Evilginx, EvilProxy).
//
// CONTEXT
// -------
// Adversary-in-the-Middle (AitM) phishing kits like Starkiller use headless
// Chrome instances inside Docker containers to proxy legitimate login pages.
// While the proxied page looks pixel-perfect, the TLS handshake from the
// headless browser carries a distinct fingerprint that differs from a real
// user's browser. JA3 hashing captures this fingerprint.
//
// JA3 PRIMER
// ----------
// JA3 creates a fingerprint from the TLS ClientHello by concatenating:
//   1. TLS version
//   2. Cipher suites (sorted list)
//   3. Extensions (sorted list)
//   4. Elliptic curves (supported groups)
//   5. Elliptic curve point formats
//
// These fields are joined with commas, then MD5-hashed to produce a
// 32-character fingerprint. The same client software on the same OS
// will (generally) produce the same JA3 hash, regardless of the
// destination server.
//
// WHAT THIS PoC DOES
// ------------------
// - Parses raw TLS ClientHello bytes (from a capture or hex input)
// - Extracts all JA3 component fields
// - Computes the JA3 hash (MD5 of the canonical string)
// - Matches against a curated table of known fingerprints
// - Reports whether the client looks like a real browser, headless
//   browser, automation tool, or known proxy infrastructure
//
// WHAT THIS PoC DOES NOT DO
// -------------------------
// - Capture live traffic (use tcpdump/tshark and pipe in)
// - Replace a production TLS inspection stack
// - Handle TLS 1.3 encrypted extensions (by design, JA3 has limits here;
//   JA3S and JA4 address some of these — noted in the code)
//
// USAGE
//   cargo run                         # runs against built-in test vectors
//   cargo run -- --hex <hex_bytes>    # parse a hex-encoded ClientHello
//
// LICENSE: MIT — RevEng3 Ltd, 2026
// AUTHOR:  Gabriel Biondo

use std::env;
use std::fmt;

// ---------------------------------------------------------------------------
// TLS Constants
// ---------------------------------------------------------------------------

/// GREASE (Generate Random Extensions And Sustain Extensibility) values.
/// These are dummy values inserted by modern browsers to test server
/// tolerance. They MUST be filtered out of JA3 computation per spec.
const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(val: u16) -> bool {
    GREASE_VALUES.contains(&val)
}

// ---------------------------------------------------------------------------
// JA3 Fingerprint Components
// ---------------------------------------------------------------------------

/// Represents the extracted fields from a TLS ClientHello needed for JA3.
#[derive(Debug, Clone)]
struct Ja3Components {
    /// TLS version from the ClientHello (e.g., 0x0303 = TLS 1.2)
    tls_version: u16,
    /// Offered cipher suites, GREASE filtered
    cipher_suites: Vec<u16>,
    /// Extensions present, GREASE filtered
    extensions: Vec<u16>,
    /// Supported elliptic curves (from supported_groups extension)
    elliptic_curves: Vec<u16>,
    /// EC point formats (from ec_point_formats extension)
    point_formats: Vec<u8>,
}

impl Ja3Components {
    /// Build the canonical JA3 string:
    ///   version,ciphers,extensions,curves,point_formats
    /// where each list is dash-separated.
    fn to_ja3_string(&self) -> String {
        let version = self.tls_version.to_string();

        let ciphers = self
            .cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let extensions = self
            .extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let curves = self
            .elliptic_curves
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let points = self
            .point_formats
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("-");

        format!(
            "{},{},{},{},{}",
            version, ciphers, extensions, curves, points
        )
    }

    /// Compute the JA3 hash (MD5 of the canonical string).
    /// We use a minimal inline MD5 to keep this zero-dependency.
    fn to_ja3_hash(&self) -> String {
        let input = self.to_ja3_string();
        md5_hex(input.as_bytes())
    }
}

impl fmt::Display for Ja3Components {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "  TLS Version:    0x{:04x} ({})",
            self.tls_version,
            tls_version_name(self.tls_version)
        )?;
        writeln!(f, "  Cipher Suites:  {} entries", self.cipher_suites.len())?;
        for cs in &self.cipher_suites {
            writeln!(f, "    - 0x{:04x} ({})", cs, cipher_suite_name(*cs))?;
        }
        writeln!(f, "  Extensions:     {} entries", self.extensions.len())?;
        for ext in &self.extensions {
            writeln!(f, "    - 0x{:04x} ({})", ext, extension_name(*ext))?;
        }
        writeln!(f, "  Elliptic Curves: {:?}", self.elliptic_curves)?;
        writeln!(f, "  Point Formats:   {:?}", self.point_formats)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ClientHello Parser
// ---------------------------------------------------------------------------

/// Parse a TLS ClientHello from raw bytes.
///
/// Expected input: the ClientHello message starting from the TLS record
/// layer (content_type=0x16). This is what you'd capture from the wire.
///
/// Layout:
///   [0]       content_type (0x16 = Handshake)
///   [1..3]    TLS record version
///   [3..5]    record length
///   [5]       handshake_type (0x01 = ClientHello)
///   [6..9]    handshake length (3 bytes)
///   [9..11]   client_version  <-- this is what JA3 uses
///   [11..43]  random (32 bytes)
///   [43]      session_id_length
///   ...       session_id
///   ...       cipher_suites_length (2 bytes)
///   ...       cipher_suites
///   ...       compression_methods_length (1 byte)
///   ...       compression_methods
///   ...       extensions_length (2 bytes)
///   ...       extensions
fn parse_client_hello(data: &[u8]) -> Result<Ja3Components, String> {
    if data.len() < 6 {
        return Err("Data too short for TLS record".into());
    }

    // Validate content type
    if data[0] != 0x16 {
        return Err(format!(
            "Not a TLS Handshake record (got 0x{:02x})",
            data[0]
        ));
    }

    // Validate handshake type
    if data[5] != 0x01 {
        return Err(format!(
            "Not a ClientHello (handshake type 0x{:02x})",
            data[5]
        ));
    }

    let mut pos: usize = 9; // skip to client_version

    // --- TLS Version (what JA3 uses) ---
    if pos + 2 > data.len() {
        return Err("Truncated at TLS version".into());
    }
    let tls_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // --- Skip Random (32 bytes) ---
    pos += 32;

    // --- Session ID ---
    if pos >= data.len() {
        return Err("Truncated at session ID length".into());
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // --- Cipher Suites ---
    if pos + 2 > data.len() {
        return Err("Truncated at cipher suites length".into());
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + cs_len > data.len() {
        return Err("Truncated in cipher suites".into());
    }

    let mut cipher_suites = Vec::new();
    let cs_end = pos + cs_len;
    while pos + 1 < cs_end {
        let cs = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        // Filter GREASE values per JA3 spec
        if !is_grease(cs) {
            cipher_suites.push(cs);
        }
    }

    // --- Compression Methods ---
    if pos >= data.len() {
        return Err("Truncated at compression methods".into());
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    // --- Extensions ---
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut point_formats = Vec::new();

    if pos + 2 <= data.len() {
        let ext_total_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let ext_end = pos + ext_total_len;
        while pos + 4 <= ext_end && pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            // Filter GREASE extension types
            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }

            let ext_data_end = pos + ext_len;

            // Extension 0x000a = supported_groups (elliptic curves)
            if ext_type == 0x000a && ext_len >= 2 && ext_data_end <= data.len() {
                let list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                let mut curve_pos = pos + 2;
                let curve_end = pos + 2 + list_len;
                while curve_pos + 1 < curve_end && curve_pos + 1 < data.len() {
                    let curve = u16::from_be_bytes([data[curve_pos], data[curve_pos + 1]]);
                    curve_pos += 2;
                    if !is_grease(curve) {
                        elliptic_curves.push(curve);
                    }
                }
            }

            // Extension 0x000b = ec_point_formats
            if ext_type == 0x000b && ext_len >= 1 && ext_data_end <= data.len() {
                let fmt_len = data[pos] as usize;
                for i in 0..fmt_len {
                    if pos + 1 + i < data.len() {
                        point_formats.push(data[pos + 1 + i]);
                    }
                }
            }

            pos = ext_data_end;
        }
    }

    Ok(Ja3Components {
        tls_version,
        cipher_suites,
        extensions,
        elliptic_curves,
        point_formats,
    })
}

// ---------------------------------------------------------------------------
// Fingerprint Database
// ---------------------------------------------------------------------------

/// A known JA3 fingerprint with metadata about what it identifies.
struct KnownFingerprint {
    ja3_hash: &'static str,
    client: &'static str,
    category: ClientCategory,
    notes: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ClientCategory {
    /// Standard desktop/mobile browser — likely legitimate
    RealBrowser,
    /// Headless browser — potential AitM proxy infrastructure
    HeadlessBrowser,
    /// Automation framework — likely bot or scraper
    Automation,
    /// Known proxy/phishing infrastructure
    ProxyInfra,
    /// CLI tool or library — context-dependent
    CliTool,
}

impl fmt::Display for ClientCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientCategory::RealBrowser => write!(f, "REAL BROWSER"),
            ClientCategory::HeadlessBrowser => write!(f, "HEADLESS BROWSER"),
            ClientCategory::Automation => write!(f, "AUTOMATION"),
            ClientCategory::ProxyInfra => write!(f, "PROXY INFRA"),
            ClientCategory::CliTool => write!(f, "CLI TOOL"),
        }
    }
}

/// Curated database of known JA3 fingerprints.
///
/// NOTE: These are representative examples. In production, you would
/// maintain a continuously updated database fed by threat intelligence.
/// Sources include:
///   - https://ja3er.com
///   - https://github.com/salesforce/ja3
///   - Infoblox, Lab539 AitM feeds
///   - Your own Aradia telemetry
///
/// JA3 hashes can vary across OS, browser version, and TLS library version.
/// These are known-good examples as of early 2026.
fn known_fingerprints() -> Vec<KnownFingerprint> {
    vec![
        // --- Real Browsers ---
        KnownFingerprint {
            ja3_hash: "b32309a26951912be7dba376398abc3b",
            client: "Chrome 120+ (Windows)",
            category: ClientCategory::RealBrowser,
            notes: "Standard Chrome on Windows with full extension set",
        },
        KnownFingerprint {
            ja3_hash: "cd08e31494f9531f560d64c695473da9",
            client: "Firefox 121+ (Windows)",
            category: ClientCategory::RealBrowser,
            notes: "Standard Firefox with default config",
        },
        KnownFingerprint {
            ja3_hash: "773906b0efdefa24a7f2b8eb6985bf37",
            client: "Safari 17+ (macOS)",
            category: ClientCategory::RealBrowser,
            notes: "Safari on macOS Sonoma+",
        },
        // --- Headless Browsers (AitM indicators) ---
        KnownFingerprint {
            ja3_hash: "a0e9f5d64349fb13191bc781f81f42e1",
            client: "Headless Chrome (Puppeteer)",
            category: ClientCategory::HeadlessBrowser,
            notes: "Puppeteer default config — missing extensions present in real Chrome",
        },
        KnownFingerprint {
            ja3_hash: "e7d705a3286e19ea42f587b344ee6865",
            client: "Headless Chrome (Docker)",
            category: ClientCategory::HeadlessBrowser,
            notes: "Chrome --headless in Docker — Starkiller-style infra",
        },
        KnownFingerprint {
            ja3_hash: "535aca3d99fc247509cd50933cd71d37",
            client: "Headless Chrome (Playwright)",
            category: ClientCategory::HeadlessBrowser,
            notes: "Playwright Chromium — common in scraping and proxy infra",
        },
        // --- Automation ---
        KnownFingerprint {
            ja3_hash: "e35f1dea0c3b98c0c35e05faa0ba8f92",
            client: "Selenium WebDriver",
            category: ClientCategory::Automation,
            notes: "Selenium with default ChromeDriver",
        },
        KnownFingerprint {
            ja3_hash: "9e10692f1b7f78228b2d4e424db3a98c",
            client: "PhantomJS",
            category: ClientCategory::Automation,
            notes: "Legacy but still seen in older phishing kits",
        },
        // --- Proxy Infrastructure ---
        KnownFingerprint {
            ja3_hash: "4d7a28d6f2263ed61de88ca66eb011e3",
            client: "Evilginx2/3",
            category: ClientCategory::ProxyInfra,
            notes: "Go net/http default — Evilginx reverse proxy signature",
        },
        KnownFingerprint {
            ja3_hash: "19e29534fd49dd27d09234e639c4057e",
            client: "Modlishka",
            category: ClientCategory::ProxyInfra,
            notes: "Go-based AitM proxy",
        },
        KnownFingerprint {
            ja3_hash: "3b5074b1b5d032e5620f69f9f700ff0e",
            client: "Muraena",
            category: ClientCategory::ProxyInfra,
            notes: "Go-based AitM framework",
        },
        // --- CLI Tools ---
        KnownFingerprint {
            ja3_hash: "3e5b4b524b1c214e5cc7286a6a400236",
            client: "curl / libcurl",
            category: ClientCategory::CliTool,
            notes: "curl with OpenSSL — common in legitimate and malicious use",
        },
        KnownFingerprint {
            ja3_hash: "36f7277af969a6947a61ae0b815907a1",
            client: "Python requests",
            category: ClientCategory::CliTool,
            notes: "Python urllib3/requests — credential stuffing or legit scripting",
        },
    ]
}

/// Look up a JA3 hash against the known fingerprint database.
fn lookup_fingerprint(hash: &str) -> Option<&'static KnownFingerprint> {
    // This is a linear scan — fine for a PoC.
    // Production: use a HashMap or a trie for O(1) lookup.
    //
    // SAFETY: we leak the Vec to get 'static references.
    // In a real tool, you'd use lazy_static or once_cell.
    let db: &'static Vec<KnownFingerprint> = {
        let db = known_fingerprints();
        Box::leak(Box::new(db))
    };

    db.iter().find(|fp| fp.ja3_hash == hash)
}

/// Classify an unknown fingerprint heuristically.
/// Even if we don't have an exact match, certain JA3 string patterns
/// are indicative of non-browser clients.
fn heuristic_classify(components: &Ja3Components) -> &'static str {
    // Very few cipher suites → likely a minimal TLS library (Go, curl)
    if components.cipher_suites.len() < 5 {
        return "Low cipher suite count — possibly Go stdlib, curl, or custom TLS client";
    }

    // No ec_point_formats extension → unusual for real browsers
    if components.point_formats.is_empty() {
        return "Missing EC point formats — atypical for standard browsers";
    }

    // Very few extensions → headless or stripped browser
    if components.extensions.len() < 8 {
        return "Low extension count — possible headless browser or automation tool";
    }

    // TLS 1.0/1.1 → ancient client or intentional downgrade
    if components.tls_version < 0x0303 {
        return "Pre-TLS 1.2 — legacy client or deliberate downgrade";
    }

    "Fingerprint profile consistent with a standard browser"
}

// ---------------------------------------------------------------------------
// Test Vectors
// ---------------------------------------------------------------------------

/// Synthesize a realistic TLS ClientHello for demonstration.
/// This builds a valid ClientHello that mimics a headless Chrome instance
/// (the kind Starkiller would use).
fn build_test_client_hello_headless_chrome() -> Vec<u8> {
    let mut hello = Vec::new();

    // --- TLS Record Layer ---
    hello.push(0x16); // content_type: Handshake
    hello.extend_from_slice(&[0x03, 0x01]); // record version: TLS 1.0 (compat)

    // Placeholder for record length — we'll fill this in at the end
    let record_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]);

    // --- Handshake Header ---
    hello.push(0x01); // handshake_type: ClientHello
                      // Placeholder for handshake length (3 bytes)
    let hs_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    // --- ClientHello Body ---
    // client_version: TLS 1.2 (real version negotiated via supported_versions ext)
    hello.extend_from_slice(&[0x03, 0x03]);

    // random: 32 bytes of fake randomness
    hello.extend_from_slice(&[0x42; 32]);

    // session_id: empty
    hello.push(0x00);

    // --- Cipher Suites ---
    // Headless Chrome typically offers fewer cipher suites than real Chrome.
    // This is a simplified set that mimics a headless instance.
    let cipher_suites: Vec<u16> = vec![
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    ];
    let cs_bytes: Vec<u8> = cipher_suites
        .iter()
        .flat_map(|cs| cs.to_be_bytes())
        .collect();
    hello.extend_from_slice(&(cs_bytes.len() as u16).to_be_bytes());
    hello.extend_from_slice(&cs_bytes);

    // --- Compression Methods ---
    hello.push(0x01); // length
    hello.push(0x00); // null compression

    // --- Extensions ---
    let mut ext_buf = Vec::new();

    // supported_groups (0x000a) — curves offered
    let curves: Vec<u16> = vec![0x001d, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
    let curves_bytes: Vec<u8> = curves.iter().flat_map(|c| c.to_be_bytes()).collect();
    ext_buf.extend_from_slice(&0x000au16.to_be_bytes());
    ext_buf.extend_from_slice(&((curves_bytes.len() + 2) as u16).to_be_bytes());
    ext_buf.extend_from_slice(&(curves_bytes.len() as u16).to_be_bytes());
    ext_buf.extend_from_slice(&curves_bytes);

    // ec_point_formats (0x000b)
    ext_buf.extend_from_slice(&0x000bu16.to_be_bytes());
    ext_buf.extend_from_slice(&0x0002u16.to_be_bytes()); // ext length
    ext_buf.push(0x01); // formats length
    ext_buf.push(0x00); // uncompressed

    // server_name (0x0000) — SNI
    ext_buf.extend_from_slice(&0x0000u16.to_be_bytes());
    ext_buf.extend_from_slice(&0x0000u16.to_be_bytes()); // empty for this demo

    // signature_algorithms (0x000d)
    ext_buf.extend_from_slice(&0x000du16.to_be_bytes());
    ext_buf.extend_from_slice(&0x0000u16.to_be_bytes());

    // supported_versions (0x002b)
    ext_buf.extend_from_slice(&0x002bu16.to_be_bytes());
    ext_buf.extend_from_slice(&0x0000u16.to_be_bytes());

    // Total extensions length
    hello.extend_from_slice(&(ext_buf.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ext_buf);

    // --- Patch lengths ---
    let record_len = (hello.len() - 5) as u16;
    hello[record_len_pos] = (record_len >> 8) as u8;
    hello[record_len_pos + 1] = (record_len & 0xff) as u8;

    let hs_len = (hello.len() - hs_len_pos - 3) as u32;
    hello[hs_len_pos] = ((hs_len >> 16) & 0xff) as u8;
    hello[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
    hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

    hello
}

/// Build a second test vector: a Go net/http client (Evilginx-style)
fn build_test_client_hello_go_stdlib() -> Vec<u8> {
    let mut hello = Vec::new();

    hello.push(0x16);
    hello.extend_from_slice(&[0x03, 0x01]);
    let record_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]);

    hello.push(0x01);
    let hs_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    // TLS 1.2
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x37; 32]); // random

    hello.push(0x00); // no session ID

    // Go stdlib cipher suites — notably different from browsers
    let cipher_suites: Vec<u16> = vec![
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02c, // ECDHE_ECDSA_AES_256_GCM
        0xc02b, // ECDHE_ECDSA_AES_128_GCM
        0xc030, // ECDHE_RSA_AES_256_GCM
        0xc02f, // ECDHE_RSA_AES_128_GCM
    ];
    let cs_bytes: Vec<u8> = cipher_suites
        .iter()
        .flat_map(|cs| cs.to_be_bytes())
        .collect();
    hello.extend_from_slice(&(cs_bytes.len() as u16).to_be_bytes());
    hello.extend_from_slice(&cs_bytes);

    hello.push(0x01);
    hello.push(0x00);

    // Go has a minimal extension set — key differentiator
    let mut ext_buf = Vec::new();

    // supported_groups — Go only offers 3 curves
    let curves: Vec<u16> = vec![0x001d, 0x0017, 0x0018];
    let curves_bytes: Vec<u8> = curves.iter().flat_map(|c| c.to_be_bytes()).collect();
    ext_buf.extend_from_slice(&0x000au16.to_be_bytes());
    ext_buf.extend_from_slice(&((curves_bytes.len() + 2) as u16).to_be_bytes());
    ext_buf.extend_from_slice(&(curves_bytes.len() as u16).to_be_bytes());
    ext_buf.extend_from_slice(&curves_bytes);

    // ec_point_formats
    ext_buf.extend_from_slice(&0x000bu16.to_be_bytes());
    ext_buf.extend_from_slice(&0x0002u16.to_be_bytes());
    ext_buf.push(0x01);
    ext_buf.push(0x00);

    hello.extend_from_slice(&(ext_buf.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ext_buf);

    // Patch lengths
    let record_len = (hello.len() - 5) as u16;
    hello[record_len_pos] = (record_len >> 8) as u8;
    hello[record_len_pos + 1] = (record_len & 0xff) as u8;

    let hs_len = (hello.len() - hs_len_pos - 3) as u32;
    hello[hs_len_pos] = ((hs_len >> 16) & 0xff) as u8;
    hello[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
    hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

    hello
}

// ---------------------------------------------------------------------------
// Minimal MD5 (zero dependencies)
// ---------------------------------------------------------------------------

/// Minimal MD5 implementation. In production, use the `md5` crate.
/// Included here to keep the PoC zero-dependency.
fn md5_hex(input: &[u8]) -> String {
    // Initial hash values
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Per-round shift amounts
    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    // Precomputed constants (floor(2^32 * abs(sin(i+1))))
    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    // Padding
    let orig_len_bits = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    // Process 512-bit blocks
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(m[g])).rotate_left(s[i]),
            );
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}",
        a0.to_le(),
        b0.to_le(),
        c0.to_le(),
        d0.to_le()
    )
}

// ---------------------------------------------------------------------------
// Name Lookups (for pretty printing)
// ---------------------------------------------------------------------------

fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

fn cipher_suite_name(cs: u16) -> &'static str {
    match cs {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "ECDHE_ECDSA_AES_128_GCM_SHA256",
        0xc02c => "ECDHE_ECDSA_AES_256_GCM_SHA384",
        0xc02f => "ECDHE_RSA_AES_128_GCM_SHA256",
        0xc030 => "ECDHE_RSA_AES_256_GCM_SHA384",
        0x009e => "DHE_RSA_AES_128_GCM_SHA256",
        0x009f => "DHE_RSA_AES_256_GCM_SHA384",
        0xc013 => "ECDHE_RSA_AES_128_SHA",
        0xc014 => "ECDHE_RSA_AES_256_SHA",
        _ => "Unknown",
    }
}

fn extension_name(ext: u16) -> &'static str {
    match ext {
        0x0000 => "server_name",
        0x0001 => "max_fragment_length",
        0x0005 => "status_request",
        0x000a => "supported_groups",
        0x000b => "ec_point_formats",
        0x000d => "signature_algorithms",
        0x0010 => "ALPN",
        0x0012 => "signed_certificate_timestamp",
        0x0017 => "extended_master_secret",
        0x001c => "record_size_limit",
        0x002b => "supported_versions",
        0x002d => "psk_key_exchange_modes",
        0x0033 => "key_share",
        0xff01 => "renegotiation_info",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Hex Decoding
// ---------------------------------------------------------------------------

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.replace(" ", "").replace(":", "").replace("\n", "");
    if hex.len() % 2 != 0 {
        return Err("Hex string has odd length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  ja3-probe — TLS ClientHello Fingerprint Extractor         ║");
    println!("║  PoC for AitM Phishing Proxy Detection                     ║");
    println!("║  RevEng3 Ltd — 2026                                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    if args.len() >= 3 && args[1] == "--hex" {
        // Parse user-provided hex bytes
        let hex_input = args[2..].join("");
        match decode_hex(&hex_input) {
            Ok(data) => analyze_client_hello(&data, "User-provided ClientHello"),
            Err(e) => eprintln!("Error decoding hex: {}", e),
        }
    } else {
        // Run built-in test vectors
        println!("Running against built-in test vectors...");
        println!("(Use --hex <bytes> to analyze captured ClientHello data)");
        println!();

        // Test 1: Headless Chrome (Starkiller-style)
        let headless = build_test_client_hello_headless_chrome();
        analyze_client_hello(
            &headless,
            "Test Vector 1: Headless Chrome (Starkiller-style Docker)",
        );

        println!();
        println!("{}", "─".repeat(64));
        println!();

        // Test 2: Go stdlib (Evilginx-style)
        let go_client = build_test_client_hello_go_stdlib();
        analyze_client_hello(
            &go_client,
            "Test Vector 2: Go net/http (Evilginx-style proxy)",
        );

        println!();
        println!("{}", "─".repeat(64));
        println!();
        println!("OPERATIONAL NOTES:");
        println!("  • In production, capture ClientHello with: tcpdump -w capture.pcap");
        println!("  • Extract hex: tshark -r capture.pcap -Y 'tls.handshake.type==1' -T fields -e tls.record.content_type -e tls.handshake.type");
        println!("  • Or integrate this parser into your TLS termination layer");
        println!("  • Feed results into Aradia for semantic correlation with other signals");
        println!();
    }
}

fn analyze_client_hello(data: &[u8], label: &str) {
    println!("┌─ {} ─┐", label);
    println!("│  Input: {} bytes", data.len());
    println!();

    match parse_client_hello(data) {
        Ok(components) => {
            println!("  Parsed Components:");
            print!("{}", components);
            println!();

            let ja3_string = components.to_ja3_string();
            let ja3_hash = components.to_ja3_hash();

            println!("  JA3 String: {}", ja3_string);
            println!("  JA3 Hash:   {}", ja3_hash);
            println!();

            // Database lookup
            match lookup_fingerprint(&ja3_hash) {
                Some(fp) => {
                    println!("  ╔══ MATCH FOUND ══╗");
                    println!("  ║ Client:   {}", fp.client);
                    println!("  ║ Category: {}", fp.category);
                    println!("  ║ Notes:    {}", fp.notes);
                    println!("  ╚═════════════════╝");

                    if fp.category != ClientCategory::RealBrowser {
                        println!();
                        println!("  ⚡ ACTION: This fingerprint suggests non-browser traffic.");
                        println!(
                            "     Consider: rate limiting, additional verification, or blocking."
                        );
                    }
                }
                None => {
                    println!("  ╔══ NO EXACT MATCH ══╗");
                    println!("  ║ Hash not in database");
                    println!("  ╚════════════════════╝");
                    println!();
                    println!("  Heuristic Analysis:");
                    println!("  {}", heuristic_classify(&components));
                }
            }
        }
        Err(e) => {
            println!("  ✗ Parse error: {}", e);
        }
    }
}
