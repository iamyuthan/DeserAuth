<p align="center">
  <h1 align="center">DeserAuth</h1>
  <p align="center"><strong>Deserialization Authorization Analyzer</strong></p>
  <p align="center">
    A Burp Suite extension for automated authorization testing in Java serialized communication
  </p>
</p>

<p align="center">
  <a href="https://github.com/iamyuthan/DeserAuth/releases"><img src="https://img.shields.io/github/v/release/iamyuthan/DeserAuth?style=flat-square" alt="Release"></a>
  <a href="https://github.com/iamyuthan/DeserAuth/blob/main/LICENSE"><img src="https://img.shields.io/github/license/iamyuthan/DeserAuth?style=flat-square" alt="License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-2.7%20(Jython)-blue?style=flat-square" alt="Python"></a>
  <a href="https://portswigger.net/burp"><img src="https://img.shields.io/badge/Burp%20Suite-Extension-orange?style=flat-square" alt="Burp"></a>
</p>

---

## Overview

**DeserAuth** is a Burp Suite extension purpose-built for testing **authorization and access control** in applications that communicate using **Java serialized objects** — such as Spring HTTP Invoker, RMI over HTTP, WebLogic T3, and custom binary protocols.

Many enterprise Java thick-client applications embed user identity (USERID, account numbers, session tokens) directly inside serialized request bodies. Traditional Burp tools like Auth Analyzer don't understand binary serialization formats. **DeserAuth bridges that gap.**

### The Problem It Solves
| Traditional Web App: | Thick Client Java App: |
|----------------------|------------------------|
| GET /api/user/123 | POST /app/service.action |
| Cookie: session=abc | Content-Type: application/x-java-serialized-object |
|  | Body: AC ED 00 05 [binary blob with USERID inside] |
| Other Extenders works | Other Extenders fails |
| DeserAuth works | DeserAuth works |


---

## Features

### Passive Automatic Analysis
- Intercepts all matching requests across selected Burp tools
- Automatically replays with modified serialized values
- Compares original vs modified responses
- Color-codes results: 🟢 SAME | 🟡 SIMILAR | 🔴 DIFFERENT

###️ Manual Right-Click Actions
- **Send to Repeater (Same Length)** — fast direct replacement
- **Send to Repeater (Any Length)** — patches length prefixes automatically
- **Send to Repeater (Batch)** — comma-separated payloads, one tab per payload
- **Send to Repeater using Saved Rule** — apply pre-configured rules instantly

### Smart Serialization Handling
- **Java `char[]` buffers** — overwrites null-padding or expands buffer + patches array size
- **TC_STRING format** — auto-patches 2-byte length prefix
- **UTF-16BE encoding** — handles Java's internal string representation
- **ASCII strings** — catches method names and plain-text fields

### Results & Reporting
- Sortable results table (click column headers)
- Side-by-side Original vs Modified request/response viewers
- Export to **CSV**, **HTML**, **XML**, **Excel**
- Configurable field selection for exports
- Diff percentage calculation

### Full Scope Coverage
Works across all Burp tools:
- Proxy | Repeater | Intruder | Scanner | Sequencer | Spider | Extender | Target

---

## Installation

### Prerequisites

| Requirement | Details |
|-------------|---------|
| Burp Suite | Professional or Community Edition |
| Jython | Standalone JAR (2.7.x) — [Download](https://www.jython.org/download) |

### Steps

1. **Download** [`deserauth.py`](https://github.com/iamyuthan/DeserAuth/releases)

2. **Configure Jython** in Burp:

```
Extender → Options → Python Environment → Jython standalone JAR path
```


3. **Load the extension**:

```
Extender → Add → Extension Type: Python → Select deserauth.py
```


4. A new **"DeserAuth"** tab appears in Burp.

---

## Usage Guide

### Passive Mode (Automatic Authorization Testing)

1. **Add Swap Rules** in the DeserAuth tab:
- Search: `User1` (your user ID)
- Replace: `User2` (target user ID)
- Mode: Any Length

2. **Select Scope** — choose which Burp tools to monitor

3. **Click START**

4. **Use the application normally** — browse, click, perform actions

5. **Watch the results table** — DIFFERENT entries indicate potential authorization bypass

6. **Click any row** to inspect the full original vs modified request/response

### Manual Mode (On-Demand Testing)

Right-click any request anywhere in Burp:

```
Right-click → DeserAuth → Send to Repeater (Same Length)
Right-click → DeserAuth → Send to Repeater (Any Length)
Right-click → DeserAuth → Send to Repeater (Batch)
Right-click → DeserAuth → Send to Repeater using Saved Rule → [rule]
```


### Export Results

Click **Export...** → Select fields → Choose format → Save

---

## Use Cases

### 1. USERID Impersonation

```
Search:  User1  (your user)
Replace: Admin1  (other user)
```

Tests if the server trusts client-supplied identity.

### 2. IDOR via Account Numbers

```
Search:  ID00001  (your account)
Replace: ID00002  (another account)
```

Tests if you can access other users' data.

### 3. Privilege Escalation

```
Search:  ROLE_USER
Replace: ROLE_ADMIN
```

Tests if role identifiers in serialized objects are validated server-side.

### 4. Method Name Tampering

```
Search:  getUserProfile
Replace: getAdminPanel
```

Tests if the remote interface exposes unauthorized methods.

### 5. Injection Testing

```
Search:  normalValue
Replace: alert(1)
```

Tests if deserialized values reach sinks without sanitization.

---

## How It Works

### Architecture

┌──────────────────────────────────────────────────────────┐
│                  DeserAuth Extension                     │
├──────────────────────────┬───────────────────────────────┤
│   IHttpListener          │   IContextMenuFactory         │
│   (Passive Mode)         │   (Manual Mode)               │
│                          │                               │
│   Intercepts responses   │   Right-click actions         │
│   from selected tools    │   Send to Repeater            │
│   → Apply swap rules     │   → Same/Any/Batch/Saved      │
│   → Replay modified      │                               │
│   → Compare responses    │                               │
│   → Log results          │                               │
├──────────────────────────┴───────────────────────────────┤
│                    Swap Engine                           │
│                                                          │
│   1. UTF-16BE char[] replacement (with null-padding)     │
│   2. Array size prefix patching (4-byte big-endian int)  │
│   3. TC_STRING length prefix patching (2-byte)           │
│   4. ASCII fallback replacement                          │
└──────────────────────────────────────────────────────────┘


### Serialized String Storage in Java

Standard TC_STRING:
┌──────┬──────────┬─────────────────┐
│ 0x74 │ 2-byte   │ UTF-8 string    │
│      │ length   │ bytes           │
└──────┴──────────┴─────────────────┘

char[] Array (StringBuilder internal):
┌────────────┬──────┬──────┬──────┬──────┬──────┬──────┐
│ 4-byte     │ \x00 │ \x00 │ \x00 │ \x00 │ \x00 │ \x00 │
│ array size │  L   │  1   │  7   │  3   │ \x00 │ \x00 │ ← null padding
└────────────┴──────┴──────┴──────┴──────┴──────┴──────┘
↑ UTF-16BE chars ↑     ↑ available space ↑


DeserAuth handles both formats automatically.

---

## Configuration Tips

### Same Length vs Any Length

| Mode | When to Use | How It Works |
|------|-------------|--------------|
| Same Length | IDs, codes, values of equal character count | Direct byte-for-byte replacement |
| Any Length | Payloads, longer/shorter values, injection strings | Patches length prefixes and expands/contracts buffers |

### Performance Considerations

- **Disable Repeater scope** during passive analysis to avoid processing your own replayed requests
- DeserAuth automatically skips its own generated requests (tagged with `SSA-` comment)
- Use specific search strings to minimize false matches

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Extension won't load | Ensure Jython standalone JAR is set in Extender → Options |
| `ZipException: zip END header not found` | You selected "Java" extension type — change to "Python" |
| `NameError: global name 'X' is not defined` | Missing import — check Jython console output |
| No entries appearing in table | Verify: rules have search values, scope is correct, START is clicked |
| Export fails with encoding error | Fixed in v1.2 — binary bodies are sanitized before export |

---

## Changelog

### v1.2 (Current)
- Added right-click context menu with Same/Any/Batch modes
- Added "Send to Repeater using Saved Rule" for instant rule application
- Added full export support (CSV, HTML, XML, Excel)
- Added column sorting
- Added Diff % column
- Binary-safe export with `_safe_str()` sanitization
- All Burp tool scopes supported

### v1.1
- Added context menu support (IContextMenuFactory)
- Added manual Send-to-Repeater actions

### v1.0
- Initial release
- Passive authorization analysis
- Same-length and any-length swap engine
- Color-coded results table
- Request/response comparison viewers

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Author

**Yuthan Balaji K**

- GitHub: [@iamyuthan](https://github.com/iamyuthan)
- Repository: [DeserAuth](https://github.com/iamyuthan/DeserAuth)

---

If this tool helps you find authorization bugs, please consider giving it a ⭐!

---

<p align="center">
  <sub>Built with ☕ for the offensive security community</sub>
</p>
