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

**DeserAuth** is a Burp Suite extension purpose-built for testing **authorization and access control** in applications that communicate using **Java serialized objects**, such as Spring HTTP Invoker, RMI over HTTP, WebLogic T3, and custom binary protocols.

<img width="1913" height="938" alt="image" src="https://github.com/user-attachments/assets/9f3a1468-64f9-407a-ae83-9ac86e16e29a" />


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

## What's New in v2.0

### Deserialized Message Editor Tab

<!-- TODO: Add screenshot of the Deserialized tab showing parsed Java objects -->

DeserAuth now adds a **"Deserialized"** tab alongside Pretty/Raw/Hex in Burp's message editors - just like how the JWT extension decodes JSON Web Tokens, DeserAuth decodes Java serialized objects into a **human-readable, editable** view.

- **Automatic detection** - tab appears whenever a request or response contains Java serialized data (`Content-Type: application/x-java-serialized-object` or `AC ED 00 05` magic bytes)
- **Full protocol parser** - decodes TC_OBJECT, TC_STRING, TC_ARRAY, TC_CLASSDESC, TC_REFERENCE, TC_ENUM, TC_BLOCKDATA, TC_PROXYCLASSDESC, and all Java primitives
- **Live editing** - modify string values, numbers, and booleans directly in the structured text view
- **Apply button** - click Apply to reconstruct the binary and verify your changes in Raw/Pretty before sending
- **Automatic reconstruction** - edits are also applied when switching tabs or sending the request
- **Works everywhere** - available in Proxy (intercept + history), Repeater, Intruder, Scanner, and any extension that uses Burp's standard message editor (Stepper, Logger++, Autorize, etc.)

Example output:
```
=== Deserialized Java Object Stream ===

[Object] org.springframework.remoting.support.RemoteInvocation
  methodName (String) = "getUserProfile"
  parameterTypes:
    [Ljava.lang.Class;] length=1
      [0]: (String) = "java.lang.String"
  arguments:
    [Ljava.lang.Object;] length=1
      [0]: (String) = "admin_user"
  [Object] java.util.Hashtable
    (String) = "appcontext"
    [Object] java.util.Hashtable
      (String) = "USERID"
      (String) = "ID00001"
      (String) = "locale"
      (String) = "en_AU"
```

---

## Features


### Passive Automatic Analysis

<img width="1874" height="574" alt="image" src="https://github.com/user-attachments/assets/9f9941e2-1540-40a3-b213-f5368fe74b8c" />

- Intercepts all matching requests across selected Burp tools
- Automatically replays with modified serialized values
- Compares original vs modified responses
- Color-codes results: SAME | SIMILAR | DIFFERENT

### Manual Right-Click Actions

<img width="972" height="593" alt="image" src="https://github.com/user-attachments/assets/de66f823-fda1-4207-b033-2321aaa0a711" />

- **Send to Repeater (Same Length)** - fast direct replacement
- **Send to Repeater (Any Length)** - patches length prefixes automatically
- **Send to Repeater (Batch)** - comma-separated payloads, one tab per payload
- **Send to Repeater using Saved Rule** - apply pre-configured rules instantly

### Smart Serialization Handling
- **Java `char[]` buffers** - overwrites null-padding or expands buffer + patches array size
- **TC_STRING format** - auto-patches 2-byte length prefix
- **UTF-16BE encoding** - handles Java's internal string representation
- **ASCII strings** - catches method names and plain-text fields

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
| Jython | Standalone JAR (2.7.x) - [Download](https://www.jython.org/download) |

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


4. A new **"DeserAuth"** tab appears in Burp, and a **"Deserialized"** tab appears in all message editors when viewing Java serialized content.

---

## Usage Guide

### Deserialized Editor Tab (New in v2.0)

The Deserialized tab appears automatically alongside Pretty/Raw/Hex whenever a request or response contains Java serialized data.

1. **Navigate to any serialized request** in Proxy, Repeater, Intruder, or any message editor
2. **Click the "Deserialized" tab** to see the parsed object tree
3. **Edit values** directly in the text view - change strings (in quotes), numbers, or booleans
4. **Click "Apply"** to reconstruct the binary and verify your changes
5. **Switch to Raw/Pretty** to see the reconstructed serialized bytes
6. **Send the request** - modifications are automatically applied

| Location | View | Edit | Apply |
|---|---|---|---|
| Proxy Intercept | Yes | Yes | Yes |
| Proxy History | Yes | No | No |
| Repeater | Yes | Yes | Yes |
| Intruder | Yes | Yes | Yes |
| Scanner | Yes | No | No |
| Target Site Map | Yes | No | No |
| Other Extensions (Stepper, etc.) | Yes | Depends | Depends |

### Passive Mode (Automatic Authorization Testing)

1. **Add Swap Rules** in the DeserAuth tab:
- Search: `User1` (your user ID)
- Replace: `User2` (target user ID)
- Mode: Any Length

2. **Select Scope** - choose which Burp tools to monitor

3. **Click START**

4. **Use the application normally** - browse, click, perform actions

5. **Watch the results table** - DIFFERENT entries indicate potential authorization bypass

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

### 6. Live Object Inspection (New in v2.0)

Use the Deserialized tab to inspect any serialized request without swap rules:

- Identify class names, method calls, and parameters in unfamiliar applications
- Discover hidden fields and values embedded in the binary stream
- Understand the object structure before crafting targeted test payloads

---

## How It Works

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     DeserAuth Extension                          │
├─────────────────┬──────────────────┬─────────────────────────────┤
│ IHttpListener   │ IContextMenu     │ IMessageEditorTabFactory    │
│ (Passive Mode)  │ Factory          │ (Deserialized Tab)          │
│                 │ (Manual Mode)    │                             │
│ Intercepts      │ Right-click      │ Adds "Deserialized" tab    │
│ responses from  │ actions: Send    │ to all message editors      │
│ selected tools  │ to Repeater      │ → Parses binary stream      │
│ → Apply rules   │ → Same/Any/     │ → Shows editable tree       │
│ → Replay        │   Batch/Saved    │ → Reconstructs on Apply     │
│ → Compare       │                  │ → Patches binary on send    │
│ → Log results   │                  │                             │
├─────────────────┴──────────────────┴─────────────────────────────┤
│                    Swap Engine                                    │
│                                                                  │
│   1. UTF-16BE char[] replacement (with null-padding)             │
│   2. Array size prefix patching (4-byte big-endian int)          │
│   3. TC_STRING length prefix patching (2-byte)                   │
│   4. ASCII fallback replacement                                  │
├──────────────────────────────────────────────────────────────────┤
│                Java Serialization Parser (New in v2.0)            │
│                                                                  │
│   Full Java Object Serialization Stream Protocol decoder:        │
│   TC_OBJECT | TC_STRING | TC_ARRAY | TC_CLASSDESC | TC_ENUM     │
│   TC_REFERENCE | TC_BLOCKDATA | TC_PROXYCLASSDESC | Primitives  │
│   → Structured text output with editable values                  │
│   → Graceful degradation for unknown/exotic structures           │
└──────────────────────────────────────────────────────────────────┘
```

### Serialized String Storage in Java

Standard TC_STRING:
```
┌──────┬──────────┬─────────────────┐
│ 0x74 │ 2-byte   │ UTF-8 string    │
│      │ length   │ bytes           │
└──────┴──────────┴─────────────────┘
```

char[] Array (StringBuilder internal):
```
┌────────────┬──────┬──────┬──────┬──────┬──────┬──────┐
│ 4-byte     │ \x00 │ \x00 │ \x00 │ \x00 │ \x00 │ \x00 │
│ array size │  I   │  D   │  0   │  1   │ \x00 │ \x00 │ ← null padding
└────────────┴──────┴──────┴──────┴──────┴──────┴──────┘
↑ UTF-16BE chars ↑     ↑ available space ↑
```

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
| `ZipException: zip END header not found` | You selected "Java" extension type - change to "Python" |
| `NameError: global name 'X' is not defined` | Missing import - check Jython console output |
| No entries appearing in table | Verify: rules have search values, scope is correct, START is clicked |
| Deserialized tab not appearing | Request must contain `Content-Type: application/x-java-serialized-object` header or body starting with `AC ED 00 05` |
| Deserialized tab shows parse error | Complex or non-standard serialized objects may partially parse - check the Raw tab for full content |
| Apply button not visible | The Apply button only appears in editable editors (Repeater request, Proxy intercept) - not in read-only views |
| Export fails with encoding error | Fixed in v1.2 - binary bodies are sanitized before export |

---

## Changelog

### v2.0 (Current)
- **Deserialized Message Editor Tab** - human-readable view of Java serialized objects, like JWT extension for serialization
- Full Java Object Serialization Stream Protocol parser (TC_OBJECT, TC_STRING, TC_ARRAY, TC_CLASSDESC, TC_REFERENCE, TC_ENUM, TC_BLOCKDATA, TC_PROXYCLASSDESC, all primitives)
- Live editing of string, numeric, and boolean values in the structured text view
- Apply button for manual reconstruction with status feedback
- Automatic binary reconstruction on tab switch or send
- Works across all Burp message editors (Proxy, Repeater, Intruder, Scanner, and third-party extensions)
- char[] arrays displayed as decoded strings for readability
- Graceful degradation for complex/unknown serialized structures

### v1.2
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

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Yuthan Balaji K**

- GitHub: [@iamyuthan](https://github.com/iamyuthan)
- Repository: [DeserAuth](https://github.com/iamyuthan/DeserAuth)

---

If this tool helps you find authorization bugs, please consider giving it a star!

---

<p align="center">
  <sub>Built with coffee for the offensive security community</sub>
</p>
