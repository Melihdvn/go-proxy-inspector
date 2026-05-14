# go-proxy-inspector

A terminal-based **Intercepting Forward Proxy** (like Charles Proxy or Fiddler) built with Go and [Bubble Tea](https://github.com/charmbracelet/bubbletea).

Sit between your OS/Browser and the internet, inspect every HTTP/HTTPS request and response in real time, edit request bodies, replay them, and even intercept/block them dynamically — all from the terminal.

---

## Features

- **Forward Proxy Architecture** — Intercepts all traffic routed through it (HTTP and HTTPS).
- **HTTPS MITM Support** — Dynamically generates certificates to decrypt and inspect HTTPS traffic.
- **Live Request List** — See every proxied request as it happens with full host and path.
- **Advanced Filtering** — Support for regex (`regex:^https`), host (`host:api.github.com`), method (`method:POST`), and status codes.
- **Intercept Mode** — Pause incoming requests, modify them on the fly, and forward or drop them.
- **Domain Blocklist** — Dynamically block tracking or ad domains and see them crossed out.
- **Edit & Replay** — Modify the request body and resend it to the original target, viewing the new response instantly.
- **Traffic Statistics** — View a latency histogram, status code breakdown, and top hosts.
- **HAR Export** — Export traffic to HTTP Archive format (HAR) compatible with Chrome DevTools.
- **YAML Config** — Supports saving settings to `config.yaml`.
- **Brute Force Tool** — Built-in attack module with rate limiting (delays/batching), status code success criteria, and automated password generation.
- **Auto-Generation Mode** — Automatically generates password combinations if no wordlist is provided.

---

## Getting Started

### Prerequisites

- Go 1.21+
- [mkcert](https://github.com/FiloSottile/mkcert) (Required for HTTPS MITM interception)

### Installation & Certificate Setup

1. **Install mkcert and local CA:**
   ```bash
   # Windows (winget/choco)
   winget install FiloSottile.mkcert
   mkcert -install
   ```

2. **Run the application:**
   The application will automatically detect your `mkcert` Root CA.
   ```bash
   go run .
   ```
   Or use flags:
   ```bash
   go run . -port :8080 -config config.yaml
   ```

---

## Keybindings

### Global
| Key | Action |
|-----|--------|
| `?` | Show Help screen |
| `q` / `Ctrl+C` | Quit |
| `Esc` | Go back |

### List Screen
| Key | Action |
|-----|--------|
| `↑` / `k`, `↓` / `j` | Navigate requests |
| `Enter` | Open detail view |
| `/` | Filter (e.g. `host:api`, `method:POST`, `regex:^http`) |
| `ctrl+x` | Clear filter |
| `i` | Toggle Intercept Mode (Pause & Modify) |
| `x` | Export events to JSON |
| `h` | Export events to HAR (Browser DevTools compatible) |
| `r` | Quick replay selected request |
| `b` | Block selected request's host |
| `A` | Open Brute Force Tool for selected request |
| `T` | Open General Brute Force Tool (empty URL) |
| `B` | View Blocklist |
| `S` | View Statistics |

### Detail & Edit Screens
| Key | Action |
|-----|--------|
| `e` | Open edit mode |
| `ctrl+s`| Replay with edited body |
| `A` | Open Brute Force Tool for this request |
| `↑` / `↓` | Scroll up/down |

### Intercept Screen
| Key | Action |
|-----|--------|
| `ctrl+f`| Forward request (with modified body) |
| `ctrl+d`| Drop request |

---

## Brute Force Tool

The built-in brute force module allows you to test login endpoints for credential vulnerabilities.

### Accessing
- **Shift+A**: Open the tool prepopulated with the selected request's URL and field names.
- **Shift+T**: Open a fresh Brute Force Tool with an empty target URL.

### Advanced Features
- **Auto-Generation**: Leave the `Wordlist` field empty to trigger automated password generation. You can configure the character set and maximum length.
- **Success Criteria**: Define success based on a specific HTTP Status Code (e.g., "Success if status is 200" or "Success if status is NOT 403").
- **Rate Limit Bypass**: 
    - `Delay`: Milliseconds to wait between every individual request.
    - `Batch`: Pause for a longer duration after every `N` requests to avoid triggering security blocks.

---

## Configuration

You can use a `config.yaml` file to set defaults:

```yaml
listenaddr: ":3000"
maxevents: 1500
blockeddomains:
  - doubleclick.net
  - tracking.example.com
```

Run with `-config config.yaml` to load it.

---

## License

MIT
