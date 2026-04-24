# go-proxy-inspector

A terminal-based **Intercepting Forward Proxy** (like Charles Proxy or Fiddler) built with Go and [Bubble Tea](https://github.com/charmbracelet/bubbletea).

Sit between your OS/Browser and the internet, inspect every HTTP/HTTPS request and response in real time, edit request bodies, and replay them — all from the terminal.

---

## Features

- **Forward Proxy Architecture** — Intercepts all traffic routed through it (HTTP and HTTPS).
- **HTTPS MITM Support** — Dynamically generates certificates to decrypt and inspect HTTPS traffic.
- **Live request list** — see every proxied request as it happens.
- **Detail view** — inspect request headers, request body, response headers, and response body.
- **Edit & replay** — modify the request body and resend it to the original target.
- **Scrollable UI** — navigate large payloads comfortably.

---

## Getting Started

### Prerequisites

- Go 1.21+
- [mkcert](https://github.com/FiloSottile/mkcert) (Required for HTTPS MITM interception)

### Installation & Certificate Setup

To intercept HTTPS traffic (like `https://google.com` or `https://api.github.com`), the proxy needs a trusted Certificate Authority (CA) to dynamically generate certificates. 

1. **Install mkcert and local CA:**
   ```bash
   # Windows (winget/choco)
   winget install FiloSottile.mkcert
   mkcert -install
   ```

2. **Run the application:**
   The application will automatically detect your `mkcert` Root CA in your system's AppData folder and enable HTTPS MITM interception.
   ```bash
   go run .
   ```

---

## Usage

By default the proxy listens on **`localhost:3000`**.

### 1. Test via cURL
You can explicitly tell cURL to use your proxy:
```bash
# HTTP Request
curl -x http://localhost:3000 http://httpbin.org/get

# HTTPS Request
curl -x http://localhost:3000 https://httpbin.org/get
```

### 2. System-wide / Browser Interception
To capture all your browser or system traffic:
- **Windows:** Go to Settings -> Network & Internet -> Proxy. Set "Use a proxy server" to `On`, Address: `127.0.0.1`, Port: `3000`.
- **Postman/Insomnia:** Configure the HTTP/HTTPS proxy in the app's settings to `127.0.0.1:3000`.

*Note: Make sure you have run `mkcert -install` so your browser trusts the proxy's certificates.*

---

## Keybindings

### List screen
| Key | Action |
|-----|--------|
| `↑` / `k` | Move cursor up |
| `↓` / `j` | Move cursor down |
| `Enter` | Open detail view |
| `q` / `Ctrl+C` | Quit |

### Detail screen
| Key | Action |
|-----|--------|
| `↑` / `k` | Scroll up |
| `↓` / `j` | Scroll down |
| `e` | Open edit mode |
| `Esc` | Back to list |
| `q` / `Ctrl+C` | Quit |

### Edit screen
| Key | Action |
|-----|--------|
| `←` / `→` | Move cursor |
| `Home` / `Ctrl+A` | Jump to start |
| `End` / `Ctrl+E` | Jump to end |
| `Backspace` | Delete character before cursor |
| `Delete` | Delete character after cursor |
| `Enter` | New line |
| `Ctrl+S` | **Replay** with edited body |
| `Esc` | Cancel |

---

## Project Structure

```
go-proxy-inspector/
├── main.go          # Entry point — auto-detects certs and wires proxy to UI
├── proxy/
│   ├── config.go    # Proxy configuration (ListenAddr, Certs)
│   ├── proxy.go     # Forward Proxy server using elazarl/goproxy
│   └── event.go     # Event struct and channel
└── ui/
    └── model.go     # Bubble Tea model — list, detail, and edit screens
```

---

## License

MIT
