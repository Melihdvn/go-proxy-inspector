# go-proxy-inspector

A terminal-based HTTP proxy inspector built with Go and [Bubble Tea](https://github.com/charmbracelet/bubbletea).

Sit between your HTTP client and your API, inspect every request and response in real time, edit request bodies, and replay them — all from the terminal.

```
Client → :3000 (proxy) → :4001 (your API)
```

---

## Features

- **Live request list** — see every proxied request as it happens
- **Detail view** — inspect request headers, request body, response headers, and response body
- **Edit & replay** — modify the request body and resend it; the replayed request is logged as a new event
- **Scrollable UI** — navigate large payloads comfortably
- No external dependencies beyond Bubble Tea

---

## Getting Started

### Prerequisites

- Go 1.21+

### Install & Run

```bash
git clone https://github.com/Melihdvn/go-proxy-inspector
cd go-proxy-inspector
go run main.go
```

By default the proxy listens on **`:3000`** and forwards to **`http://localhost:4001`**.  
To change the target, edit `main.go`:

```go
go proxy.Start("http://localhost:YOUR_PORT")
```

---

## Usage

Send requests to the proxy instead of your API directly:

```bash
# Instead of: curl http://localhost:4001/test
curl http://localhost:3000/test

# With a JSON body
curl -X POST http://localhost:3000/test \
  -H "Content-Type: application/json" \
  -d '{"message":"hello"}'
```

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
├── main.go          # Entry point — wires proxy and UI together
├── proxy/
│   ├── proxy.go     # Reverse proxy with custom RoundTripper for inspection
│   └── event.go     # Event struct and channel
└── ui/
    └── model.go     # Bubble Tea model — list, detail, and edit screens
```

---

## How it Works

1. `proxy.Start()` spins up an `httputil.ReverseProxy` on `:3000` with a custom `RoundTripper`
2. For every request, the `RoundTripper` reads and restores both the request and response bodies, then sends an `Event` over a buffered channel
3. `main.go` bridges the channel to Bubble Tea via `p.Send(event)`
4. The UI updates in real time across three screens: **List → Detail → Edit**
5. Replay sends a new request back through `:3000`, so it is captured and logged as a fresh event

---

## License

MIT
