# gatewatch

Real-time terminal dashboard for monitoring Linux gateways running strongSwan VPN and iptables NAT.

![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue)

## Features

- **VPN Tunnels** — live status of all strongSwan IKE SAs (uptime, bytes, remote IP)
- **NAT Rules** — parsed view of iptables DNAT/SNAT rules grouped by service
- **Active Connections** — real-time TCP connections per port with peer IPs
- **Traffic** — per-port bandwidth rates and cumulative byte counters
- **Search** — filter all panels by keyword (`/` to search, `ESC` to clear)
- **Detail View** — select a NAT rule and press `Enter` to see the full connection flow

## Requirements

- **Node.js** >= 20
- **Linux** with `strongSwan` (swanctl) and `iptables`
- **Root access** (needed to read iptables rules and socket info)

## Install

```bash
git clone https://github.com/Felipe-Nazal/gatewatch.git
cd gatewatch
npm install
```

## Usage

```bash
sudo node index.js
```

Or install globally:

```bash
npm install -g .
sudo gatewatch
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GATEWATCH_INTERVAL` | `5000` | Refresh interval in ms |
| `GATEWATCH_RULES` | `/etc/iptables/rules.v4` | Path to iptables rules file |

### Keyboard Shortcuts

| Key | Action |
|---|---|
| `TAB` / `Shift+TAB` | Switch between panels |
| `Up` / `Down` | Scroll within panel |
| `/` | Open search filter |
| `Enter` | Show detail for selected NAT rule |
| `ESC` | Close detail / clear filter |
| `q` | Quit |

## Architecture

```
gatewatch/
  index.js              # Main loop — runs parsers, updates dashboard
  parsers/
    swanctl.js          # Parses `swanctl --list-sas` output
    iptables.js         # Parses /etc/iptables/rules.v4
    sockets.js          # Parses `ss` output (connections + traffic)
  ui/
    dashboard.js        # Terminal UI built with blessed
```

## License

MIT
