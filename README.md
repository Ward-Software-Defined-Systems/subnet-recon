<p align="center">
  <img src="assets/banner.svg" alt="subnet-recon" width="700"/>
</p>

<p align="center">
  A fast, parallel network subnet scanner written in Rust.<br/>
  Scans IP subnets to find reachable hosts via ICMP echo or TCP connect probes,<br/>
  with real-time progress display and configurable output.
</p>

---

## Features

- **ICMP and TCP probing** — ICMP echo requests (requires root) or TCP connect probes (no root needed, RST = reachable)
- **Parallel scanning** — Rayon-based thread pool, defaults to all available cores
- **IP randomization** — Global shuffle, per-subnet interleave, or sequential order
- **Rate limiting** — Token-bucket limiter to cap probes/sec across all threads
- **Progress display** — Per-subnet and overall progress bars with rate, elapsed time, and ETA
- **Flexible output** — Plain text (one IP per line) or JSON, to stdout or file

## Build

Requires Rust 1.56+ (edition 2021).

```bash
cargo build --release
```

The binary is at `./target/release/subnet-recon`.

## Setup

Copy the example config and edit it with your target subnets:

```bash
cp config.toml.example config.toml
# Edit config.toml with your subnets, probe method, etc.
```

`config.toml` is gitignored since it contains environment-specific targets.

## Usage

```bash
# ICMP scan (requires root)
sudo ./target/release/subnet-recon

# TCP scan (no root needed) — set method = "tcp" in config.toml
./target/release/subnet-recon

# Custom config file
./target/release/subnet-recon -c /path/to/config.toml

# Write results to file
./target/release/subnet-recon -o results.txt

# Override thread count
./target/release/subnet-recon -t 16

# Quiet mode (no progress bars)
./target/release/subnet-recon -q

# Verbose mode (prints config summary)
./target/release/subnet-recon -v

# Combine flags
sudo ./target/release/subnet-recon -c config.toml -o results.txt -t 8 -v
```

### CLI Options

```
  -c, --config <CONFIG>    Config file path [default: ./config.toml]
  -o, --output <OUTPUT>    Write results to file (overrides config)
  -t, --threads <THREADS>  Number of worker threads (overrides config)
  -v, --verbose...         Increase log verbosity
  -q, --quiet              Suppress progress display
```

## Configuration

All scan parameters are set in a TOML config file. See `config.toml.example` for a fully commented template.

### `[scan]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `method` | `"icmp"` \| `"tcp"` | `"icmp"` | Probe method. ICMP requires root. |
| `timeout_ms` | integer | `1000` | Per-probe timeout in milliseconds. |
| `threads` | integer | `0` | Worker threads. `0` = all available cores. |
| `rate_limit` | integer | `0` | Max probes/sec across all threads. `0` = unlimited. |
| `randomize` | `"global"` \| `"per_subnet"` \| `"none"` | `"global"` | IP scan order randomization mode. |
| `tcp_port` | integer | `80` | Target port for TCP probes. |

### `[output]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file` | string | `""` | Output file path. Empty = stdout only. |
| `format` | `"plain"` \| `"json"` | `"plain"` | Output format. |
| `include_unreachable` | bool | `false` | Include unreachable hosts in output. |

### `[dns]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `servers` | list of strings | `[]` | DNS server IPs for reverse lookups. Empty = system default. |
| `timeout_ms` | integer | `3000` | DNS query timeout in milliseconds. |

### `[[subnets]]`

Define one or more subnets to scan:

```toml
[[subnets]]
cidr = "192.168.1.0/24"
label = "Office LAN"

[[subnets]]
cidr = "10.0.0.0/8"
label = "Private Class A"
```

### Randomization Modes

- **`global`** — All IPs from all subnets are shuffled together. Best for large scans to avoid spending hours in one /24 block.
- **`per_subnet`** — Each subnet is shuffled independently, then round-robin interleaved. Ensures all subnets make progress concurrently.
- **`none`** — Sequential by subnet order, then by IP. Useful for debugging.

## Output Formats

**Plain** (default) — one IP per line (tab-separated hostname when resolved), sorted:

```
10.0.1.5	gateway.local
10.0.1.23
192.168.1.1	router.lan
192.168.1.100
```

**JSON** — array of objects with IP, subnet CIDR, label, and hostname (when resolved):

```json
[
  {
    "ip": "192.168.1.1",
    "subnet": "192.168.1.0/24",
    "label": "Office LAN",
    "hostname": "router.lan"
  }
]
```

## Memory

The full `10.0.0.0/8` expands to ~16.7M IPs. Each scan target uses 8 bytes, totaling ~128 MB for the IP list. This is acceptable for bare-metal scanning.

## Project Structure

```
src/
├── main.rs       Entry point, CLI parsing, orchestration
├── config.rs     Config loading, validation, CLI args (clap)
├── scan.rs       Probe logic (ICMP/TCP), thread pool, rate limiter
├── progress.rs   Progress bars (indicatif), quiet mode
└── results.rs    Output formatting (plain/JSON)
```

## License

Proprietary — Ward Software Defined Systems LLC
