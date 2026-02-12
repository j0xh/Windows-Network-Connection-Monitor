# NetMonitor

A single-binary Windows network monitor. Maps every TCP/UDP socket to its owning process in real time, flags public and suspicious endpoints, and logs everything to disk.

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

- Live TCP connection table with process name, PID, local/remote address
- UDP listener table with process mapping
- Color-coded flags — `PUBLIC` for internet-bound traffic, `ALERT` for high-risk ports (SMB, RDP, WinRM, etc.)
- Dark themed ANSI console UI with alternating row shading
- Pause/resume with `P` to freeze output for inspection
- Background logging to `connections.log`

## Requirements

- Windows 10 or later
- Visual Studio 2019+ with C++ Desktop Development workload
- Run as Administrator for full process visibility

## Build

From a Developer Command Prompt:

```
cl core.cpp /EHsc /link iphlpapi.lib ws2_32.lib /out:NetMonitor.exe
```

Or run the included `build.bat` from a Developer Command Prompt.

## Usage

```
NetMonitor.exe
```

Run as Administrator for best results. Without elevation, system service process names show as `System`.

| Key | Action |
|---|---|
| `P` | Pause / Resume |
| `Ctrl+C` | Exit |

The display is split into two sections:

**TCP Connections** — active connections with remote endpoints. `PUBLIC` flags traffic leaving your local network. `ALERT` marks connections on commonly targeted ports (25, 135, 139, 445, 3389, 5985).

**UDP Listeners** — local ports with a bound process.

All activity is appended to `connections.log` while the monitor is running. Pausing stops logging.

## Disclaimer

Reads system connection tables via standard Windows APIs. Does not capture packets, intercept TLS, or modify traffic.