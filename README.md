# airlanes
A TUI WiFi scanner for channel analysis and congestion mapping.

## Features

- Scans nearby WiFi networks and lists SSID, channel, signal strength, and security.
- Starts with an automatic initial scan, then leaves rescans to the user.
- Builds separate congestion maps for 2.4 GHz and 5 GHz channels.
- Recommends the least congested channel in each band.
- Supports keyboard-driven navigation with Ratatui.

## Run

```bash
cargo run
```

Controls:

- `r` rescan
- `j` / `k` or arrow keys move through networks
- `q` quits

## Notes

- macOS scanning uses `system_profiler SPAirPortDataType` (with an optional `sudo -n` retry when SSIDs are redacted). Nearby SSIDs only appear when macOS allows it—usually after you grant **Location Services** to the app that launched the terminal (for example **Terminal**, **Cursor**, or **iTerm**) under **System Settings → Privacy & Security → Location Services**, then restart that terminal.
- Linux scanning uses `nmcli` and expects NetworkManager to be installed.
- Scans run in the background so the TUI stays responsive during startup and refreshes.
- After startup, rescans only happen when you press `r`.
- If WiFi is disabled or the OS denies scan access, the TUI will stay up and show the scan error in the status bar.
- If every SSID still shows as `<redacted>`, check the **Access** line in the TUI for a short hint, and confirm Location Services for your terminal host app (above).

### Future: CoreWLAN / entitlements

A dedicated helper using **CoreWLAN** (Swift or Rust with `objc2`) could reduce reliance on parsing `system_profiler` text. Distribution as a signed app may require the **`com.apple.developer.networking.wifi-info`** entitlement (and users still typically need Location consent for Wi‑Fi identifiers on recent macOS).
