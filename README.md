# Ion Security

Made by Domderok.

Ion Security is a Windows desktop app focused on local protection, real network monitoring, and automatic reaction to suspicious remote connections.

## Main Features

- Reads the real Microsoft Defender status through `Get-MpComputerStatus`
- Verifies Windows Firewall profiles through `Get-NetFirewallProfile`
- Checks SmartScreen status
- Monitors real active connections with `netstat`
- Classifies remote connections by risk using IPs, ports, and geolocation
- Shows suspicious remote IPs directly to the user
- Attempts to block suspicious IPs automatically through `Windows Firewall`
- Stores already blocked IPs to avoid duplicate actions
- Manages WireGuard tunnels through `.conf` files
- Includes a built-in local assistant that explains the real data collected by the app

## Active Protection

When active protection is enabled, Ion Security:

- alerts the user when a high-risk remote IP is detected
- tries to expel it by blocking traffic to that IP with a firewall rule
- links the event to IP, port, PID, and process name when available

## Automatic Bootstrap

On first launch, the app can:

- create its required folders
- install WireGuard with `winget`
- enable Windows Firewall
- update Microsoft Defender signatures
- set SmartScreen to `Warn`

## Realistic Limits

- It cannot honestly guarantee blocking 100% of all threats
- It does not fully replace a dedicated proprietary antivirus engine
- A real VPN connection still requires at least one provider `.conf` file inside the VPN folder
- Automatic blocking depends on the real system and network data exposed by Windows at detection time

## Requirements

- Windows 10 or Windows 11
- Administrator privileges for firewall, Defender, and VPN actions
- Node.js 18+ for local development

## Development

```bash
npm install
npm start
```

## Build

```bash
npm run pack
```

The ready-to-run app build is generated in `dist/win-unpacked/`.

## GitHub Distribution

For end users, the recommended distribution method is a GitHub Release containing a zipped `win-unpacked` build, so users can download it, extract it, and launch `Ion Security.exe`.

## Note

Ion Security is a concrete base for local defense and real monitoring, but a more professional public release still needs code signing, a final icon, a privacy policy, broader testing, and a stronger release pipeline.
