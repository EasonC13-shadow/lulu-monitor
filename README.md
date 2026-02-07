# LuLu Monitor

Monitor [LuLu Firewall](https://objective-see.org/products/lulu.html) alerts and forward them to [OpenClaw](https://github.com/openclaw/openclaw) for remote management.

## Features

- 🔍 Monitors for LuLu alert windows
- 📤 Forwards alerts to OpenClaw via CLI or webhook
- 🎮 Control LuLu (Allow/Block) via command line
- 🚀 Lightweight Node.js implementation

## Installation

```bash
npm install -g lulu-monitor
```

Or run directly:
```bash
npx lulu-monitor
```

## Usage

### Start Monitoring

```bash
# Use OpenClaw CLI (default)
lulu-monitor

# Or send to webhook
lulu-monitor --webhook http://your-webhook-url

# With verbose logging
lulu-monitor -v
```

### Control LuLu Directly

```bash
# Allow current alert (process lifetime)
lulu-monitor --allow

# Allow permanently
lulu-monitor --allow always

# Block current alert
lulu-monitor --block
```

## OpenClaw Integration

LuLu Monitor sends alerts to OpenClaw, which can then:
1. Notify you via Telegram, Discord, etc.
2. Wait for your decision
3. Execute the action on LuLu

### Message Format

When an alert is detected, OpenClaw receives:
```
🔥 **LuLu Firewall Alert**

**Connection:**
• Process: `curl`
• Path: `/usr/bin/curl`
• Destination: `185.199.108.153:443` (TCP)
• DNS: `cdn.github.com`

**Reply with:**
• `allow always` - Allow permanently
• `allow process` - Allow for process lifetime
• `block` - Block this connection
• `ignore` - Handle locally
```

## Auto-Start on Login

Create a launchd plist to start on login:

```bash
cat > ~/Library/LaunchAgents/com.openclaw.lulu-monitor.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openclaw.lulu-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/node</string>
        <string>/opt/homebrew/lib/node_modules/lulu-monitor/bin/lulu-monitor.js</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/lulu-monitor.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/lulu-monitor.error.log</string>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.openclaw.lulu-monitor.plist
```

## Requirements

- macOS (tested on 14+)
- Node.js 18+
- [LuLu Firewall](https://objective-see.org/products/lulu.html)
- Accessibility permission for Terminal/Node

## Permissions

The monitor needs Accessibility permission to read LuLu's window contents. Grant permission in:
**System Settings → Privacy & Security → Accessibility**

Add Terminal.app or your Node.js process.

## License

MIT
