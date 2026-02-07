#!/usr/bin/env node

/**
 * LuLu Monitor CLI
 * Monitor LuLu Firewall alerts and forward to OpenClaw
 */

const LuLuMonitor = require('../src/monitor');
const { clickLuLuButton } = require('../src/extractor');

// Parse command line arguments
const args = process.argv.slice(2);

function printHelp() {
  console.log(`
LuLu Monitor - Monitor LuLu Firewall alerts for OpenClaw

Usage: lulu-monitor [options]

Options:
  --webhook <url>     Send alerts to webhook URL
  --poll <ms>         Poll interval in milliseconds (default: 500)
  --verbose, -v       Enable verbose logging
  --help, -h          Show this help

Commands:
  --allow [always|process]   Click Allow on current LuLu alert
  --block                    Click Block on current LuLu alert

Examples:
  lulu-monitor                          # Start monitoring (uses OpenClaw CLI)
  lulu-monitor --webhook http://...     # Send to webhook
  lulu-monitor --allow always           # Allow current alert permanently
  lulu-monitor --block                  # Block current alert

Environment Variables:
  LULU_WEBHOOK_URL    Default webhook URL
  OPENCLAW_PATH       Path to openclaw CLI (default: /opt/homebrew/bin/openclaw)
`);
}

// Handle help
if (args.includes('--help') || args.includes('-h')) {
  printHelp();
  process.exit(0);
}

// Handle --allow command
const allowIndex = args.indexOf('--allow');
if (allowIndex !== -1) {
  const duration = args[allowIndex + 1] || 'process';
  console.log(`Clicking Allow (${duration})...`);
  
  clickLuLuButton('allow', duration).then(success => {
    if (success) {
      console.log('✓ Allowed');
      process.exit(0);
    } else {
      console.log('✗ Failed to click Allow');
      process.exit(1);
    }
  });
} 
// Handle --block command
else if (args.includes('--block')) {
  console.log('Clicking Block...');
  
  clickLuLuButton('block').then(success => {
    if (success) {
      console.log('✓ Blocked');
      process.exit(0);
    } else {
      console.log('✗ Failed to click Block');
      process.exit(1);
    }
  });
}
// Start monitoring
else {
  const options = {
    verbose: args.includes('--verbose') || args.includes('-v'),
    pollInterval: 500,
    webhookUrl: null
  };

  // Parse --webhook
  const webhookIndex = args.indexOf('--webhook');
  if (webhookIndex !== -1 && args[webhookIndex + 1]) {
    options.webhookUrl = args[webhookIndex + 1];
  }

  // Parse --poll
  const pollIndex = args.indexOf('--poll');
  if (pollIndex !== -1 && args[pollIndex + 1]) {
    options.pollInterval = parseInt(args[pollIndex + 1], 10) || 500;
  }

  // Create and start monitor
  const monitor = new LuLuMonitor(options);

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\nShutting down...');
    monitor.stop();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    monitor.stop();
    process.exit(0);
  });

  // Start monitoring
  monitor.start();
}
