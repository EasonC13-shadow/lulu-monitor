/**
 * LuLu Window Monitor
 * Polls for LuLu alert windows using AppleScript
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const { extractAlertData } = require('./extractor');

class LuLuMonitor {
  constructor(options = {}) {
    this.webhookUrl = options.webhookUrl || process.env.LULU_WEBHOOK_URL;
    this.openclawPath = options.openclawPath || '/opt/homebrew/bin/openclaw';
    this.pollInterval = options.pollInterval || 500; // ms
    this.verbose = options.verbose || false;
    
    this.lastAlertHash = null;
    this.isRunning = false;
    this.pollTimer = null;
  }

  log(...args) {
    if (this.verbose) {
      console.log('[LuLu Monitor]', ...args);
    }
  }

  /**
   * Start monitoring for LuLu alerts
   */
  start() {
    if (this.isRunning) {
      console.log('Monitor already running');
      return;
    }

    console.log('🔥 LuLu Monitor started');
    console.log(`   Poll interval: ${this.pollInterval}ms`);
    if (this.webhookUrl) {
      console.log(`   Webhook: ${this.webhookUrl}`);
    } else {
      console.log(`   Mode: OpenClaw CLI (${this.openclawPath})`);
    }

    this.isRunning = true;
    this.poll();
  }

  /**
   * Stop monitoring
   */
  stop() {
    this.isRunning = false;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
    console.log('Monitor stopped');
  }

  /**
   * Poll for LuLu alert windows
   */
  async poll() {
    if (!this.isRunning) return;

    try {
      const hasAlert = await this.checkForAlert();
      
      if (hasAlert) {
        await this.handleAlert();
      }
    } catch (err) {
      this.log('Poll error:', err.message);
    }

    // Schedule next poll
    this.pollTimer = setTimeout(() => this.poll(), this.pollInterval);
  }

  /**
   * Check if LuLu has an alert window open
   */
  async checkForAlert() {
    const script = `
      tell application "System Events"
        if exists process "LuLu" then
          tell process "LuLu"
            set windowNames to name of every window
            repeat with wName in windowNames
              if wName contains "LuLu Alert" then
                return "found"
              end if
            end repeat
          end tell
        end if
      end tell
      return "none"
    `;

    try {
      const { stdout } = await execAsync(`osascript -e '${script.replace(/'/g, "'\"'\"'")}'`);
      return stdout.trim() === 'found';
    } catch (err) {
      return false;
    }
  }

  /**
   * Handle a detected LuLu alert
   */
  async handleAlert() {
    this.log('Alert detected, extracting data...');

    try {
      // Extract alert data
      const alertData = await extractAlertData();
      
      if (!alertData) {
        this.log('Failed to extract alert data');
        return;
      }

      // Create hash to detect duplicate alerts
      const alertHash = this.hashAlert(alertData);
      
      if (alertHash === this.lastAlertHash) {
        this.log('Duplicate alert, skipping');
        return;
      }
      
      this.lastAlertHash = alertHash;
      
      console.log(`\n🚨 New LuLu Alert:`);
      console.log(`   Process: ${alertData.processName || 'unknown'}`);
      console.log(`   Destination: ${alertData.ipAddress}:${alertData.port}`);
      if (alertData.reverseDNS) {
        console.log(`   DNS: ${alertData.reverseDNS}`);
      }

      // Send to OpenClaw
      await this.sendToOpenClaw(alertData);

    } catch (err) {
      console.error('Error handling alert:', err.message);
    }
  }

  /**
   * Create a hash of alert data for deduplication
   */
  hashAlert(data) {
    return `${data.processName}|${data.ipAddress}|${data.port}`;
  }

  /**
   * Send alert data to OpenClaw
   */
  async sendToOpenClaw(alertData) {
    const message = this.formatAlertMessage(alertData);

    if (this.webhookUrl) {
      // Send via webhook
      await this.sendWebhook(message, alertData);
    } else {
      // Send via OpenClaw CLI
      await this.sendViaCLI(message);
    }
  }

  /**
   * Format alert data as a message
   */
  formatAlertMessage(data) {
    let msg = `🔥 **LuLu Firewall Alert**\n\n`;
    
    msg += `**Connection:**\n`;
    if (data.processName) msg += `• Process: \`${data.processName}\`\n`;
    if (data.pid) msg += `• PID: ${data.pid}\n`;
    if (data.path) msg += `• Path: \`${data.path}\`\n`;
    if (data.args) msg += `• Args: \`${data.args}\`\n`;
    msg += `• Destination: \`${data.ipAddress}:${data.port}\` (${data.protocol || 'TCP'})\n`;
    if (data.reverseDNS) msg += `• DNS: \`${data.reverseDNS}\`\n`;
    
    msg += `\n**Reply with:**\n`;
    msg += `• \`allow always\` - Allow permanently\n`;
    msg += `• \`allow process\` - Allow for process lifetime\n`;
    msg += `• \`block\` - Block this connection\n`;
    msg += `• \`ignore\` - Handle locally\n`;

    return msg;
  }

  /**
   * Send alert via webhook
   */
  async sendWebhook(message, alertData) {
    try {
      const response = await fetch(this.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'lulu_alert',
          message,
          data: alertData,
          timestamp: new Date().toISOString()
        })
      });

      if (response.ok) {
        this.log('Alert sent via webhook');
      } else {
        console.error('Webhook error:', response.status);
      }
    } catch (err) {
      console.error('Webhook error:', err.message);
    }
  }

  /**
   * Send alert via OpenClaw CLI
   */
  async sendViaCLI(message) {
    try {
      // Use openclaw cron wake to inject a message
      const escaped = message.replace(/"/g, '\\"').replace(/`/g, '\\`');
      const cmd = `"${this.openclawPath}" cron wake --text "${escaped}" --mode now`;
      
      await execAsync(cmd);
      this.log('Alert sent via OpenClaw CLI');
    } catch (err) {
      console.error('CLI error:', err.message);
      
      // Fallback: write to a file that OpenClaw can read
      const fs = require('fs');
      const alertFile = '/tmp/lulu-alert.json';
      fs.writeFileSync(alertFile, JSON.stringify({ message, timestamp: Date.now() }));
      console.log(`Alert written to ${alertFile}`);
    }
  }
}

module.exports = LuLuMonitor;
