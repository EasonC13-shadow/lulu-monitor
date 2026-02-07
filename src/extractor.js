/**
 * LuLu Alert Data Extractor
 * Uses AppleScript to extract text from LuLu alert windows
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

/**
 * Extract all text elements from the LuLu alert window
 */
async function extractAlertData() {
  // AppleScript to get all UI element values from LuLu window
  const script = `
    set outputText to ""
    
    tell application "System Events"
      tell process "LuLu"
        set frontmost to true
        delay 0.1
        
        try
          set alertWindow to window 1
          
          -- Get all static text values recursively
          set allTexts to my getTextsFromElement(alertWindow)
          
          repeat with t in allTexts
            set outputText to outputText & t & "|||"
          end repeat
          
        on error errMsg
          return "ERROR:" & errMsg
        end try
      end tell
    end tell
    
    return outputText
    
    -- Helper function to recursively get text from UI elements
    on getTextsFromElement(elem)
      set texts to {}
      
      tell application "System Events"
        try
          -- Get value if it exists
          set elemValue to value of elem
          if elemValue is not missing value and elemValue is not "" then
            set end of texts to elemValue as text
          end if
        end try
        
        try
          -- Get title if it exists
          set elemTitle to title of elem
          if elemTitle is not missing value and elemTitle is not "" then
            set end of texts to elemTitle as text
          end if
        end try
        
        try
          -- Get description if it exists
          set elemDesc to description of elem
          if elemDesc is not missing value and elemDesc is not "" then
            set end of texts to elemDesc as text
          end if
        end try
        
        -- Recurse into children
        try
          set childElements to UI elements of elem
          repeat with child in childElements
            set childTexts to my getTextsFromElement(child)
            set texts to texts & childTexts
          end repeat
        end try
      end tell
      
      return texts
    end getTextsFromElement
  `;

  try {
    const { stdout, stderr } = await execAsync(`osascript -e '${script.replace(/'/g, "'\"'\"'")}'`, {
      timeout: 5000
    });

    if (stdout.startsWith('ERROR:')) {
      console.error('AppleScript error:', stdout);
      return null;
    }

    // Parse the output
    const texts = stdout.split('|||').filter(t => t.trim());
    
    // Parse texts into structured data
    return parseAlertTexts(texts);

  } catch (err) {
    console.error('Extraction error:', err.message);
    return null;
  }
}

/**
 * Parse raw text array into structured alert data
 */
function parseAlertTexts(texts) {
  const data = {
    processName: '',
    pid: '',
    path: '',
    args: '',
    ipAddress: '',
    port: '',
    protocol: 'TCP',
    reverseDNS: '',
    rawTexts: texts
  };

  for (const text of texts) {
    const trimmed = text.trim();
    
    // Skip labels
    if (trimmed.endsWith(':')) continue;
    
    // IP address pattern
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed) && !data.ipAddress) {
      data.ipAddress = trimmed;
    }
    // Port/Protocol (e.g., "443 (TCP)")
    else if (/^\d{1,5} \((TCP|UDP)\)$/.test(trimmed)) {
      const match = trimmed.match(/^(\d+) \((TCP|UDP)\)$/);
      if (match) {
        data.port = match[1];
        data.protocol = match[2];
      }
    }
    // PID (4-6 digit number)
    else if (/^\d{4,6}$/.test(trimmed) && !data.pid) {
      data.pid = trimmed;
    }
    // Path (starts with /)
    else if (trimmed.startsWith('/') && trimmed.includes('/')) {
      data.path = trimmed;
      // Extract process name from path
      const parts = trimmed.split('/');
      const name = parts[parts.length - 1];
      if (name && !data.processName) {
        data.processName = name;
      }
    }
    // URL args
    else if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      data.args = trimmed;
    }
    // Reverse DNS (hostname pattern)
    else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\.?$/.test(trimmed) && !data.reverseDNS && !trimmed.startsWith('/')) {
      data.reverseDNS = trimmed.replace(/\.$/, '');
    }
    // Process name (simple word, not a label)
    else if (!trimmed.includes(' ') && !trimmed.includes('/') && !trimmed.includes(':') && trimmed.length < 50) {
      const skipWords = ['Details', 'Options', 'Process', 'Connection', 'LuLu', 'Alert', 'Block', 'Allow'];
      if (!skipWords.some(w => trimmed.includes(w)) && !data.processName) {
        data.processName = trimmed;
      }
    }
  }

  return data;
}

/**
 * Control LuLu - click Allow or Block button
 */
async function clickLuLuButton(action, duration = null) {
  const buttonName = action === 'allow' ? 'Allow' : 'Block';
  
  let script = '';
  
  // Set duration first if allowing
  if (action === 'allow' && duration) {
    const durationText = duration === 'always' ? 'Always' : 'Process lifetime';
    script += `
      tell application "System Events"
        tell process "LuLu"
          set frontmost to true
          delay 0.2
          try
            click radio button "${durationText}" of window 1
          on error
            try
              click radio button "${durationText}" of group 1 of window 1
            end try
          end try
        end tell
      end tell
      delay 0.2
    `;
  }
  
  // Click the button
  script += `
    tell application "System Events"
      tell process "LuLu"
        set frontmost to true
        delay 0.2
        click button "${buttonName}" of window 1
      end tell
    end tell
    return "ok"
  `;

  try {
    const { stdout } = await execAsync(`osascript -e '${script.replace(/'/g, "'\"'\"'")}'`);
    return stdout.trim() === 'ok';
  } catch (err) {
    console.error('Click error:', err.message);
    return false;
  }
}

module.exports = {
  extractAlertData,
  clickLuLuButton
};
