'use strict';

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

/**
 * Extract port from an address string like "172.8.47.132:4107" or "[::]:22".
 * Uses lastIndexOf to handle IPv6.
 */
function extractPort(addr) {
  if (!addr) return '';
  const lastColon = addr.lastIndexOf(':');
  if (lastColon === -1) return '';
  return addr.substring(lastColon + 1);
}

/**
 * Extract IP from an address string like "172.8.47.132:4107".
 * Returns everything before the last colon.
 */
function extractIp(addr) {
  if (!addr) return '';
  const lastColon = addr.lastIndexOf(':');
  if (lastColon === -1) return addr;
  return addr.substring(0, lastColon);
}

/**
 * Extract process name from ss users column.
 * Format: users:(("java",pid=12345,fd=67))
 */
function extractProcessName(line) {
  const marker = 'users:((';
  const idx = line.indexOf(marker);
  if (idx === -1) return '';

  const afterMarker = line.substring(idx + marker.length);
  // Process name is in quotes: "java"
  if (afterMarker[0] === '"') {
    const endQuote = afterMarker.indexOf('"', 1);
    if (endQuote !== -1) return afterMarker.substring(1, endQuote);
  }
  return '';
}

/**
 * Parse `ss -lntp` output into listening port information.
 *
 * Format:
 *   State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
 *   LISTEN 0       128     0.0.0.0:4107        0.0.0.0:*          users:(("java",...))
 */
function parseListening(output) {
  if (!output) return [];

  const listeners = [];
  const lines = output.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.indexOf('LISTEN') === -1) continue;

    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;

    // Column indices: 0=State, 1=Recv-Q, 2=Send-Q, 3=Local, 4=Peer, 5+=Process
    const localAddr = parts[3];
    const port = extractPort(localAddr);
    if (!port) continue;

    const processName = extractProcessName(line);

    listeners.push({
      port: port,
      address: localAddr,
      process: processName
    });
  }

  return listeners;
}

/**
 * Parse `ss -antp` output into active (ESTAB) connection list.
 *
 * Format:
 *   State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
 *   ESTAB  0       0       172.8.47.132:4107   10.20.30.40:54321  users:(("java",...))
 */
function parseConnections(output) {
  if (!output) return [];

  const connections = [];
  const lines = output.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.indexOf('ESTAB') === -1) continue;

    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;

    const localAddr = parts[3];
    const peerAddr = parts[4];

    const localPort = extractPort(localAddr);
    const peerIp = extractIp(peerAddr);
    const peerPort = extractPort(peerAddr);

    if (!localPort) continue;

    connections.push({
      localPort: localPort,
      localIp: extractIp(localAddr),
      peerIp: peerIp,
      peerPort: peerPort,
      process: extractProcessName(line)
    });
  }

  return connections;
}

/**
 * Parse `ss -antpi` output to extract per-connection byte counters.
 * The extended TCP info appears on the line(s) following each connection entry.
 *
 * Format:
 *   ESTAB  0  0  172.8.47.132:4107  10.20.30.40:54321  users:((...))
 *        cubic ... bytes_sent:12345 bytes_received:67890 ...
 *
 * Returns object keyed by local port: { [port]: { bytesSent, bytesReceived, connections } }
 */
function parseTrafficInfo(output) {
  if (!output) return {};

  const traffic = {};
  const lines = output.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.indexOf('ESTAB') === -1) continue;

    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;

    const localPort = extractPort(parts[3]);
    if (!localPort) continue;

    // Look ahead for the TCP info line (starts with whitespace, contains 'bytes_')
    let bytesSent = 0;
    let bytesReceived = 0;

    for (let j = i + 1; j < Math.min(i + 4, lines.length); j++) {
      const infoLine = lines[j];
      // Stop if we hit another connection entry
      if (infoLine.indexOf('ESTAB') !== -1 ||
          infoLine.indexOf('LISTEN') !== -1 ||
          infoLine.indexOf('TIME-WAIT') !== -1 ||
          infoLine.indexOf('CLOSE-WAIT') !== -1) {
        break;
      }

      // Extract bytes_sent:N
      const sentIdx = infoLine.indexOf('bytes_sent:');
      if (sentIdx !== -1) {
        const afterSent = infoLine.substring(sentIdx + 11);
        const endNum = afterSent.search(/[^0-9]/);
        bytesSent = parseInt(afterSent.substring(0, endNum === -1 ? undefined : endNum), 10) || 0;
      }

      // Extract bytes_received:N
      const recvIdx = infoLine.indexOf('bytes_received:');
      if (recvIdx !== -1) {
        const afterRecv = infoLine.substring(recvIdx + 15);
        const endNum = afterRecv.search(/[^0-9]/);
        bytesReceived = parseInt(afterRecv.substring(0, endNum === -1 ? undefined : endNum), 10) || 0;
      }
    }

    if (!traffic[localPort]) {
      traffic[localPort] = { bytesSent: 0, bytesReceived: 0, connections: 0 };
    }
    traffic[localPort].bytesSent += bytesSent;
    traffic[localPort].bytesReceived += bytesReceived;
    traffic[localPort].connections += 1;
  }

  return traffic;
}

// ── Fetch functions ──────────────────────────────────────────────

async function fetchListeners() {
  try {
    const { stdout } = await execAsync('ss -lntp', { timeout: 5000 });
    return parseListening(stdout);
  } catch (err) {
    return { error: err.message || 'Failed to run ss -lntp' };
  }
}

async function fetchConnections() {
  try {
    const { stdout } = await execAsync('ss -antp', { timeout: 5000 });
    return parseConnections(stdout);
  } catch (err) {
    return { error: err.message || 'Failed to run ss -antp' };
  }
}

async function fetchTraffic() {
  try {
    const { stdout } = await execAsync('ss -antpi', { timeout: 5000 });
    return parseTrafficInfo(stdout);
  } catch (err) {
    return { error: err.message || 'Failed to run ss -antpi' };
  }
}

module.exports = {
  parseListening,
  parseConnections,
  parseTrafficInfo,
  fetchListeners,
  fetchConnections,
  fetchTraffic
};
