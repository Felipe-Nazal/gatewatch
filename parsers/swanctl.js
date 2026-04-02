'use strict';

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

/**
 * Format seconds into human-readable uptime string.
 */
function formatUptime(seconds) {
  if (typeof seconds !== 'number' || isNaN(seconds) || seconds < 0) return '-';
  if (seconds < 60) return seconds + 's';
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return m + 'm ' + s + 's';
  }
  if (seconds < 86400) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return h + 'h ' + m + 'm';
  }
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  return d + 'd ' + h + 'h';
}

/**
 * Format byte count into human-readable string.
 */
function formatBytes(bytes) {
  if (typeof bytes !== 'number' || isNaN(bytes)) return '-';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

/**
 * Extract a numeric value followed by " bytes" from a line.
 * Uses indexOf-based extraction instead of regex.
 */
function extractBytes(line) {
  const idx = line.indexOf(' bytes');
  if (idx === -1) return 0;

  // Walk backwards from the position to find the start of the number
  let end = idx;
  let start = end - 1;
  while (start >= 0 && line[start] >= '0' && line[start] <= '9') {
    start--;
  }
  start++;

  if (start >= end) return 0;
  return parseInt(line.substring(start, end), 10) || 0;
}

/**
 * Extract IP address after '@' character.
 * Format: remote '...' @ 203.0.113.10[4500]
 */
function extractRemoteIp(line) {
  const atIdx = line.indexOf('@ ');
  if (atIdx === -1) return '';

  const afterAt = line.substring(atIdx + 2).trim();
  // IP ends at '[' or whitespace
  let end = 0;
  while (end < afterAt.length && afterAt[end] !== '[' && afterAt[end] !== ' ') {
    end++;
  }
  return afterAt.substring(0, end);
}

/**
 * Extract "established Ns ago" value.
 */
function extractEstablishedSeconds(line) {
  const keyword = 'established ';
  const idx = line.indexOf(keyword);
  if (idx === -1) return -1;

  const afterKeyword = line.substring(idx + keyword.length);
  const sIdx = afterKeyword.indexOf('s ');
  if (sIdx === -1) return -1;

  const numStr = afterKeyword.substring(0, sIdx);
  const value = parseInt(numStr, 10);
  return isNaN(value) ? -1 : value;
}

/**
 * Parse output of `swanctl --list-sas` into structured tunnel data.
 *
 * Output format (indentation-based hierarchy):
 *   conn-name: #N, ESTABLISHED, IKEv2, ...
 *     local  '...' @ LOCAL_IP[PORT]
 *     remote '...' @ REMOTE_IP[PORT]
 *     established Ns ago, ...
 *     child-sa: #N, reqid N, INSTALLED, TUNNEL, ...
 *       installed Ns ago, ...
 *       in  cXXXX,  NNNN bytes, ...
 *       out cXXXX,  NNNN bytes, ...
 *       local  CIDR
 *       remote CIDR
 */
function parseSas(output) {
  if (!output || typeof output !== 'string') return [];

  const tunnels = [];
  const lines = output.split('\n');
  let current = null;
  let inChildSa = false;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.trim()) continue;

    // Measure indentation (spaces/tabs)
    const indent = raw.length - raw.trimStart().length;
    const trimmed = raw.trim();

    // Top-level IKE SA: indent 0, contains '#' and ':'
    if (indent === 0 && trimmed.indexOf('#') !== -1 && trimmed.indexOf(':') !== -1) {
      if (current) tunnels.push(current);

      const colonIdx = trimmed.indexOf(':');
      const name = trimmed.substring(0, colonIdx).trim();

      current = {
        name: name,
        status: trimmed.indexOf('ESTABLISHED') !== -1 ? 'UP' : 'DOWN',
        remoteIp: '',
        bytesIn: 0,
        bytesOut: 0,
        uptime: '',
        uptimeSeconds: 0
      };
      inChildSa = false;
      continue;
    }

    if (!current) continue;

    // Remote address line (IKE level)
    if (!inChildSa && trimmed.indexOf('remote') === 0 && trimmed.indexOf('@') !== -1) {
      current.remoteIp = extractRemoteIp(trimmed);
      continue;
    }

    // Established time (IKE level, before any child SA)
    if (!inChildSa && trimmed.indexOf('established ') === 0) {
      const secs = extractEstablishedSeconds(trimmed);
      if (secs >= 0) {
        current.uptimeSeconds = secs;
        current.uptime = formatUptime(secs);
      }
      continue;
    }

    // Child SA header line: contains 'reqid'
    if (trimmed.indexOf('reqid') !== -1) {
      inChildSa = true;
      if (trimmed.indexOf('INSTALLED') === -1) {
        // Child SA not installed means tunnel is effectively down
        if (current.status === 'UP') current.status = 'DEGRADED';
      }
      continue;
    }

    // Bytes in (child SA level)
    if (inChildSa && trimmed.indexOf('in ') === 0 && trimmed.indexOf('bytes') !== -1) {
      current.bytesIn += extractBytes(trimmed);
      continue;
    }

    // Bytes out (child SA level)
    if (inChildSa && trimmed.indexOf('out ') === 0 && trimmed.indexOf('bytes') !== -1) {
      current.bytesOut += extractBytes(trimmed);
      continue;
    }
  }

  if (current) tunnels.push(current);

  // ── Deduplicate by connection name ──
  // During IKE rekeying, multiple SAs coexist for the same connection.
  // Merge them: keep newest (lowest uptimeSeconds), sum all bytes.
  var byName = {};
  for (var t = 0; t < tunnels.length; t++) {
    var tunnel = tunnels[t];
    if (!byName[tunnel.name]) {
      byName[tunnel.name] = {
        name: tunnel.name,
        status: tunnel.status,
        remoteIp: tunnel.remoteIp,
        bytesIn: tunnel.bytesIn,
        bytesOut: tunnel.bytesOut,
        uptime: tunnel.uptime,
        uptimeSeconds: tunnel.uptimeSeconds
      };
    } else {
      var existing = byName[tunnel.name];
      // Sum bytes from all SAs
      existing.bytesIn += tunnel.bytesIn;
      existing.bytesOut += tunnel.bytesOut;
      // Keep info from the newest SA (lowest uptime = most recent)
      if (tunnel.uptimeSeconds < existing.uptimeSeconds) {
        existing.remoteIp = tunnel.remoteIp;
        existing.uptime = tunnel.uptime;
        existing.uptimeSeconds = tunnel.uptimeSeconds;
      }
      // If any SA is UP, connection is UP
      if (tunnel.status === 'UP' && existing.status !== 'UP') {
        existing.status = 'UP';
      }
    }
  }

  var deduped = [];
  var names = Object.keys(byName);
  for (var n = 0; n < names.length; n++) {
    deduped.push(byName[names[n]]);
  }
  return deduped;
}

/**
 * Execute swanctl --list-sas and return parsed tunnels.
 * Returns array of tunnels on success, or { error: string } on failure.
 */
async function fetchTunnels() {
  try {
    const { stdout } = await execAsync('sudo swanctl --list-sas', { timeout: 10000 });
    return parseSas(stdout);
  } catch (err) {
    if (err.code === 'ENOENT' || (err.message && err.message.indexOf('not found') !== -1)) {
      return { error: 'swanctl not found — is strongSwan installed?' };
    }
    if (err.killed) {
      return { error: 'swanctl timed out' };
    }
    return { error: err.message || 'Unknown error' };
  }
}

module.exports = { parseSas, fetchTunnels, formatBytes, formatUptime };
