'use strict';

const { readFile } = require('fs').promises;

/**
 * Extract value for a given iptables flag from a rule line.
 * Uses indexOf-based parsing, no regex.
 */
function extractFlag(line, flag) {
  const idx = line.indexOf(flag);
  if (idx === -1) return null;

  let pos = idx + flag.length;
  while (pos < line.length && line[pos] === ' ') pos++;

  let end = pos;
  while (end < line.length && line[end] !== ' ') end++;

  var value = line.substring(pos, end);
  return value || null;
}

/**
 * Strip CIDR suffix from an IP address.  172.8.47.132/32 -> 172.8.47.132
 */
function stripCidr(addr) {
  if (!addr) return '';
  var idx = addr.indexOf('/');
  return idx !== -1 ? addr.substring(0, idx) : addr;
}

/**
 * Check if a comment is meta-info (not a hospital name).
 *
 * Real-world patterns that should be SKIPPED:
 *   "End VA Mason"               -> section end marker
 *   "END Medstar Georgetown"     -> section end marker
 *   "commented on 2021/11/16"    -> timestamp note
 *   "ensure we can talk to..."   -> infrastructure note
 *   "From Fairview"              -> directional sub-section
 *   "To Fairview"                -> directional sub-section
 *   "to Allina"                  -> directional sub-section
 *   "to North Memorial"          -> directional sub-section
 *   "testing mssql"              -> infrastructure sub-section
 *   "mssql port"                 -> infrastructure sub-section
 *   "non-prod mssql"             -> infrastructure sub-section
 *   "ICMP rules"                 -> ICMP section label
 *   "2021/11/16 ..."             -> date-prefixed comment
 *   "Redoing as SNAT"            -> rework note
 *
 * Things that should NOT be skipped (hospital names):
 *   "uc health vpn"
 *   "Fort Wayne Ortho"
 *   "Memorial Hospital Sheridan"
 *   "UCLA"
 */
function isMetaComment(text) {
  var lower = text.toLowerCase().trim();
  if (!lower) return true;

  // End markers: "End ...", "END ..."
  if (lower.indexOf('end ') === 0) return true;

  // Timestamp notes: "commented on ...", "commented ..."
  if (lower.indexOf('commented') === 0) return true;

  // Infrastructure notes
  if (lower.indexOf('ensure') === 0) return true;
  if (lower.indexOf('note') === 0) return true;
  if (lower.indexOf('todo') === 0) return true;
  if (lower.indexOf('fixme') === 0) return true;

  // Directional sub-sections: "From ...", "To ..."
  if (lower.indexOf('from ') === 0) return true;
  if (lower.indexOf('to ') === 0) return true;

  // Infrastructure sub-sections
  if (lower.indexOf('testing') === 0) return true;
  if (lower.indexOf('mssql') === 0) return true;
  if (lower.indexOf('non-prod') === 0) return true;
  if (lower.indexOf('redoing') === 0) return true;
  if (lower.indexOf('troubleshoot') === 0) return true;

  // ICMP section labels
  if (lower.indexOf('icmp') !== -1) return true;

  // Pure date-like comments: "2021/11/16 ..."
  if (lower[0] >= '0' && lower[0] <= '9') return true;

  // Section markers: "start ..." on its own (the name cleaning handles "Start Hospital")
  // but "start" alone or "start of" is meta
  if (lower === 'start') return true;

  return false;
}

/**
 * Clean a hospital comment string.
 *
 * Strips prefixes like "Start", "Return to pacs", and
 * suffixes like "inbound", "QR to/from Weasis UI", etc.
 *
 * Examples:
 *   "Start OrthoIndy"                           -> "OrthoIndy"
 *   "Return to pacs Juno"                        -> "Juno"
 *   "OrthoIndy QR to/from Weasis UI"            -> "OrthoIndy"
 *   "uc health vpn"                              -> "uc health"
 *   "UCSD inbound retrieve result to mirth"      -> "UCSD"
 *   "Memorial Hospital Sheridan query/retrieve"  -> "Memorial Hospital Sheridan"
 */
function cleanHospitalName(comment) {
  if (!comment) return '';
  var name = comment.trim();
  var lower = name.toLowerCase();

  // Prefixes to strip (ordered longest first)
  var prefixes = [
    'return to pacs ',
    'return-to-pacs ',
    'start '
  ];

  for (var p = 0; p < prefixes.length; p++) {
    if (lower.indexOf(prefixes[p]) === 0) {
      name = name.substring(prefixes[p].length).trim();
      lower = name.toLowerCase();
      break;
    }
  }

  // Suffixes to strip (ordered longest first so we match the most specific)
  var suffixes = [
    'inbound retrieve result to mirth',
    'inbound retrieve result',
    'qr to/from weasis ui',
    'query/retrieve',
    'to/from weasis ui',
    'return to pacs',
    'return-to-pacs',
    'inbound',
    'r2p',
    'vpn'
  ];

  for (var i = 0; i < suffixes.length; i++) {
    var idx = lower.indexOf(suffixes[i]);
    if (idx > 0) {
      name = name.substring(0, idx).trim();
      lower = name.toLowerCase();
    }
  }

  return name;
}

/**
 * Classify a line from rules.v4 using CONTENT-BASED approach.
 *
 * The key insight: comment format varies wildly in real rules files.
 * Single hash, double hash, multi-hash, with/without spaces — all used
 * for hospital name comments. The ONLY reliable way to detect a
 * disabled (commented-out) rule is to check if the content after
 * stripping '#' and whitespace starts with '-A' (an iptables chain append).
 *
 * Examples:
 *   "#Fort Wayne Ortho"            -> { type: 'comment', text: 'Fort Wayne Ortho' }
 *   "# WWMG"                       -> { type: 'comment', text: 'WWMG' }
 *   "## uc health vpn"             -> { type: 'comment', text: 'uc health vpn' }
 *   "####### VA Mason ..."         -> { type: 'comment', text: 'VA Mason ...' }
 *   "# -A PREROUTING ..."          -> { type: 'disabled' }
 *   "#-A PREROUTING ..."           -> { type: 'disabled' }
 *   "-A PREROUTING ..."            -> { type: 'rule', line: '-A PREROUTING ...' }
 *   ""                             -> { type: 'skip' }
 *   "*nat"                         -> { type: 'skip' }  (table declarations)
 *   "COMMIT"                       -> { type: 'skip' }
 *   ":PREROUTING ACCEPT [0:0]"     -> { type: 'skip' }  (chain policy)
 */
function classifyLine(raw) {
  var trimmed = raw.trim();
  if (!trimmed) return { type: 'skip' };

  // Not a comment — check if it's a rule or structural line
  if (trimmed[0] !== '#') {
    // Active iptables rule
    if (trimmed.indexOf('-A ') === 0) {
      return { type: 'rule', line: trimmed };
    }
    // Structural lines: *nat, COMMIT, :PREROUTING ACCEPT [0:0], etc.
    return { type: 'skip' };
  }

  // ── Line starts with '#' ──
  // Strip ALL leading '#' and whitespace to get the content
  var content = trimmed.replace(/^[#\s]+/, '');
  if (!content) return { type: 'skip' };

  // If content starts with '-A' → this is a commented-out (disabled) rule
  if (content.indexOf('-A ') === 0 || content.indexOf('-A\t') === 0) {
    return { type: 'disabled' };
  }

  // Everything else is a comment (hospital name, section header, meta, etc.)
  return { type: 'comment', text: content };
}

/**
 * Parse /etc/iptables/rules.v4 into Return-to-PACS route mappings.
 *
 * Handles real-world patterns from production:
 *   ## uc health vpn            -> hospital name (double-hash)
 *   ####### OrthoIndy QR ...    -> hospital name (multi-hash)
 *   #Fort Wayne Ortho           -> hospital name (single-hash, no space)
 *   # WWMG                      -> hospital name (single-hash, space)
 *   # UCLA                      -> hospital name
 *   ####### End VA Mason        -> meta comment (skipped)
 *   ## commented on 2021/...    -> meta comment (skipped)
 *   ## From Fairview            -> directional sub-section (skipped)
 *   ## testing mssql            -> infra sub-section (skipped)
 *   -A PREROUTING ... DNAT      -> active DNAT rule
 *   -A POSTROUTING ... SNAT     -> active SNAT rule
 *   # -A PREROUTING ...         -> disabled rule (skipped)
 *   #-A PREROUTING ...          -> disabled rule (skipped)
 *   ... -p icmp ...             -> ICMP rule (skipped)
 *
 * Multiple DNAT rules per hospital (different source subnets) are grouped
 * into a single route entry keyed by hospital + gateway port.
 */
function parseRules(content) {
  if (!content || typeof content !== 'string') return [];

  var lines = content.split('\n');
  var currentComment = '';

  // Group routes by "hospital|port" to deduplicate
  var routeMap = {};

  // Collect SNAT rules separately for second-pass matching
  var snatRules = [];

  for (var i = 0; i < lines.length; i++) {
    var classified = classifyLine(lines[i]);

    if (classified.type === 'skip' || classified.type === 'disabled') {
      continue;
    }

    // -- Active section comment --
    if (classified.type === 'comment') {
      var lc = classified.text.toLowerCase();
      // Skip auto-generated timestamps
      if (lc.indexOf('generated') === 0 || lc.indexOf('completed') === 0) continue;
      // Skip meta-comments (End markers, notes, dates, directional, infra)
      if (isMetaComment(classified.text)) continue;
      // Valid hospital name — clean it
      var cleaned = cleanHospitalName(classified.text);
      if (cleaned) {
        currentComment = cleaned;
      }
      continue;
    }

    // -- Active rule --
    var rule = classified.line;

    // Skip ICMP rules entirely — we only care about TCP routes
    if (rule.indexOf('-p icmp') !== -1) continue;

    // DNAT in PREROUTING
    if (rule.indexOf('-A PREROUTING') !== -1 && rule.indexOf('DNAT') !== -1) {
      var dport = extractFlag(rule, '--dport');
      var toDest = extractFlag(rule, '--to-destination');
      var source = extractFlag(rule, '-s');

      if (dport && toDest) {
        var colonIdx = toDest.indexOf(':');
        var targetIp = colonIdx !== -1 ? toDest.substring(0, colonIdx) : toDest;
        var targetPort = colonIdx !== -1 ? toDest.substring(colonIdx + 1) : dport;

        var hospital = currentComment || 'Unknown';
        var key = hospital + '|' + dport;

        if (!routeMap[key]) {
          routeMap[key] = {
            hospital: hospital,
            gatewayPort: dport,
            targetIp: targetIp,
            targetPort: targetPort,
            mirthIp: '',
            sources: new Set()
          };
        }
        if (source) routeMap[key].sources.add(stripCidr(source));
      }
      continue;
    }

    // SNAT in POSTROUTING
    if (rule.indexOf('-A POSTROUTING') !== -1 && rule.indexOf('SNAT') !== -1) {
      var toSource = extractFlag(rule, '--to-source');
      var destIp = extractFlag(rule, '-d');
      var sdport = extractFlag(rule, '--dport');
      var ssource = extractFlag(rule, '-s');

      if (toSource) {
        snatRules.push({
          hospital: currentComment || '',
          mirthIp: stripCidr(toSource),
          destIp: stripCidr(destIp || ''),
          dport: sdport || '',
          source: stripCidr(ssource || '')
        });
      }
      continue;
    }
  }

  // -- Second pass: match SNAT rules to DNAT routes --
  for (var s = 0; s < snatRules.length; s++) {
    var snat = snatRules[s];
    var matched = false;

    // Try matching by port first
    if (snat.dport) {
      var keys = Object.keys(routeMap);
      for (var k = 0; k < keys.length; k++) {
        var route = routeMap[keys[k]];
        if (route.gatewayPort === snat.dport && !route.mirthIp) {
          route.mirthIp = snat.mirthIp;
          matched = true;
          break;
        }
      }
    }

    // Try matching by hospital name
    if (!matched && snat.hospital) {
      var keys2 = Object.keys(routeMap);
      for (var k2 = 0; k2 < keys2.length; k2++) {
        if (keys2[k2].indexOf(snat.hospital + '|') === 0 && !routeMap[keys2[k2]].mirthIp) {
          routeMap[keys2[k2]].mirthIp = snat.mirthIp;
          matched = true;
        }
      }
    }

    // SNAT-only route (no DNAT counterpart) — create if it has a port
    if (!matched && snat.dport && snat.hospital) {
      var skey = snat.hospital + '|' + snat.dport;
      if (!routeMap[skey]) {
        routeMap[skey] = {
          hospital: snat.hospital,
          gatewayPort: snat.dport,
          targetIp: snat.destIp,
          targetPort: snat.dport,
          mirthIp: snat.mirthIp,
          sources: new Set()
        };
        if (snat.source) routeMap[skey].sources.add(snat.source);
      }
    }
  }

  // -- Convert to sorted array --
  var routes = [];
  var allKeys = Object.keys(routeMap);
  for (var r = 0; r < allKeys.length; r++) {
    var rt = routeMap[allKeys[r]];
    routes.push({
      hospital: rt.hospital,
      mirthIp: rt.mirthIp,
      gatewayPort: rt.gatewayPort,
      hospitalIp: rt.targetIp,
      hospitalPort: rt.targetPort,
      sources: Array.from(rt.sources),
      sourceCount: rt.sources.size
    });
  }

  routes.sort(function (a, b) {
    return parseInt(a.gatewayPort, 10) - parseInt(b.gatewayPort, 10);
  });

  return routes;
}

/**
 * Read and parse iptables rules file.
 */
async function fetchRoutes(filePath) {
  var rulesPath = filePath || '/etc/iptables/rules.v4';
  try {
    var content = await readFile(rulesPath, 'utf8');
    return parseRules(content);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return { error: 'Rules file not found: ' + rulesPath };
    }
    if (err.code === 'EACCES') {
      return { error: 'Permission denied: ' + rulesPath + ' (run as root?)' };
    }
    return { error: err.message || 'Cannot read rules file' };
  }
}

module.exports = { parseRules, fetchRoutes };
