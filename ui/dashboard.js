'use strict';

const blessed = require('blessed');
const { formatBytes, formatUptime } = require('../parsers/swanctl');

// ── Helpers ──────────────────────────────────────────────────────

function pad(str, width) {
  const s = String(str);
  const visible = s.replace(/\{[^}]+\}/g, '');

  if (visible.length > width) {
    if (s === visible) return s.substring(0, width - 1) + '\u2026';
    return visible.substring(0, width - 1) + '\u2026';
  }

  const padding = Math.max(0, width - visible.length);
  return s + ' '.repeat(padding);
}

function renderHeader(headers, widths) {
  let line = '';
  for (let i = 0; i < headers.length; i++) {
    line += pad(headers[i], widths[i] || 15);
  }
  const totalWidth = widths.reduce(function (a, b) { return a + b; }, 0);
  const sep = '\u2500'.repeat(Math.min(totalWidth, 200));
  return '{bold}' + line + '{/bold}\n{cyan-fg}' + sep + '{/cyan-fg}';
}

function buildRow(cells, widths) {
  var line = '';
  for (var i = 0; i < cells.length; i++) {
    line += pad(cells[i] != null ? String(cells[i]) : '-', widths[i] || 15);
  }
  return line;
}

function renderRows(rows, widths) {
  if (rows.length === 0) {
    return '{yellow-fg} No data available{/yellow-fg}';
  }
  const lines = [];
  for (const row of rows) {
    lines.push(buildRow(row, widths));
  }
  return lines.join('\n');
}

// ── Dashboard ────────────────────────────────────────────────────

function createDashboard() {
  const screen = blessed.screen({
    smartCSR: true,
    title: 'GateWatch - Gateway Monitor',
    fullUnicode: true
  });

  // ── Stored data for search & detail ──

  var storedTunnels = [];
  var storedRoutes = [];
  var storedConnections = [];
  var storedCurrentTraffic = null;
  var storedPreviousTraffic = null;
  var storedDeltaSeconds = 0;
  var storedTrafficRoutes = [];
  var searchFilter = '';
  var filteredRoutes = []; // maps 1:1 to routes list items

  // ── Header ──

  const appHeader = blessed.box({
    top: 0,
    left: 0,
    width: '100%',
    height: 1,
    tags: true,
    content: ' {bold}GATEWATCH{/bold} \u2502 Gateway Monitor',
    style: { fg: 'white', bg: 'blue' }
  });

  // ── Footer ──

  const footer = blessed.box({
    bottom: 0,
    left: 0,
    width: '100%',
    height: 1,
    tags: true,
    style: { fg: 'white', bg: 'blue' }
  });

  // ── Search input ──

  var searchInput = blessed.textbox({
    bottom: 0,
    left: 0,
    width: '100%',
    height: 1,
    tags: true,
    keys: true,
    inputOnFocus: true,
    style: { fg: 'white', bg: 'magenta' },
    hidden: true
  });

  // ── Detail popup ──

  var detailBox = blessed.box({
    top: 'center',
    left: 'center',
    width: '75%',
    height: '75%',
    tags: true,
    border: { type: 'line' },
    style: {
      fg: 'white',
      border: { fg: 'yellow' },
      label: { fg: 'yellow', bold: true }
    },
    scrollable: true,
    alwaysScroll: true,
    keys: true,
    vi: true,
    mouse: true,
    scrollbar: {
      ch: '\u2588',
      style: { bg: 'yellow' }
    },
    hidden: true
  });

  // ── Panel factory ──

  function makePanel(label, topPos, heightVal, asList) {
    var container = blessed.box({
      top: topPos,
      left: 0,
      width: '100%',
      height: heightVal,
      label: ' ' + label + ' ',
      tags: true,
      border: { type: 'line' },
      style: {
        border: { fg: 'cyan' },
        label: { fg: 'cyan', bold: true },
        focus: {
          border: { fg: 'green' },
          label: { fg: 'green' }
        }
      }
    });

    var headerBox = blessed.box({
      parent: container,
      top: 0,
      left: 1,
      right: 1,
      height: 2,
      tags: true,
      style: { fg: 'white' }
    });

    var contentBox;
    if (asList) {
      contentBox = blessed.list({
        parent: container,
        top: 2,
        left: 1,
        right: 1,
        bottom: 0,
        tags: true,
        keys: true,
        vi: true,
        mouse: true,
        scrollable: true,
        style: {
          selected: { bg: 'blue' },
          item: { fg: 'white' }
        },
        scrollbar: {
          ch: '\u2588',
          style: { bg: 'cyan' }
        }
      });
    } else {
      contentBox = blessed.box({
        parent: container,
        top: 2,
        left: 1,
        right: 1,
        bottom: 0,
        tags: true,
        scrollable: true,
        alwaysScroll: true,
        keys: true,
        vi: true,
        mouse: true,
        scrollbar: {
          ch: '\u2588',
          style: { bg: 'cyan' }
        }
      });
    }

    return { container: container, header: headerBox, content: contentBox };
  }

  // 4 panels — routes uses list mode for selection
  var vpn = makePanel('VPN TUNNELS', 1, '25%-1');
  var routes = makePanel('INBOUND NAT RULES', '25%', '25%', true);
  var conns = makePanel('ACTIVE CONNECTIONS', '50%', '25%');
  var traffic = makePanel('TRAFFIC PER HOSPITAL', '75%', '25%-1');

  screen.append(appHeader);
  screen.append(vpn.container);
  screen.append(routes.container);
  screen.append(conns.container);
  screen.append(traffic.container);
  screen.append(footer);
  screen.append(searchInput);
  screen.append(detailBox);

  // ── Tab navigation ──

  var contentPanels = [vpn.content, routes.content, conns.content, traffic.content];
  var activeIdx = 0;

  function focusPanel(idx) {
    activeIdx = idx;
    contentPanels[activeIdx].focus();
    screen.render();
  }

  screen.key(['tab'], function () {
    if (!detailBox.hidden || !searchInput.hidden) return;
    focusPanel((activeIdx + 1) % contentPanels.length);
  });

  screen.key(['S-tab'], function () {
    if (!detailBox.hidden || !searchInput.hidden) return;
    focusPanel((activeIdx - 1 + contentPanels.length) % contentPanels.length);
  });

  // ── Filter helper ──

  function matchesFilter(text) {
    if (!searchFilter) return true;
    return text.toLowerCase().indexOf(searchFilter) !== -1;
  }

  // ── VPN matching: find VPN tunnel that matches a hospital name ──

  function findMatchingVpn(hospitalName) {
    if (!Array.isArray(storedTunnels)) return null;
    var normHosp = hospitalName.toLowerCase().replace(/[-_\s]+/g, '');

    for (var i = 0; i < storedTunnels.length; i++) {
      var t = storedTunnels[i];
      if (!t.name) continue;
      var vpnNorm = t.name.toLowerCase().replace(/[-_\s]+/g, '');

      // Exact match
      if (vpnNorm === normHosp) return t;

      // Containment (either direction)
      if (normHosp.indexOf(vpnNorm) !== -1 || vpnNorm.indexOf(normHosp) !== -1) return t;

      // All VPN name parts found in hospital name
      var parts = t.name.toLowerCase().split('-');
      var allMatch = true;
      for (var p = 0; p < parts.length; p++) {
        if (normHosp.indexOf(parts[p]) === -1) {
          allMatch = false;
          break;
        }
      }
      if (allMatch && parts.length > 0) return t;
    }
    return null;
  }

  // ── Render: VPN Tunnels ──

  var vpnHeaders = ['Connection', 'Remote IP', 'Status', 'Bytes In', 'Bytes Out', 'Uptime'];
  var vpnWidths = [22, 18, 12, 14, 14, 12];

  function renderVpn() {
    vpn.header.setContent(renderHeader(vpnHeaders, vpnWidths));

    if (storedTunnels && storedTunnels.error) {
      vpn.content.setContent('{red-fg}Error: ' + storedTunnels.error + '{/red-fg}');
      return;
    }

    var rows = [];
    var data = Array.isArray(storedTunnels) ? storedTunnels : [];
    for (var i = 0; i < data.length; i++) {
      var t = data[i];
      if (!matchesFilter(t.name || '')) continue;

      var status;
      if (t.status === 'UP') {
        status = '{green-fg}\u25CF UP{/green-fg}';
      } else if (t.status === 'DEGRADED') {
        status = '{yellow-fg}\u25CF DEGR{/yellow-fg}';
      } else {
        status = '{red-fg}\u25CF DOWN{/red-fg}';
      }

      rows.push([
        t.name,
        t.remoteIp || '-',
        status,
        formatBytes(t.bytesIn),
        formatBytes(t.bytesOut),
        t.uptime || '-'
      ]);
    }

    vpn.content.setContent(renderRows(rows, vpnWidths));
  }

  // ── Render: Routes (list mode for selection) ──

  var routeHeaders = ['Hospital', 'Mirth IP', 'GW Port', 'DNAT Target', 'Port', 'Sources'];
  var routeWidths = [30, 16, 10, 16, 8, 8];

  function renderRoutes() {
    routes.header.setContent(renderHeader(routeHeaders, routeWidths));

    if (storedRoutes && storedRoutes.error) {
      routes.content.setItems(['{red-fg}Error: ' + storedRoutes.error + '{/red-fg}']);
      filteredRoutes = [];
      return;
    }

    filteredRoutes = [];
    var items = [];
    var data = Array.isArray(storedRoutes) ? storedRoutes : [];
    for (var i = 0; i < data.length; i++) {
      var r = data[i];
      if (!matchesFilter(r.hospital || '')) continue;

      filteredRoutes.push(r);
      var srcCount = r.sourceCount || (r.sources ? r.sources.length : 0);
      var srcStr = srcCount > 0 ? '{cyan-fg}' + srcCount + '{/cyan-fg}' : '-';
      items.push(buildRow(
        [r.hospital, r.mirthIp || '-', r.gatewayPort, r.hospitalIp, r.hospitalPort, srcStr],
        routeWidths
      ));
    }

    if (items.length === 0) {
      routes.content.setItems(['{yellow-fg} No matching routes{/yellow-fg}']);
    } else {
      routes.content.setItems(items);
    }
  }

  // ── Render: Connections ──

  var connHeaders = ['Hospital', 'Port', 'Active', 'Remote Peers'];
  var connWidths = [24, 10, 10, 48];

  function renderConnections() {
    conns.header.setContent(renderHeader(connHeaders, connWidths));

    if (storedConnections && storedConnections.error) {
      conns.content.setContent('{red-fg}Error: ' + storedConnections.error + '{/red-fg}');
      return;
    }

    // Route lookup: port -> hospital
    var routeMap = {};
    if (Array.isArray(storedRoutes)) {
      for (var j = 0; j < storedRoutes.length; j++) {
        routeMap[storedRoutes[j].gatewayPort] = storedRoutes[j].hospital;
      }
    }

    var byPort = {};
    var connList = Array.isArray(storedConnections) ? storedConnections : [];
    for (var k = 0; k < connList.length; k++) {
      var c = connList[k];
      if (!byPort[c.localPort]) {
        byPort[c.localPort] = { count: 0, peers: new Set() };
      }
      byPort[c.localPort].count++;
      byPort[c.localPort].peers.add(c.peerIp);
    }

    var ports = Object.keys(byPort).sort(function (a, b) {
      return parseInt(a, 10) - parseInt(b, 10);
    });

    var routePorts = new Set(Object.keys(routeMap));
    var relevantPorts = ports.filter(function (p) {
      return routePorts.size === 0 || routePorts.has(p);
    });

    var displayPorts = relevantPorts.length > 0 ? relevantPorts : ports;

    var rows = [];
    for (var i = 0; i < displayPorts.length; i++) {
      var port = displayPorts[i];
      var info = byPort[port];
      var hospital = routeMap[port] || '-';
      if (!matchesFilter(hospital)) continue;

      var peersArr = Array.from(info.peers);
      var peersStr = peersArr.slice(0, 5).join(', ') + (peersArr.length > 5 ? ' ...' : '');

      var countStr = info.count > 0
        ? '{green-fg}' + info.count + '{/green-fg}'
        : '{yellow-fg}0{/yellow-fg}';

      rows.push([hospital, port, countStr, peersStr]);
    }

    conns.content.setContent(renderRows(rows, connWidths));
  }

  // ── Render: Traffic ──

  var trafficHeaders = ['Hospital', 'Port', 'In KB/s', 'Out KB/s', 'Total In', 'Total Out'];
  var trafficWidths = [24, 10, 12, 12, 14, 14];

  function renderTraffic() {
    traffic.header.setContent(renderHeader(trafficHeaders, trafficWidths));

    if (storedCurrentTraffic && storedCurrentTraffic.error) {
      traffic.content.setContent('{red-fg}Error: ' + storedCurrentTraffic.error + '{/red-fg}');
      return;
    }

    var routeMap = {};
    if (Array.isArray(storedTrafficRoutes)) {
      for (var j = 0; j < storedTrafficRoutes.length; j++) {
        routeMap[storedTrafficRoutes[j].gatewayPort] = storedTrafficRoutes[j].hospital;
      }
    }

    var ports = Object.keys(storedCurrentTraffic || {}).sort(function (a, b) {
      return parseInt(a, 10) - parseInt(b, 10);
    });

    var rows = [];
    for (var i = 0; i < ports.length; i++) {
      var port = ports[i];
      var curr = storedCurrentTraffic[port];
      var prev = storedPreviousTraffic ? storedPreviousTraffic[port] : null;
      var hospital = routeMap[port] || '-';
      if (!matchesFilter(hospital)) continue;

      var inRate = '{white-fg}-{/white-fg}';
      var outRate = '{white-fg}-{/white-fg}';

      if (prev && storedDeltaSeconds > 0) {
        var inDelta = Math.max(0, curr.bytesReceived - prev.bytesReceived);
        var outDelta = Math.max(0, curr.bytesSent - prev.bytesSent);
        var inKBs = (inDelta / 1024 / storedDeltaSeconds).toFixed(1);
        var outKBs = (outDelta / 1024 / storedDeltaSeconds).toFixed(1);

        inRate = parseFloat(inKBs) > 0
          ? '{green-fg}' + inKBs + '{/green-fg}'
          : '{yellow-fg}' + inKBs + '{/yellow-fg}';
        outRate = parseFloat(outKBs) > 0
          ? '{green-fg}' + outKBs + '{/green-fg}'
          : '{yellow-fg}' + outKBs + '{/yellow-fg}';
      }

      rows.push([
        hospital,
        port,
        inRate,
        outRate,
        formatBytes(curr.bytesReceived),
        formatBytes(curr.bytesSent)
      ]);
    }

    traffic.content.setContent(renderRows(rows, trafficWidths));
  }

  // ── Render all panels ──

  function renderAllPanels() {
    renderVpn();
    renderRoutes();
    renderConnections();
    renderTraffic();
  }

  // ── Detail popup ──

  function showDetail(route) {
    var vpnMatch = findMatchingVpn(route.hospital);

    var text = '';

    // Title
    text += '{bold}{yellow-fg}\u2500\u2500 ' + route.hospital.toUpperCase() + ' \u2500\u2500{/yellow-fg}{/bold}\n\n';

    // Flow diagram
    text += '{bold}FLOW:{/bold}\n\n';
    text += '  {cyan-fg}Hospital PACS{/cyan-fg}';
    if (vpnMatch) text += '  (' + (vpnMatch.remoteIp || '?') + ')';
    text += '\n';
    text += '      {cyan-fg}\u2502{/cyan-fg}\n';
    text += '      {cyan-fg}\u25BC{/cyan-fg} VPN tunnel';
    if (vpnMatch) text += ' ({bold}' + vpnMatch.name + '{/bold})';
    text += '\n';
    text += '      {cyan-fg}\u2502{/cyan-fg}\n';
    text += '  {cyan-fg}Gateway{/cyan-fg} port {bold}' + route.gatewayPort + '{/bold}  (52.6.114.199)\n';
    text += '      {cyan-fg}\u2502{/cyan-fg}\n';
    text += '      {cyan-fg}\u25BC{/cyan-fg} DNAT\n';
    text += '      {cyan-fg}\u2502{/cyan-fg}\n';
    text += '  {cyan-fg}Mirth{/cyan-fg} ' + (route.hospitalIp || '?') + ':' + (route.hospitalPort || '?') + '\n';
    if (route.mirthIp) {
      text += '      {cyan-fg}\u2502{/cyan-fg}\n';
      text += '      {cyan-fg}\u25B2{/cyan-fg} SNAT as ' + route.mirthIp + '\n';
    }
    text += '\n';

    // VPN info
    text += '{bold}VPN TUNNEL:{/bold}\n';
    if (vpnMatch) {
      var vpnStatus = vpnMatch.status === 'UP'
        ? '{green-fg}\u25CF UP{/green-fg}'
        : '{red-fg}\u25CF DOWN{/red-fg}';
      text += '  Status:    ' + vpnStatus + '\n';
      text += '  Remote IP: ' + (vpnMatch.remoteIp || '-') + '\n';
      text += '  Uptime:    ' + (vpnMatch.uptime || '-') + '\n';
      text += '  Bytes:     ' + formatBytes(vpnMatch.bytesIn) + ' in / ' + formatBytes(vpnMatch.bytesOut) + ' out\n';
    } else {
      text += '  {yellow-fg}No matching VPN tunnel found{/yellow-fg}\n';
      text += '  {yellow-fg}(may connect without VPN or via different name){/yellow-fg}\n';
    }
    text += '\n';

    // NAT rule
    text += '{bold}NAT RULE:{/bold}\n';
    text += '  GW Port:    ' + route.gatewayPort + '\n';
    text += '  DNAT:       \u2192 ' + (route.hospitalIp || '?') + ':' + (route.hospitalPort || '?') + '\n';
    if (route.mirthIp) {
      text += '  SNAT:       \u2190 ' + route.mirthIp + '\n';
    }
    var srcCount = route.sourceCount || (route.sources ? route.sources.length : 0);
    text += '  Sources:    ' + srcCount + ' network' + (srcCount !== 1 ? 's' : '') + '\n';
    if (route.sources && route.sources.length > 0) {
      for (var s = 0; s < route.sources.length; s++) {
        text += '              ' + route.sources[s] + '\n';
      }
    }
    text += '\n';

    // Active connections on this port
    text += '{bold}CONNECTIONS:{/bold}\n';
    var connCount = 0;
    var connPeers = [];
    if (Array.isArray(storedConnections)) {
      for (var c = 0; c < storedConnections.length; c++) {
        if (storedConnections[c].localPort === route.gatewayPort) {
          connCount++;
          if (connPeers.indexOf(storedConnections[c].peerIp) === -1) {
            connPeers.push(storedConnections[c].peerIp);
          }
        }
      }
    }
    if (connCount > 0) {
      text += '  Active: {green-fg}' + connCount + '{/green-fg}\n';
      text += '  Peers:  ' + connPeers.join(', ') + '\n';
    } else {
      text += '  {yellow-fg}No active connections on port ' + route.gatewayPort + '{/yellow-fg}\n';
    }
    text += '\n';

    // Traffic on this port
    text += '{bold}TRAFFIC:{/bold}\n';
    if (storedCurrentTraffic && storedCurrentTraffic[route.gatewayPort]) {
      var ct = storedCurrentTraffic[route.gatewayPort];
      text += '  Total In:  ' + formatBytes(ct.bytesReceived) + '\n';
      text += '  Total Out: ' + formatBytes(ct.bytesSent) + '\n';
    } else {
      text += '  {yellow-fg}No traffic data for port ' + route.gatewayPort + '{/yellow-fg}\n';
    }

    detailBox.label = ' ' + route.hospital + ' (ESC to close) ';
    detailBox.setContent(text);
    detailBox.setScrollPerc(0);
    detailBox.show();
    detailBox.focus();
    screen.render();
  }

  // ── Event: Enter on routes list → show detail ──

  routes.content.on('select', function (item, index) {
    var route = filteredRoutes[index];
    if (route) showDetail(route);
  });

  // ── Event: ESC → close detail or clear search ──

  detailBox.key(['escape', 'q'], function () {
    detailBox.hide();
    focusPanel(activeIdx);
    screen.render();
  });

  screen.key(['escape'], function () {
    if (!detailBox.hidden) {
      detailBox.hide();
      focusPanel(activeIdx);
      screen.render();
      return;
    }
    if (searchFilter) {
      searchFilter = '';
      renderAllPanels();
      updateFooter();
      focusPanel(activeIdx);
      screen.render();
    }
  });

  // ── Search: event-based (submit = Enter, cancel = Escape) ──

  searchInput.on('submit', function (value) {
    searchFilter = (value || '').trim().toLowerCase();
    searchInput.hide();
    renderAllPanels();
    updateFooter();
    focusPanel(activeIdx);
    screen.render();
  });

  searchInput.on('cancel', function () {
    searchInput.hide();
    updateFooter();
    focusPanel(activeIdx);
    screen.render();
  });

  screen.key(['/'], function () {
    if (!detailBox.hidden) return;
    if (!searchInput.hidden) return;
    searchInput.show();
    searchInput.setValue('');
    searchInput.focus();
    searchInput.readInput();
    screen.render();
  });

  // ── Event: quit ──

  screen.key(['C-c'], function () {
    screen.destroy();
    process.exit(0);
  });

  screen.key(['q'], function () {
    if (!searchInput.hidden) return;
    if (!detailBox.hidden) return; // handled by detailBox key handler
    screen.destroy();
    process.exit(0);
  });

  focusPanel(0);

  // ── Update functions (public API from index.js) ──

  function updateVpn(tunnels) {
    storedTunnels = tunnels;
    renderVpn();
  }

  function updateRoutes(routeData) {
    storedRoutes = routeData;
    renderRoutes();
  }

  function updateConnections(connections, routeData) {
    storedConnections = connections;
    renderConnections();
  }

  function updateTraffic(currentTraffic, previousTraffic, deltaSeconds, routeData) {
    storedCurrentTraffic = currentTraffic;
    storedPreviousTraffic = previousTraffic;
    storedDeltaSeconds = deltaSeconds;
    storedTrafficRoutes = routeData;
    renderTraffic();
  }

  function updateFooter() {
    var now = new Date();
    var ts = now.toLocaleTimeString();
    var line = ' {bold}TAB{/bold} switch  {bold}\u2191\u2193{/bold} scroll  {bold}/{/bold} search  {bold}Enter{/bold} detail  {bold}q{/bold} quit';
    if (searchFilter) {
      line += '  \u2502  {magenta-fg}Filter: "' + searchFilter + '"{/magenta-fg} (ESC clear)';
    }
    line += '  \u2502  Last refresh: ' + ts;
    footer.setContent(line);
  }

  function updateTimestamp() {
    updateFooter();
  }

  function render() {
    screen.render();
  }

  return {
    screen: screen,
    updateVpn: updateVpn,
    updateRoutes: updateRoutes,
    updateConnections: updateConnections,
    updateTraffic: updateTraffic,
    updateTimestamp: updateTimestamp,
    render: render
  };
}

module.exports = { createDashboard };
