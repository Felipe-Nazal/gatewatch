#!/usr/bin/env node
'use strict';

const { createDashboard } = require('./ui/dashboard');
const { fetchTunnels } = require('./parsers/swanctl');
const { fetchRoutes } = require('./parsers/iptables');
const { fetchConnections, fetchTraffic } = require('./parsers/sockets');

// ── Configuration ────────────────────────────────────────────────

const REFRESH_INTERVAL = parseInt(process.env.GATEWATCH_INTERVAL, 10) || 5000;
const RULES_FILE = process.env.GATEWATCH_RULES || '/etc/iptables/rules.v4';

// ── Main ─────────────────────────────────────────────────────────

async function main() {
  const dashboard = createDashboard();

  let routes = [];
  let previousTraffic = null;
  let previousTimestamp = null;

  async function refresh() {
    const now = Date.now();

    // Run all parsers in parallel
    const [tunnels, newRoutes, connections, traffic] = await Promise.all([
      fetchTunnels(),
      fetchRoutes(RULES_FILE),
      fetchConnections(),
      fetchTraffic()
    ]);

    // Keep last valid routes for cross-referencing
    if (Array.isArray(newRoutes)) {
      routes = newRoutes;
    }

    // Calculate time delta for traffic rate
    const deltaSeconds = previousTimestamp ? (now - previousTimestamp) / 1000 : 0;

    // Update all panels
    dashboard.updateVpn(tunnels);
    dashboard.updateRoutes(newRoutes);
    dashboard.updateConnections(connections, routes);
    dashboard.updateTraffic(traffic, previousTraffic, deltaSeconds, routes);
    dashboard.updateTimestamp();
    dashboard.render();

    // Store snapshot for next rate calculation
    if (traffic && !traffic.error) {
      previousTraffic = traffic;
      previousTimestamp = now;
    }
  }

  // Initial load
  await refresh();

  // Periodic refresh
  const timer = setInterval(refresh, REFRESH_INTERVAL);

  // Cleanup on exit
  process.on('SIGINT', function () {
    clearInterval(timer);
    process.exit(0);
  });
  process.on('SIGTERM', function () {
    clearInterval(timer);
    process.exit(0);
  });
}

main().catch(function (err) {
  console.error('Fatal:', err.message);
  process.exit(1);
});
