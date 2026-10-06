import { MeshController } from './mesh-controller.js?v=mesh-v1';
import { RelayMap } from './relay-map.js?v=mesh-map-v2';
const fmt = value => { const n = Number(value) || 0; return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(2)} MiB`; };
const states = { OFF: 'OFF', CONNECTING: 'Connecting', ACTIVE: 'Connected', RECONNECTING: 'Reconnecting', WAITING_PEER: 'Waiting for peers', PAUSED_AI: 'Paused for AI', OFF_LIMIT: 'Limit reached', ERROR: 'Connection error' };
const $ = id => document.getElementById(id);

export function setupRelayUI({ openHome = () => {} } = {}) {
  const relay = new MeshController();
  if (!$('relayOn')) return relay;
  const map = new RelayMap($('relayMap'));
  let lastError = '', lastErrorAt = 0;
  const render = snapshot => {
    $('relayState').textContent = states[snapshot.state] || snapshot.state;
    $('relayState').dataset && ($('relayState').dataset.state = snapshot.state);
    $('relayOn').disabled = snapshot.requested; $('relayOff').disabled = !snapshot.requested;
    $('relayReason').textContent = snapshot.reason || 'Node is OFF. Join when you want to help relay public data.';
    const connected = snapshot.requested ? snapshot.peers.filter(p => p.connected) : [];
    $('relayPeers').textContent = String(connected.length);
    const commonConnections = snapshot.requested && Array.isArray(snapshot.commonConnections) ? snapshot.commonConnections : [];
    const connectedCommons = commonConnections.filter(connection => connection.connected);
    const commonConnected = connectedCommons.length > 0;
    const sourceLabel = connection => connection.sourceId || connection.nodeId?.slice(0, 10) || connection.id || 'Common';
    $('relayCommonPeers').textContent = String(connectedCommons.length);
    $('relayCommonPeerHint').textContent = commonConnected ? `${connectedCommons.map(sourceLabel).join(', ')} · WSS connected` : 'This browser’s Common WSS connections';
    $('relayCommonList').replaceChildren();
    for (const connection of commonConnections) {
      const row = document.createElement('div'); row.className = 'relay-peer';
      row.setAttribute('data-common-connected', String(!!connection.connected));
      row.setAttribute('data-common-source', sourceLabel(connection));
      const name = document.createElement('strong'); name.textContent = sourceLabel(connection);
      const state = document.createElement('span'); state.textContent = connection.connected ? 'WSS connected' : 'WSS disconnected / connecting';
      if (connection.connected && connection.browserSignatureVerified) state.textContent += connection.endpointVerified ? ' · endpoint signature verified' : ' · Common signature verified';
      if (connection.remoteOrigin) row.title = connection.remoteOrigin;
      row.append(name, state); $('relayCommonList').append(row);
    }
    if (!commonConnections.length) {
      const row = document.createElement('p'); row.textContent = snapshot.requested ? 'Waiting for a Common WSS connection.' : 'No Common connections while Node is OFF.';
      $('relayCommonList').append(row);
    }
    const capacity = snapshot.capacities, circuitLimit = capacity?.endpointCircuits ?? '—';
    // Occupancy includes pending opens for admission; a live connection count does not.
    const endpointOpening = commonConnected ? (snapshot.pendingInbound || 0) + (snapshot.pendingOutbound || 0) : 0;
    const endpointOpen = commonConnected ? Math.max(0, (snapshot.endpointCircuits || 0) - endpointOpening) : 0;
    const opening = snapshot.requested ? snapshot.pendingHandshakes || 0 : 0;
    const openCircuits = snapshot.requested ? Math.max(0, (snapshot.circuits || 0) - opening) : 0;
    const transitOpen = snapshot.requested ? Math.max(0, (snapshot.transitCircuits || 0) - (snapshot.pendingTransit || 0)) : 0;
    $('relayCommonCircuits').textContent = String(endpointOpen);
    $('relayCommonCircuitHint').textContent = `Open across Common links · ${endpointOpening} opening`;
    // Before the first config fetch, show the configured browser ceiling; the legacy admission fallback is not an observed gateway limit.
    const commonLimit = !relay.config ? relay.maxCommonConnections : snapshot.connectionLimits?.commons ?? relay.config?.limits?.maxCommonConnections ?? 20;
    $('relayConnectionLimits').textContent = `Browser peer limit: ${snapshot.connectionLimits?.peers ?? relay.config?.limits?.maxPeers ?? 20} · Common attachment limit: ${commonLimit} · Shared browser circuit policy: 40 total across all Common links and browser peers · ${capacity ? `Endpoint circuit limit: ${circuitLimit} · Browser circuit limit: ${capacity.circuits} · Each Common shares ${capacity.common.circuits} circuits across up to ${capacity.common.maxSessions} sessions · capacity includes pending opens` : 'Circuit capacity appears after connection'}`;
    $('relayReceiptsCount').textContent = `${snapshot.acknowledgedCount || 0}`;
    $('relayReceiptsBytes').textContent = `${fmt(snapshot.acknowledgedBytes)} acknowledged by peers`;
    $('relayCache').textContent = `${fmt(snapshot.queuedBytes)} / 512 KiB`;
    $('relayCacheEntries').textContent = `${openCircuits} open circuits · ${opening} opening · ${transitOpen} transit · RAM only`;
    $('relayGatewayRx').textContent = fmt(snapshot.nativeReceivedBytes);
    $('relayPeerRx').textContent = fmt(snapshot.receivedBytes);
    $('relayPeerTx').textContent = fmt(snapshot.sentBytes);
    $('relayBudget').textContent = `${fmt(snapshot.totalBytes)} / 100 MiB`;
    $('relayAi').textContent = snapshot.aiLoad === 'idle' ? `Normal · up to ${capacity?.circuits ?? 40} circuits share send ≤48 KiB/s` : snapshot.aiLoad === 'generating' ? 'AI generating · send ≤24 KiB/s · up to 1 circuit' : 'AI loading / benchmarking · transfers paused';
    const rows = snapshot.sources || [];
    $('relayFreshness').textContent = rows.length ? rows.map(s => `${s.sourceId || s.nodeId?.slice(0, 10) || 'Common'} · advertised ${new Date(s.issuedAt).toLocaleTimeString()} · ${Date.now() >= s.expiresAt ? 'EXPIRED' : `${Math.max(0, Math.floor((Date.now() - s.issuedAt) / 1000))}s old`}`).join(' / ') : snapshot.requested ? 'Waiting for a Common advertisement.' : 'No Common connection while OFF.';
    $('relayNativeState').textContent = commonConnected ? `${connectedCommons.length} Common WSS connection${connectedCommons.length === 1 ? '' : 's'}` : 'Common WSS disconnected';
    $('relaySignalState').textContent = snapshot.discovery?.enabled && snapshot.requested ?
      `${snapshot.discovery.connectedGateways} introduction gateway${snapshot.discovery.connectedGateways === 1 ? '' : 's'} connected · ${snapshot.discovery.verifiedEndpoints} verified Common candidates` :
      snapshot.signalConnected ? 'Signaling connected' : 'Signaling disconnected';
    $('relayCredit').textContent = fmt(snapshot.nativeCreditBytes);
    $('relayStream').textContent = fmt(snapshot.streamForwardedBytes);
    $('relayRtc').textContent = (snapshot.rtcStats || []).map(r => `${r.peerId.slice(0, 8)}: ${fmt(r.bytesSent)} sent / ${fmt(r.bytesReceived)} received (${r.path})`).join(' · ') || 'No RTC measurement yet';
    const errors = Object.entries(snapshot.sourceErrors || {}).map(([id, error]) => `${id}: ${error}`);
    if (lastError && Date.now() - lastErrorAt < 60000) errors.push(lastError);
    $('relayErrors').textContent = errors.join(' · '); $('relayErrors').hidden = !errors.length;
    $('relayMapCaption').textContent = !snapshot.requested ? 'Your connection appears here when you turn Node ON.' : `${connected.length} browser peer${connected.length === 1 ? '' : 's'} · ${connected.filter(p => !p.geo).length} in the location-unavailable area${snapshot.selfGeo ? ` · you: ${snapshot.selfGeo.label}` : ' · your location: unavailable'}. Pins show country estimates, not precise locations.`;
    $('relayPeerList').replaceChildren();
    if (!snapshot.peers.length) { const item = document.createElement('p'); item.textContent = snapshot.requested ? 'Keep this page visible. Waiting for another participating browser.' : 'No connections while Node is OFF.'; $('relayPeerList').append(item); }
    for (const peer of snapshot.peers) {
      const item = document.createElement('div'); item.className = 'relay-peer';
      const name = document.createElement('strong'); name.textContent = `${peer.geo?.label || 'Location unknown'} · ${peer.peerId.slice(0, 8)}`;
      const path = document.createElement('span'); path.textContent = `${peer.connected ? 'WebRTC' : 'Connecting'} · ${peer.path === 'TURN' ? 'TURN relay' : peer.path === 'direct' ? 'Direct' : 'Route unconfirmed'}`;
      item.append(name, path); $('relayPeerList').append(item);
    }
    $('relayReceipts').replaceChildren();
    for (const receipt of (snapshot.receipts || []).slice(-5).reverse()) {
      const row = document.createElement('li'); row.textContent = `${new Date(receipt.at).toLocaleTimeString()} · ${receipt.peerId.slice(0, 8)} · circuit ${receipt.circuitId?.slice(0, 8) || '—'} / seq ${receipt.seq} · ${fmt(receipt.rawBytes)} · ${receipt.path}`;
      $('relayReceipts').append(row);
    }
    $('relayNoReceipts').hidden = !!snapshot.receipts?.length;
    map.set(snapshot);
  };
  relay.addEventListener('stats', event => render(event.detail));
  relay.addEventListener('state', event => render(event.detail));
  relay.addEventListener('event', event => {
    const telemetry = event.detail;
    if (telemetry.name === 'chunk_accepted' && telemetry.from !== 'native') map.transfer({ ...telemetry, name: 'received', peerId: telemetry.from });
    else if (telemetry.name === 'chunk_sent') map.transfer({ ...telemetry, name: 'forwarded' });
    else if (telemetry.name === 'acknowledged') map.transfer(telemetry);
    if (['chunk_accepted', 'chunk_sent', 'acknowledged'].includes(event.detail.name)) $('relayDataRoute').textContent = `WebRTC · ${event.detail.path || 'route unconfirmed'}`;
    if (event.detail.name === 'error' && !event.detail.fatal) { lastError = event.detail.message || (event.detail.code === 'invalid_receipt' ? 'A receipt did not match an awaiting transfer and was ignored.' : `A mesh message was ignored (${event.detail.code || 'invalid message'}).`); lastErrorAt = Date.now(); $('relayErrors').textContent = lastError; $('relayErrors').hidden = false; }
  });
  $('relayOn').onclick = () => relay.start().catch(error => { $('relayReason').textContent = error.message; });
  $('relayOff').onclick = () => relay.stop();
  $('navRelay').onclick = () => { openHome(); $('relayPanel').scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  render(relay.snapshot());
  return relay;
}
