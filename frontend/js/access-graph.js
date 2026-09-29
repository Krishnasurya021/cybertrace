/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: ADSA 5-Tier Access Pattern Graph Engine
 * Visualizes: APPLICATION -> SOURCE IP -> USERNAME -> SESSION -> RESOURCE
 * Dynamically generated from SentinelDataStore (Single Source of Truth).
 */

const AccessGraphModule = (() => {
  let canvas, ctx;
  let graphData = { nodes: [], edges: [] };
  let nodePositions = {};
  let hoveredNode = null;
  let selectedNode = null;
  let animationInterval = null;
  let searchQuery = '';

  const TYPE_COLORS = {
    'APPLICATION': '#3b82f6',
    'IP': '#00f2fe',
    'USER': '#f59e0b',
    'SESSION': '#a855f7',
    'RESOURCE': '#10b981'
  };

  function buildGraphFromStore() {
    const events = window.SentinelDataStore ? SentinelDataStore.getEvents({ limit: 80 }) : [];
    const nodesMap = {};
    const edgesSet = new Set();
    const edges = [];

    function addNode(id, type, label, isSuspicious = false) {
      if (!nodesMap[id]) {
        nodesMap[id] = { id, type, label, is_suspicious: isSuspicious };
      } else if (isSuspicious) {
        nodesMap[id].is_suspicious = true;
      }
    }

    function addEdge(source, target, isSuspicious = false) {
      const key = `${source}->${target}`;
      if (!edgesSet.has(key)) {
        edgesSet.add(key);
        edges.push({ source, target, is_suspicious: isSuspicious });
      }
    }

    events.forEach(e => {
      const isSus = e.riskLevel === 'HIGH' || e.riskLevel === 'CRITICAL';
      const appId = `APP:${e.applicationId || 'APP_001'}`;
      const appName = e.applicationName || e.applicationId;
      const ipId = `IP:${e.sourceIp || '127.0.0.1'}`;
      const userId = `USER:${e.usernameIdentifier || 'anonymous'}`;
      const sessId = e.authenticationResult === 'SUCCESS' ? `SESS:${e.id}` : null;
      const resId = `RES:${e.resource || '/login'}`;

      addNode(appId, 'APPLICATION', appName);
      addNode(ipId, 'IP', e.sourceIp, isSus);
      addEdge(appId, ipId, isSus);

      addNode(userId, 'USER', e.usernameIdentifier, isSus);
      addEdge(ipId, userId, isSus);

      if (sessId) {
        addNode(sessId, 'SESSION', `sess_${String(e.id).padStart(4, '0')}`);
        addEdge(userId, sessId);
        addNode(resId, 'RESOURCE', e.resource || '/login');
        addEdge(sessId, resId);
      } else {
        addNode(resId, 'RESOURCE', e.resource || '/login', isSus);
        addEdge(userId, resId, isSus);
      }
    });

    graphData = {
      nodes: Object.values(nodesMap),
      edges: edges
    };
  }

  function initGraph() {
    canvas = document.getElementById('accessGraphCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    canvas.removeEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('mousemove', handleMouseMove);

    canvas.removeEventListener('click', handleMouseClick);
    canvas.addEventListener('click', handleMouseClick);

    buildGraphFromStore();
    layoutGraph();
    drawGraph();
  }

  function resizeCanvas() {
    if (!canvas) return;
    const parent = canvas.parentElement;
    canvas.width = (parent ? parent.clientWidth : 900) || 900;
    canvas.height = (parent ? parent.clientHeight : 520) || 520;
    if (graphData.nodes.length) {
      layoutGraph();
      drawGraph();
    }
  }

  function layoutGraph() {
    nodePositions = {};
    const w = canvas.width;
    const h = canvas.height;

    const tiers = {
      'APPLICATION': [],
      'IP': [],
      'USER': [],
      'SESSION': [],
      'RESOURCE': []
    };

    graphData.nodes.forEach(n => {
      if (tiers[n.type]) tiers[n.type].push(n);
    });

    const tierX = {
      'APPLICATION': w * 0.12,
      'IP': w * 0.32,
      'USER': w * 0.52,
      'SESSION': w * 0.72,
      'RESOURCE': w * 0.88
    };

    Object.keys(tiers).forEach(t => {
      const list = tiers[t];
      const count = list.length;
      list.forEach((n, idx) => {
        const spacing = (h - 80) / Math.max(1, count + 1);
        nodePositions[n.id] = {
          x: tierX[t] + (Math.sin(idx) * 10),
          y: 40 + spacing * (idx + 1),
          radius: n.is_suspicious ? 10 : 8,
          color: n.is_suspicious ? '#ef4444' : (TYPE_COLORS[n.type] || '#fff'),
          node: n,
          highlight: false
        };
      });
    });
  }

  function drawGraph() {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Filter highlight by search query
    if (searchQuery) {
      Object.values(nodePositions).forEach(p => {
        const match = p.node.label.toLowerCase().includes(searchQuery) ||
                      p.node.id.toLowerCase().includes(searchQuery);
        p.highlight = match;
      });
    }

    // Draw Edges
    graphData.edges.forEach(e => {
      const p1 = nodePositions[e.source];
      const p2 = nodePositions[e.target];
      if (!p1 || !p2) return;

      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);

      if (e.is_suspicious || (p1.highlight && p2.highlight)) {
        ctx.strokeStyle = 'rgba(239, 68, 68, 0.7)';
        ctx.lineWidth = 2.2;
      } else if (p1.highlight || p2.highlight) {
        ctx.strokeStyle = 'rgba(0, 242, 254, 0.7)';
        ctx.lineWidth = 1.8;
      } else {
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.12)';
        ctx.lineWidth = 1;
      }
      ctx.stroke();
    });

    // Draw Nodes
    Object.values(nodePositions).forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);

      if (p.highlight) {
        ctx.fillStyle = '#00f2fe';
        ctx.shadowBlur = 18;
        ctx.shadowColor = '#00f2fe';
      } else if (p.node.is_suspicious) {
        ctx.fillStyle = '#ef4444';
        ctx.shadowBlur = 14;
        ctx.shadowColor = '#ef4444';
      } else {
        ctx.fillStyle = p.color;
        ctx.shadowBlur = 6;
        ctx.shadowColor = p.color;
      }

      ctx.fill();
      ctx.shadowBlur = 0;

      // Node label
      ctx.font = "10px 'JetBrains Mono'";
      ctx.fillStyle = p.highlight || p.node.is_suspicious ? '#fff' : '#94a3b8';
      ctx.fillText(p.node.label.substring(0, 14), p.x + p.radius + 5, p.y + 3);
    });

    // Tooltip for hovered node
    if (hoveredNode) {
      const p = nodePositions[hoveredNode.id];
      if (p) {
        const text = `[${p.node.type}] ${p.node.label}`;
        ctx.font = "11px 'Inter'";
        const tw = ctx.measureText(text).width;
        ctx.fillStyle = 'rgba(7, 11, 19, 0.95)';
        ctx.fillRect(p.x - 6, p.y - 28, tw + 14, 20);
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.4)';
        ctx.strokeRect(p.x - 6, p.y - 28, tw + 14, 20);
        ctx.fillStyle = '#00f2fe';
        ctx.fillText(text, p.x, p.y - 14);
      }
    }
  }

  function handleMouseMove(e) {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    hoveredNode = null;
    for (let nid in nodePositions) {
      const p = nodePositions[nid];
      const dx = p.x - mx;
      const dy = p.y - my;
      if (Math.sqrt(dx * dx + dy * dy) <= p.radius + 4) {
        hoveredNode = p.node;
        break;
      }
    }
    drawGraph();
  }

  function handleMouseClick(e) {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    for (let nid in nodePositions) {
      const p = nodePositions[nid];
      const dx = p.x - mx;
      const dy = p.y - my;
      if (Math.sqrt(dx * dx + dy * dy) <= p.radius + 5) {
        showNodeDetails(p.node);
        return;
      }
    }
  }

  function showNodeDetails(node) {
    selectedNode = node;
    const events = window.SentinelDataStore ? SentinelDataStore.getEvents({ search: node.label, limit: 15 }) : [];

    const existing = document.getElementById('graphNodeDetailModal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'graphNodeDetailModal';
    modal.className = 'alert-modal-backdrop active';
    modal.innerHTML = `
      <div class="alert-modal-card" style="max-width:680px; border-color:${TYPE_COLORS[node.type] || 'var(--cyan-primary)'};">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <div>
            <span class="badge badge-monitoring" style="margin-bottom:4px; display:inline-block;">${node.type} ENTITY</span>
            <h3 style="font-family:var(--font-display); font-size:18px; color:#fff;">${node.label}</h3>
          </div>
          <button onclick="document.getElementById('graphNodeDetailModal').remove()" style="background:transparent; border:none; color:#94a3b8; font-size:18px; cursor:pointer;">✕</button>
        </div>

        <div style="background:#070b13; padding:12px; border-radius:8px; margin-bottom:14px; font-size:12px;">
          <div>Node ID: <code style="color:var(--cyan-primary);">${node.id}</code></div>
          <div style="margin-top:4px;">Threat Status: <b style="color:${node.is_suspicious ? '#ef4444' : '#10b981'};">${node.is_suspicious ? 'ANOMALOUS / THREAT DETECTED' : 'NORMAL / CLEAN BASELINE'}</b></div>
          <div style="margin-top:4px;">Associated Events Logged: <b style="color:#fff;">${events.length}</b></div>
        </div>

        <div class="card-title" style="font-size:13px; margin-bottom:8px;">Related Authentication Telemetry</div>
        <div class="table-responsive" style="max-height:260px; overflow-y:auto;">
          <table class="soc-table">
            <thead>
              <tr>
                <th>TIME</th>
                <th>RESULT</th>
                <th>IP</th>
                <th>USER</th>
                <th>RESOURCE</th>
                <th>RISK</th>
              </tr>
            </thead>
            <tbody>
              ${events.map(ev => `
                <tr>
                  <td style="font-family:'JetBrains Mono'; font-size:11px;">${ev.timestamp}</td>
                  <td><span class="badge ${ev.authenticationResult === 'SUCCESS' ? 'badge-safe' : 'badge-suspicious'}">${ev.authenticationResult}</span></td>
                  <td style="font-family:'JetBrains Mono';">${ev.sourceIp}</td>
                  <td style="font-family:'JetBrains Mono'; color:#38bdf8;">${ev.usernameIdentifier}</td>
                  <td><code>${ev.resource || '/login'}</code></td>
                  <td><span class="score-badge" style="background:rgba(0,242,254,0.1); color:var(--cyan-primary);">${ev.riskScore}/100</span></td>
                </tr>
              `).join('') || '<tr><td colspan="6" style="text-align:center; padding:12px;">No records.</td></tr>'}
            </tbody>
          </table>
        </div>

        <div style="display:flex; justify-content:flex-end; margin-top:16px;">
          <button onclick="document.getElementById('graphNodeDetailModal').remove()" class="btn-dismiss">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  function runTraversal(algo = 'bfs') {
    if (animationInterval) clearInterval(animationInterval);

    // Reset highlights
    Object.values(nodePositions).forEach(p => p.highlight = false);
    drawGraph();

    showToast(`Executing ADSA ${algo.toUpperCase()} Graph Traversal...`, 'info');

    // Simple BFS/DFS on client graphData
    const adj = {};
    graphData.nodes.forEach(n => adj[n.id] = []);
    graphData.edges.forEach(e => {
      if (adj[e.source]) adj[e.source].push(e.target);
    });

    const startNode = graphData.nodes[0] ? graphData.nodes[0].id : null;
    if (!startNode) return;

    const visited = [];
    const queue = [startNode];
    const visitedSet = new Set([startNode]);

    if (algo === 'bfs') {
      while (queue.length > 0) {
        const curr = queue.shift();
        visited.push(curr);
        (adj[curr] || []).forEach(nbr => {
          if (!visitedSet.has(nbr)) {
            visitedSet.add(nbr);
            queue.push(nbr);
          }
        });
      }
    } else {
      // DFS
      const stack = [startNode];
      while (stack.length > 0) {
        const curr = stack.pop();
        if (!visited.includes(curr)) {
          visited.push(curr);
          (adj[curr] || []).forEach(nbr => {
            if (!visitedSet.has(nbr)) {
              visitedSet.add(nbr);
              stack.push(nbr);
            }
          });
        }
      }
    }

    let step = 0;
    animationInterval = setInterval(() => {
      if (step >= visited.length) {
        clearInterval(animationInterval);
        showToast(`${algo.toUpperCase()} Traversal complete: Visited ${visited.length} entities`, 'success');
        return;
      }
      const nid = visited[step];
      if (nodePositions[nid]) {
        nodePositions[nid].highlight = true;
        drawGraph();
      }
      step++;
    }, 120);
  }

  function searchGraph(query) {
    searchQuery = (query || '').toLowerCase().trim();
    drawGraph();
  }

  return {
    initGraph,
    runTraversal,
    searchGraph,
    init: () => {
      const btnBfs = document.getElementById('btnRunBFS');
      if (btnBfs) btnBfs.addEventListener('click', () => runTraversal('bfs'));

      const btnDfs = document.getElementById('btnRunDFS');
      if (btnDfs) btnDfs.addEventListener('click', () => runTraversal('dfs'));

      const graphSearch = document.getElementById('graphSearchInput');
      if (graphSearch) {
        graphSearch.addEventListener('input', (e) => searchGraph(e.target.value));
      }

      if (window.SentinelDataStore) {
        SentinelDataStore.on('dataChanged', () => {
          if (SentinelState.currentView === 'access-graph') {
            buildGraphFromStore();
            layoutGraph();
            drawGraph();
          }
        });
      }
    }
  };
})();

if (typeof window !== 'undefined') {
  window.AccessGraphModule = AccessGraphModule;
  document.addEventListener('DOMContentLoaded', AccessGraphModule.init);
}
