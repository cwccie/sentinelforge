/* SentinelForge Dashboard JavaScript */

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// Severity filter
const severityFilter = document.getElementById('severity-filter');
if (severityFilter) {
  severityFilter.addEventListener('change', () => loadData());
}

// Data loading
async function loadData() {
  try {
    const response = await fetch('/dashboard/data');
    const data = await response.json();
    updateMetrics(data.metrics);
    updateAlertTable(data.alerts);
    updateIncidentTable(data.incidents);
    document.getElementById('connection-status').textContent = 'Connected';
    document.getElementById('connection-status').style.color = '#22c55e';
    document.getElementById('last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();
  } catch (error) {
    document.getElementById('connection-status').textContent = 'Connection Error';
    document.getElementById('connection-status').style.color = '#ef4444';
    console.error('Dashboard data load error:', error);
  }
}

function updateMetrics(metrics) {
  document.getElementById('total-alerts').textContent = metrics.total_alerts || 0;
  document.getElementById('total-incidents').textContent = metrics.total_incidents || 0;
  document.getElementById('critical-count').textContent = metrics.severity_distribution.CRITICAL || 0;
  document.getElementById('high-count').textContent = metrics.severity_distribution.HIGH || 0;
  document.getElementById('medium-count').textContent = metrics.severity_distribution.MEDIUM || 0;
  document.getElementById('auto-closed-count').textContent = metrics.status_distribution.auto_closed || 0;
}

function updateAlertTable(alerts) {
  const tbody = document.getElementById('alert-table-body');
  const filter = document.getElementById('severity-filter').value;

  let filtered = alerts;
  if (filter) {
    filtered = alerts.filter(a => a.severity === filter);
  }

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No alerts match the current filter. Submit logs via the API or run demo mode.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(a => `
    <tr>
      <td>${new Date(a.timestamp).toLocaleString()}</td>
      <td><span class="severity-badge sev-${a.severity}">${a.severity}</span></td>
      <td>${a.category || '-'}</td>
      <td>${a.src_ip || '-'}</td>
      <td>${a.mitre_technique_id ? a.mitre_technique_id + ' ' + (a.mitre_technique || '') : '-'}</td>
      <td title="${(a.activity || a.class_name || '').replace(/"/g, '&quot;')}">${(a.activity || a.class_name || '-').substring(0, 60)}</td>
      <td><span class="verdict-badge verdict-${a.verdict}">${a.verdict}</span></td>
      <td>${a.status}</td>
    </tr>
  `).join('');
}

function updateIncidentTable(incidents) {
  const tbody = document.getElementById('incident-table-body');

  if (!incidents || incidents.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No incidents. Run correlation to group related alerts.</td></tr>';
    return;
  }

  tbody.innerHTML = incidents.map(i => `
    <tr style="cursor:pointer" onclick="showTimeline('${i.incident_id}')">
      <td><code>${i.incident_id}</code></td>
      <td><span class="severity-badge sev-${i.severity}">${i.severity}</span></td>
      <td>${i.title.substring(0, 80)}</td>
      <td>${i.alert_ids.length}</td>
      <td>${i.kill_chain_phase || '-'}</td>
      <td>${(i.mitre_tactics || []).join(', ').substring(0, 40) || '-'}</td>
      <td>${i.status}</td>
    </tr>
  `).join('');
}

function showTimeline(incidentId) {
  // Switch to timeline tab
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="timeline"]').classList.add('active');
  document.getElementById('tab-timeline').classList.add('active');

  fetch(`/api/v1/incidents/${incidentId}`)
    .then(r => r.json())
    .then(incident => {
      const container = document.getElementById('timeline-container');
      if (!incident.timeline || incident.timeline.length === 0) {
        container.innerHTML = '<p class="empty-state">No timeline events for this incident.</p>';
        return;
      }
      container.innerHTML = `<h3 style="margin-bottom:1rem;color:#94a3b8">${incident.title}</h3>` +
        incident.timeline.map(e => `
          <div class="timeline-event ${(e.severity || '').toLowerCase()}">
            <div>
              <div style="color:#64748b;font-size:0.8rem">${new Date(e.timestamp).toLocaleString()}</div>
              <div><span class="severity-badge sev-${e.severity}">${e.severity}</span> ${e.tactic ? '<span style="color:#94a3b8">(' + e.tactic + ')</span>' : ''}</div>
              <div style="margin-top:0.25rem">${e.activity || '-'}</div>
            </div>
          </div>
        `).join('');
    })
    .catch(err => {
      document.getElementById('timeline-container').innerHTML = '<p class="empty-state">Error loading timeline.</p>';
    });
}

// WebSocket connection for real-time updates
function connectWebSocket() {
  try {
    const ws = new WebSocket(`ws://${window.location.host}/ws/alerts`);
    ws.onopen = () => {
      document.getElementById('connection-status').textContent = 'Live';
      document.getElementById('connection-status').style.color = '#22c55e';
    };
    ws.onmessage = (event) => {
      loadData(); // Refresh on new data
    };
    ws.onclose = () => {
      document.getElementById('connection-status').textContent = 'Reconnecting...';
      document.getElementById('connection-status').style.color = '#eab308';
      setTimeout(connectWebSocket, 5000);
    };
    ws.onerror = () => {
      // Silently fall back to polling
    };
  } catch (e) {
    // WebSocket not available, polling only
  }
}

// Initialize
loadData();
setInterval(loadData, 5000);
connectWebSocket();
