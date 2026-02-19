/**
 * CyberSentinel – SOC Dashboard Client
 * WebSocket client with live rendering, auto-scroll, and reconnection.
 */

const MAX_LOG_ENTRIES = 200;
const MAX_ALERT_ENTRIES = 100;
const MAX_ACTION_ENTRIES = 150;
const RECONNECT_BASE_DELAY = 1000;
const RECONNECT_MAX_DELAY = 30000;

// ── State ─────────────────────────────────────────────────
let ws = null;
let reconnectDelay = RECONNECT_BASE_DELAY;
let logCount = 0;
let alertCount = 0;
let actionCount = 0;

// ── DOM Elements ──────────────────────────────────────────
const logStream = document.getElementById('logStream');
const alertStream = document.getElementById('alertStream');
const actionStream = document.getElementById('actionStream');
const connectionStatus = document.getElementById('connectionStatus');
const modelStatus = document.getElementById('modelStatus');
const logCounter = document.getElementById('logCounter');
const alertCounter = document.getElementById('alertCounter');
const actionCounter = document.getElementById('actionCounter');

// Stats elements
const totalLogs = document.getElementById('totalLogs');
const totalAlerts = document.getElementById('totalAlerts');
const countLow = document.getElementById('countLow');
const countMedium = document.getElementById('countMedium');
const countHigh = document.getElementById('countHigh');
const countCritical = document.getElementById('countCritical');
const activeThreats = document.getElementById('activeThreats');
const suppressedCount = document.getElementById('suppressedCount');
const wsClients = document.getElementById('wsClients');

// ── WebSocket Connection ──────────────────────────────────
function connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('✅ WebSocket connected');
        setConnectionStatus(true);
        reconnectDelay = RECONNECT_BASE_DELAY;
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleMessage(msg);
        } catch (e) {
            console.error('Failed to parse message:', e);
        }
    };

    ws.onclose = () => {
        console.log('❌ WebSocket disconnected');
        setConnectionStatus(false);
        scheduleReconnect();
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        ws.close();
    };
}

function scheduleReconnect() {
    console.log(`🔄 Reconnecting in ${reconnectDelay / 1000}s...`);
    setTimeout(() => {
        reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_DELAY);
        connect();
    }, reconnectDelay);
}

function setConnectionStatus(connected) {
    connectionStatus.className = `connection-status ${connected ? 'connected' : 'disconnected'}`;
    connectionStatus.querySelector('.status-text').textContent = connected ? 'Connected' : 'Disconnected';
}

// ── Message Handler ───────────────────────────────────────
function handleMessage(msg) {
    switch (msg.type) {
        case 'log':
            renderLog(msg.data);
            break;
        case 'alert':
            renderAlert(msg.data);
            break;
        case 'stats':
            updateStats(msg.data);
            break;
    }
}

// ── Render Log Entry ──────────────────────────────────────
function renderLog(log) {
    // Remove empty state
    const empty = logStream.querySelector('.empty-state');
    if (empty) empty.remove();

    const entry = document.createElement('div');
    entry.className = `log-entry${log.is_anomaly ? ' anomaly' : ''}`;

    const time = formatTimestamp(log.timestamp);
    const severityClass = log.severity || 'NORMAL';

    entry.innerHTML = `
        <span class="timestamp">${time}</span>
        <span class="source-ip">${log.src_ip || '—'}</span>
        <span class="event-type">${log.event_type || '—'}</span>
        <span class="message">${escapeHtml(log.message || '')}</span>
    `;

    logStream.prepend(entry);
    logCount++;
    logCounter.textContent = `${logCount} entries`;

    // Cap entries
    while (logStream.children.length > MAX_LOG_ENTRIES) {
        logStream.removeChild(logStream.lastChild);
    }
}

// ── Render Alert Entry ────────────────────────────────────
function renderAlert(alert) {
    const empty = alertStream.querySelector('.empty-state');
    if (empty) empty.remove();

    const entry = document.createElement('div');
    entry.className = `alert-entry severity-${alert.severity}`;

    const time = formatTimestamp(alert.timestamp);

    let actionsHtml = '';
    if (alert.actions && alert.actions.length > 0) {
        actionsHtml = alert.actions.map(a => {
            renderAction(a, alert.severity);
            return '';
        }).join('');
    }

    entry.innerHTML = `
        <div class="alert-header">
            <span class="alert-severity ${alert.severity}">${alert.severity}</span>
            <span class="alert-score">Score: ${alert.threat_score}/100</span>
        </div>
        <div class="alert-body">
            <span class="alert-ip">${alert.src_ip} → ${alert.dst_ip}</span>
            <div class="alert-message">${escapeHtml(alert.message || '')}</div>
        </div>
        <div class="alert-time">${time} · ${alert.event_type || 'unknown'}</div>
    `;

    alertStream.prepend(entry);
    alertCount++;
    alertCounter.textContent = `${alertCount} alerts`;

    while (alertStream.children.length > MAX_ALERT_ENTRIES) {
        alertStream.removeChild(alertStream.lastChild);
    }
}

// ── Render Action Entry ───────────────────────────────────
function renderAction(action, severity) {
    const empty = actionStream.querySelector('.empty-state');
    if (empty) empty.remove();

    const entry = document.createElement('div');
    const actionType = action.type || 'unknown';
    entry.className = `action-entry ${actionType}`;

    const icons = {
        log_event: '📝',
        generate_alert: '🔔',
        increase_monitoring: '🔍',
        block_ip: '🚫',
        isolate_node: '🔒',
        escalate: '🚨',
        notify_soc: '📢',
    };

    entry.innerHTML = `
        <span>${icons[actionType] || '⚡'}</span>
        <span>${escapeHtml(action.description || actionType)}</span>
    `;

    actionStream.prepend(entry);
    actionCount++;
    actionCounter.textContent = `${actionCount} actions`;

    while (actionStream.children.length > MAX_ACTION_ENTRIES) {
        actionStream.removeChild(actionStream.lastChild);
    }
}

// ── Update Stats ──────────────────────────────────────────
function updateStats(stats) {
    animateValue(totalLogs, stats.total_logs || 0);
    animateValue(totalAlerts, stats.total_alerts || 0);

    const sc = stats.severity_counts || {};
    animateValue(countLow, sc.LOW || 0);
    animateValue(countMedium, sc.MEDIUM || 0);
    animateValue(countHigh, sc.HIGH || 0);
    animateValue(countCritical, sc.CRITICAL || 0);

    animateValue(activeThreats, stats.active_threats || 0);
    animateValue(suppressedCount, stats.suppressed_count || 0);

    if (wsClients) {
        wsClients.textContent = `${stats.ws_clients || 0} clients connected`;
    }

    // Model status
    if (stats.model_loaded) {
        modelStatus.className = 'model-status loaded';
        modelStatus.querySelector('span:last-child').textContent = 'Model: Active';
    }
}

function animateValue(element, newValue) {
    const current = parseInt(element.textContent) || 0;
    if (current !== newValue) {
        element.textContent = newValue;
        element.style.transform = 'scale(1.15)';
        element.style.transition = 'transform 0.2s ease';
        setTimeout(() => {
            element.style.transform = 'scale(1)';
        }, 200);
    }
}

// ── Utilities ─────────────────────────────────────────────
function formatTimestamp(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        return d.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    } catch {
        return ts.substring(11, 19);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ── Keepalive Ping ────────────────────────────────────────
setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send('ping');
    }
}, 30000);

// ── Initialize ────────────────────────────────────────────
connect();
