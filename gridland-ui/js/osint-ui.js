/**
 * OSINT and Network Analyzer Window Logic
 * Handles SSE streaming and UI updates for Phase 5 windows
 */

// Track active streams
let activeOsintStreamId = null;
let activeAnalyzeStreamId = null;

// ==========================================================================
// Window Toggle Functions
// ==========================================================================

function toggleOsintWindow() {
    const win = document.getElementById('osintWindow');
    if (win.style.display === 'none') {
        win.style.display = 'block';
        makeDraggable(win, document.getElementById('osintTitleBar'));
    } else {
        win.style.display = 'none';
    }
    hideToolsMenu();
}

function toggleAnalyzeWindow() {
    const win = document.getElementById('analyzeWindow');
    if (win.style.display === 'none') {
        win.style.display = 'block';
        makeDraggable(win, document.getElementById('analyzeTitleBar'));
    } else {
        win.style.display = 'none';
    }
    hideToolsMenu();
}

function openApiTests() {
    window.open('api-tests.html', '_blank');
    hideToolsMenu();
}

function hideToolsMenu() {
    const menu = document.getElementById('toolsMenu');
    if (menu) menu.style.display = 'none';
}

// ==========================================================================
// OSINT Intelligence Functions
// ==========================================================================

function startOsintGathering() {
    const ip = document.getElementById('osintIp').value.trim();

    if (!ip || !isValidIP(ip)) {
        alert('Please enter a valid IP address');
        return;
    }

    // Show progress
    const progress = document.getElementById('osintProgress');
    progress.style.display = 'block';
    document.getElementById('osintProgressFill').style.width = '0%';
    document.getElementById('osintProgressStatus').textContent = 'Starting OSINT gathering...';

    // Disable/enable buttons
    document.getElementById('startOsintBtn').disabled = true;
    document.getElementById('stopOsintBtn').disabled = false;

    // Clear previous results
    clearOsintResults();

    // Start SSE stream
    activeOsintStreamId = window.gridlandAPI.startOsintStream(ip, {
        onPhase: handleOsintPhase,
        onProgress: handleOsintProgress,
        onComplete: handleOsintComplete,
        onError: handleOsintError
    });
}

function stopOsintGathering() {
    if (activeOsintStreamId) {
        window.gridlandAPI.stopStream(activeOsintStreamId);
        activeOsintStreamId = null;
    }
    resetOsintButtons();
}

function handleOsintPhase(data) {
    const statusEl = document.getElementById('osintProgressStatus');
    statusEl.textContent = `${data.phase}: ${data.status}`;

    // Update specific sections based on phase
    if (data.phase === 'search_urls' && data.status === 'complete' && data.data) {
        renderSearchUrls(data.data.urls);
    }

    if (data.phase === 'google_dorks' && data.status === 'complete' && data.data) {
        renderDorks(data.data.dorks);
    }

    if (data.phase === 'geolocation' && data.status === 'complete' && data.data) {
        renderGeoInfo(data.data);
    }
}

function handleOsintProgress(progress, phase, status) {
    const fill = document.getElementById('osintProgressFill');
    fill.style.width = `${progress}%`;
}

function handleOsintComplete(osintData) {
    const progress = document.getElementById('osintProgress');
    document.getElementById('osintProgressStatus').textContent = 'Complete!';
    document.getElementById('osintProgressFill').style.width = '100%';

    // Render full report
    if (osintData.report) {
        const reportEl = document.getElementById('reportJson');
        reportEl.innerHTML = `<pre>${JSON.stringify(osintData.report, null, 2)}</pre>`;
    }

    // Reset after delay
    setTimeout(() => {
        progress.style.display = 'none';
        resetOsintButtons();
    }, 1500);
}

function handleOsintError(error) {
    document.getElementById('osintProgressStatus').textContent = `Error: ${error.message}`;
    setTimeout(() => {
        document.getElementById('osintProgress').style.display = 'none';
        resetOsintButtons();
    }, 2000);
}

function resetOsintButtons() {
    document.getElementById('startOsintBtn').disabled = false;
    document.getElementById('stopOsintBtn').disabled = true;
}

function clearOsintResults() {
    document.getElementById('searchUrlList').innerHTML = '<div class="placeholder-text">Loading...</div>';
    document.getElementById('dorkList').innerHTML = '<div class="placeholder-text">Loading...</div>';
    document.getElementById('geoInfo').innerHTML = '<div class="placeholder-text">Loading...</div>';
    document.getElementById('reportJson').innerHTML = '<pre class="placeholder-text">Loading...</pre>';
}

function renderSearchUrls(urls) {
    const container = document.getElementById('searchUrlList');
    let html = '';

    for (const [name, url] of Object.entries(urls)) {
        html += `
            <div class="url-item">
                <span class="url-name">${name}</span>
                <a href="${url}" target="_blank" class="url-link" title="${url}">${url}</a>
                <button class="mac-button copy-btn small" onclick="copyToClipboard('${url}')">Copy</button>
            </div>
        `;
    }

    container.innerHTML = html || '<div class="placeholder-text">No URLs generated</div>';
}

function renderDorks(dorks) {
    const container = document.getElementById('dorkList');
    let html = '';

    for (const dork of dorks) {
        html += `
            <div class="dork-item">
                <a href="${dork.url}" target="_blank" class="url-link" title="${dork.query}">${dork.query}</a>
                <button class="mac-button copy-btn small" onclick="copyToClipboard('${dork.query}')">Copy</button>
            </div>
        `;
    }

    container.innerHTML = html || '<div class="placeholder-text">No dorks generated</div>';
}

function renderGeoInfo(geo) {
    const container = document.getElementById('geoInfo');

    const rows = [
        ['IP Address', geo.ip],
        ['City', geo.city || 'Unknown'],
        ['Region', geo.region || 'Unknown'],
        ['Country', geo.country || 'Unknown'],
        ['Coordinates', geo.latitude && geo.longitude ? `${geo.latitude}, ${geo.longitude}` : 'Unknown'],
        ['Organization', geo.org || 'Unknown'],
    ];

    let html = '';
    for (const [label, value] of rows) {
        html += `<div class="geo-row"><span class="geo-label">${label}:</span><span class="geo-value">${value}</span></div>`;
    }

    if (geo.google_maps_url) {
        html += `<div class="geo-row"><span class="geo-label">Map:</span><span class="geo-value"><a href="${geo.google_maps_url}" target="_blank">View on Google Maps</a></span></div>`;
    }

    container.innerHTML = html;
}

// ==========================================================================
// Network Analyzer Functions
// ==========================================================================

function startNetworkAnalysis() {
    const ip = document.getElementById('analyzeIp').value.trim();

    if (!ip || !isValidIP(ip)) {
        alert('Please enter a valid IP address');
        return;
    }

    // Show progress
    const progress = document.getElementById('analyzeProgress');
    progress.style.display = 'block';
    document.getElementById('analyzeProgressFill').style.width = '0%';
    document.getElementById('analyzeProgressStatus').textContent = 'Starting analysis...';

    document.getElementById('startAnalyzeBtn').disabled = true;

    // Clear previous
    clearAnalyzeResults();

    // Start SSE stream
    activeAnalyzeStreamId = window.gridlandAPI.startAnalyzeStream(ip, {
        onPhase: handleAnalyzePhase,
        onProgress: handleAnalyzeProgress,
        onComplete: handleAnalyzeComplete,
        onError: handleAnalyzeError
    });
}

function handleAnalyzePhase(data) {
    document.getElementById('analyzeProgressStatus').textContent = `${data.phase}: ${data.status}`;

    if (data.phase === 'port_scan' && data.status === 'complete' && data.data) {
        renderPorts(data.data.open_ports);
    }

    if (data.phase === 'service_detection' && data.status === 'complete' && data.data) {
        renderServices(data.data.services);
    }

    if (data.phase === 'camera_detection' && data.status === 'complete' && data.data) {
        renderCamera(data.data);
    }
}

function handleAnalyzeProgress(progress) {
    document.getElementById('analyzeProgressFill').style.width = `${progress}%`;
}

function handleAnalyzeComplete(analyzeData) {
    document.getElementById('analyzeProgressStatus').textContent = 'Complete!';
    document.getElementById('analyzeProgressFill').style.width = '100%';

    setTimeout(() => {
        document.getElementById('analyzeProgress').style.display = 'none';
        document.getElementById('startAnalyzeBtn').disabled = false;
    }, 1500);
}

function handleAnalyzeError(error) {
    document.getElementById('analyzeProgressStatus').textContent = `Error: ${error.message}`;
    setTimeout(() => {
        document.getElementById('analyzeProgress').style.display = 'none';
        document.getElementById('startAnalyzeBtn').disabled = false;
    }, 2000);
}

function clearAnalyzeResults() {
    document.getElementById('portList').innerHTML = '<div class="placeholder-text">Scanning...</div>';
    document.getElementById('serviceList').innerHTML = '<div class="placeholder-text">Waiting...</div>';
    document.getElementById('cameraInfo').innerHTML = '<div class="placeholder-text">Detecting...</div>';
}

function renderPorts(ports) {
    const container = document.getElementById('portList');

    if (!ports || ports.length === 0) {
        container.innerHTML = '<div class="placeholder-text">No open ports found</div>';
        return;
    }

    const cameraPorts = [554, 8554, 37777, 37778, 34567];
    let html = '';

    for (const port of ports) {
        const isCamera = cameraPorts.includes(port);
        html += `<span class="port-badge${isCamera ? ' camera' : ''}">${port}</span>`;
    }

    container.innerHTML = html;
}

function renderServices(services) {
    const container = document.getElementById('serviceList');

    if (!services || Object.keys(services).length === 0) {
        container.innerHTML = '<div class="placeholder-text">No services detected</div>';
        return;
    }

    let html = '';
    for (const [port, service] of Object.entries(services)) {
        html += `<div class="service-item"><span class="service-port">${port}</span><span class="service-name">${service}</span></div>`;
    }

    container.innerHTML = html;
}

function renderCamera(camera) {
    const container = document.getElementById('cameraInfo');

    if (!camera || !camera.detected) {
        container.innerHTML = '<div class="camera-not-detected">No camera detected</div>';
        return;
    }

    container.innerHTML = `
        <div class="camera-detected">✅ Camera Detected!</div>
        <div class="geo-row"><span class="geo-label">Brand:</span><span class="geo-value">${camera.brand || 'Unknown'}</span></div>
        <div class="geo-row"><span class="geo-label">Confidence:</span><span class="geo-value">${Math.round((camera.confidence || 0) * 100)}%</span></div>
    `;
}

// ==========================================================================
// Tab Switching
// ==========================================================================

function switchOsintTab(tabId) {
    // Update tab buttons
    const tabs = document.querySelectorAll('.osint-tabs .tab-btn');
    tabs.forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabId);
    });

    // Update tab panes
    const panes = document.querySelectorAll('.osint-tab-content .tab-pane');
    panes.forEach(pane => {
        pane.classList.toggle('active', pane.id === `tab-${tabId}`);
    });
}

// ==========================================================================
// Utilities
// ==========================================================================

function isValidIP(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ip)) return false;

    const parts = ip.split('.');
    return parts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
    });
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Could show a toast notification here
        console.log('Copied to clipboard:', text);
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

function makeDraggable(element, handle) {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

    handle.onmousedown = dragMouseDown;

    function dragMouseDown(e) {
        e.preventDefault();
        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDragElement;
        document.onmousemove = elementDrag;
    }

    function elementDrag(e) {
        e.preventDefault();
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        element.style.top = (element.offsetTop - pos2) + 'px';
        element.style.left = (element.offsetLeft - pos1) + 'px';
    }

    function closeDragElement() {
        document.onmouseup = null;
        document.onmousemove = null;
    }
}

// ==========================================================================
// Tools Menu Integration
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Add click handler for Tools menu
    const toolsMenuItem = document.querySelectorAll('.menu-item')[5]; // Tools is 6th menu item
    if (toolsMenuItem && toolsMenuItem.textContent === 'Tools') {
        toolsMenuItem.addEventListener('click', (e) => {
            e.stopPropagation();
            const menu = document.getElementById('toolsMenu');
            menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
        });
    }

    // Close menu when clicking elsewhere
    document.addEventListener('click', hideToolsMenu);
});
