/**
 * GRIDLAND Map Integration
 * Interactive camera geolocation map with Leaflet.js
 */

// Map state
let gridlandMap = null;
let cameraMarkers = {};
let markerCluster = null;

// Camera icon
const cameraIcon = L.divIcon({
    className: 'camera-marker',
    html: '📹',
    iconSize: [24, 24],
    iconAnchor: [12, 12],
    popupAnchor: [0, -12]
});

const cameraIconActive = L.divIcon({
    className: 'camera-marker active',
    html: '🎥',
    iconSize: [28, 28],
    iconAnchor: [14, 14],
    popupAnchor: [0, -14]
});

// ==========================================================================
// Map Initialization
// ==========================================================================

function initMap() {
    if (gridlandMap) return; // Already initialized

    const mapContainer = document.getElementById('cameraMap');
    if (!mapContainer) return;

    // Initialize Leaflet map
    gridlandMap = L.map('cameraMap', {
        center: [20, 0], // World view
        zoom: 2,
        zoomControl: true,
        attributionControl: false
    });

    // Use local tile proxy (CartoDB Dark Matter via server)
    L.tileLayer('/api/map/tiles/{z}/{x}/{y}.png', {
        maxZoom: 18,
        attribution: '© OpenStreetMap contributors'
    }).addTo(gridlandMap);

    // Load existing cameras
    loadCameraLocations();
}

// ==========================================================================
// Camera Location Functions
// ==========================================================================

async function loadCameraLocations() {
    try {
        const response = await fetch('/api/map/cameras');
        const data = await response.json();

        // Clear existing markers
        Object.values(cameraMarkers).forEach(marker => {
            gridlandMap.removeLayer(marker);
        });
        cameraMarkers = {};

        // Add new markers
        data.cameras.forEach(camera => {
            if (camera.lat && camera.lon) {
                addCameraMarker(camera);
            }
        });

        // Update count
        updateMapStatus(data.count);

    } catch (error) {
        console.error('Failed to load camera locations:', error);
    }
}

function addCameraMarker(camera) {
    if (!gridlandMap || !camera.lat || !camera.lon) return;

    const marker = L.marker([camera.lat, camera.lon], {
        icon: cameraIcon,
        title: camera.ip
    });

    // Popup with camera details
    const popupContent = `
        <div class="camera-popup">
            <div class="popup-header">📹 ${camera.ip}</div>
            <div class="popup-row"><b>City:</b> ${camera.city || 'Unknown'}</div>
            <div class="popup-row"><b>Country:</b> ${camera.country || 'Unknown'}</div>
            ${camera.brand ? `<div class="popup-row"><b>Brand:</b> ${camera.brand}</div>` : ''}
            <div class="popup-row"><b>Coords:</b> ${camera.lat.toFixed(4)}, ${camera.lon.toFixed(4)}</div>
            <div class="popup-actions">
                <button class="mac-button small" onclick="analyzeFromMap('${camera.ip}')">Analyze</button>
                <button class="mac-button small" onclick="osintFromMap('${camera.ip}')">OSINT</button>
                <button class="mac-button small" onclick="removeCameraFromMap('${camera.ip}')">Remove</button>
            </div>
        </div>
    `;

    marker.bindPopup(popupContent);
    marker.addTo(gridlandMap);

    cameraMarkers[camera.ip] = marker;
}

async function locateAndAddCamera(ip) {
    if (!ip) return;

    updateMapStatus('Locating...');

    try {
        const response = await fetch(`/api/map/geo/${ip}`);
        const data = await response.json();

        if (data.status === 'located' && data.camera) {
            addCameraMarker(data.camera);

            // Pan to camera
            if (data.camera.lat && data.camera.lon) {
                gridlandMap.setView([data.camera.lat, data.camera.lon], 8);
            }

            updateMapStatus(`Located: ${data.camera.city || ip}`);
        } else {
            updateMapStatus('Location failed');
        }

    } catch (error) {
        console.error('Failed to locate camera:', error);
        updateMapStatus('Error');
    }
}

async function removeCameraFromMap(ip) {
    try {
        await fetch(`/api/map/cameras/${ip}`, { method: 'DELETE' });

        if (cameraMarkers[ip]) {
            gridlandMap.removeLayer(cameraMarkers[ip]);
            delete cameraMarkers[ip];
        }

        updateMapStatus(`Removed: ${ip}`);

    } catch (error) {
        console.error('Failed to remove camera:', error);
    }
}

// ==========================================================================
// Integration with Other Windows
// ==========================================================================

function analyzeFromMap(ip) {
    // Set IP in analyze window and open it
    const analyzeWindow = document.getElementById('analyzeWindow');
    const analyzeIp = document.getElementById('analyzeIp');

    if (analyzeWindow && analyzeIp) {
        analyzeIp.value = ip;
        analyzeWindow.style.display = 'block';
        startNetworkAnalysis();
    }
}

function osintFromMap(ip) {
    // Set IP in OSINT window and open it
    const osintWindow = document.getElementById('osintWindow');
    const osintIp = document.getElementById('osintIp');

    if (osintWindow && osintIp) {
        osintIp.value = ip;
        osintWindow.style.display = 'block';
        startOsintGathering();
    }
}

// Auto-add cameras from OSINT results
function addCameraFromOsintPhase(data) {
    if (data.phase === 'geolocation' && data.status === 'complete' && data.data) {
        const geo = data.data;
        if (geo.latitude && geo.longitude) {
            const camera = {
                ip: geo.ip,
                lat: geo.latitude,
                lon: geo.longitude,
                city: geo.city,
                country: geo.country
            };

            // Add to map
            addCameraMarker(camera);

            // Also POST to server for persistence
            fetch('/api/map/cameras', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(camera)
            });
        }
    }
}

// ==========================================================================
// UI Functions
// ==========================================================================

function toggleMapWindow() {
    const win = document.getElementById('mapWindow');
    if (win.style.display === 'none') {
        win.style.display = 'block';
        makeDraggable(win, document.getElementById('mapTitleBar'));

        // Initialize map on first open
        setTimeout(initMap, 100);
    } else {
        win.style.display = 'none';
    }
    hideToolsMenu();
}

function updateMapStatus(text) {
    const statusEl = document.getElementById('mapStatus');
    if (statusEl) {
        statusEl.textContent = text;
    }
}

function refreshMapCameras() {
    loadCameraLocations();
}

function clearAllCameras() {
    if (!confirm('Remove all cameras from map?')) return;

    Object.keys(cameraMarkers).forEach(ip => {
        removeCameraFromMap(ip);
    });
}

// ==========================================================================
// Initialization
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Fix Leaflet icon paths for local installation
    if (typeof L !== 'undefined') {
        L.Icon.Default.imagePath = '/ui/lib/leaflet/';
    }
});
