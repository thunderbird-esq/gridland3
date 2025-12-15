/**
 * GRIDLAND 3D Globe Visualization
 * Uses Cesium.js for 3D globe rendering with Google Photorealistic 3D Tiles
 */

class CesiumMap {
    constructor(containerId) {
        this.containerId = containerId;
        this.viewer = null;
        this.cameraMarkers = new Map();
        this.google3DTileset = null;
        this.is3DTilesEnabled = false;
        this.selectedCamera = null;
        this.googleMapsApiKey = null;

        // Don't initialize until explicitly called (after window is visible)
        this.initialized = false;
    }

    /**
     * Initialize the Cesium viewer
     */
    async initialize() {
        if (this.initialized) return;

        const container = document.getElementById(this.containerId);
        if (!container) {
            console.error('Cesium container not found:', this.containerId);
            return;
        }

        try {
            // Set Cesium Ion access token (free tier for basic terrain)
            // Users can set their own token for enhanced features
            Cesium.Ion.defaultAccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkZWZhdWx0IiwiaWQiOjEsImlhdCI6MTY5MDAwMDAwMH0.placeholder';

            // Initialize viewer with optimized settings
            this.viewer = new Cesium.Viewer(this.containerId, {
                terrainProvider: await Cesium.createWorldTerrainAsync(),
                baseLayerPicker: false,
                geocoder: false,
                homeButton: false,
                sceneModePicker: false,
                navigationHelpButton: false,
                animation: false,
                timeline: false,
                fullscreenButton: false,
                vrButton: false,
                selectionIndicator: true,
                infoBox: false,
                shadows: false,
                shouldAnimate: true,
                requestRenderMode: true,
                maximumRenderTimeChange: Infinity
            });

            // Configure scene
            this.viewer.scene.globe.enableLighting = true;
            this.viewer.scene.fog.enabled = true;
            this.viewer.scene.fog.density = 0.0002;

            // Set initial camera position (world view)
            this.viewer.camera.setView({
                destination: Cesium.Cartesian3.fromDegrees(0, 20, 25000000),
                orientation: {
                    heading: 0,
                    pitch: -Cesium.Math.PI_OVER_TWO,
                    roll: 0
                }
            });

            // Setup event handlers
            this.setupEventHandlers();

            // Setup mouse coordinate tracking
            this.setupCoordinateTracking();

            this.initialized = true;
            this.updateStatus('Globe ready');

        } catch (error) {
            console.error('Failed to initialize Cesium:', error);
            this.updateStatus('Failed to initialize 3D globe');
        }
    }

    /**
     * Setup click and hover event handlers
     */
    setupEventHandlers() {
        const handler = new Cesium.ScreenSpaceEventHandler(this.viewer.scene.canvas);

        // Click handler for camera markers
        handler.setInputAction((click) => {
            const pickedObject = this.viewer.scene.pick(click.position);
            if (Cesium.defined(pickedObject) && pickedObject.id) {
                const entity = pickedObject.id;
                if (entity.properties && entity.properties.cameraData) {
                    this.onCameraMarkerClick(entity);
                }
            } else {
                this.hideCameraInfo();
            }
        }, Cesium.ScreenSpaceEventType.LEFT_CLICK);

        // Double-click to fly to location
        handler.setInputAction((click) => {
            const pickedObject = this.viewer.scene.pick(click.position);
            if (Cesium.defined(pickedObject) && pickedObject.id) {
                const entity = pickedObject.id;
                if (entity.properties && entity.properties.cameraData) {
                    this.flyToCamera(entity.properties.cameraData.getValue().ip);
                }
            }
        }, Cesium.ScreenSpaceEventType.LEFT_DOUBLE_CLICK);
    }

    /**
     * Setup mouse coordinate tracking
     */
    setupCoordinateTracking() {
        const coordsDisplay = document.getElementById('mapCoords');
        if (!coordsDisplay) return;

        const handler = new Cesium.ScreenSpaceEventHandler(this.viewer.scene.canvas);

        handler.setInputAction((movement) => {
            const cartesian = this.viewer.camera.pickEllipsoid(
                movement.endPosition,
                this.viewer.scene.globe.ellipsoid
            );

            if (cartesian) {
                const cartographic = Cesium.Cartographic.fromCartesian(cartesian);
                const lat = Cesium.Math.toDegrees(cartographic.latitude).toFixed(4);
                const lon = Cesium.Math.toDegrees(cartographic.longitude).toFixed(4);
                coordsDisplay.textContent = `Lat: ${lat}, Lon: ${lon}`;
            }
        }, Cesium.ScreenSpaceEventType.MOUSE_MOVE);
    }

    /**
     * Enable Google Photorealistic 3D Tiles
     * Requires a Google Maps Platform API key
     */
    async enable3DTiles(apiKey) {
        if (!this.viewer) {
            console.error('Viewer not initialized');
            return false;
        }

        if (this.google3DTileset) {
            // Already loaded, just show it
            this.google3DTileset.show = true;
            this.is3DTilesEnabled = true;
            this.updateTileStatus('3D Tiles: On');
            return true;
        }

        if (!apiKey) {
            console.warn('Google Maps API key required for 3D tiles');
            this.updateStatus('3D Tiles require Google API key');
            return false;
        }

        this.googleMapsApiKey = apiKey;

        try {
            this.updateStatus('Loading 3D tiles...');

            // Create Google Photorealistic 3D Tiles tileset
            this.google3DTileset = await Cesium.Cesium3DTileset.fromUrl(
                `https://tile.googleapis.com/v1/3dtiles/root.json?key=${apiKey}`
            );

            this.viewer.scene.primitives.add(this.google3DTileset);
            this.is3DTilesEnabled = true;
            this.updateTileStatus('3D Tiles: On');
            this.updateStatus('3D tiles loaded');

            return true;

        } catch (error) {
            console.error('Failed to load Google 3D Tiles:', error);
            this.updateStatus('Failed to load 3D tiles');
            return false;
        }
    }

    /**
     * Toggle 3D tiles visibility
     */
    toggle3DTiles() {
        if (this.google3DTileset) {
            this.google3DTileset.show = !this.google3DTileset.show;
            this.is3DTilesEnabled = this.google3DTileset.show;
            this.updateTileStatus(`3D Tiles: ${this.is3DTilesEnabled ? 'On' : 'Off'}`);
        } else {
            // Prompt for API key
            this.showApiKeyPrompt();
        }
    }

    /**
     * Show prompt for Google API key
     */
    showApiKeyPrompt() {
        const apiKey = prompt(
            'Enter your Google Maps Platform API key for Photorealistic 3D Tiles:\n\n' +
            'Get a key at: https://console.cloud.google.com/google/maps-apis\n' +
            'Enable: "Map Tiles API" in your project'
        );

        if (apiKey && apiKey.trim()) {
            this.enable3DTiles(apiKey.trim());
        }
    }

    /**
     * Add a camera marker to the globe
     */
    async addCameraMarker(cameraData) {
        if (!this.viewer) return null;

        const { ip, lat, lon, city, country, org, ports, streams } = cameraData;

        // Skip if already exists
        if (this.cameraMarkers.has(ip)) {
            return this.cameraMarkers.get(ip);
        }

        // Determine marker color based on vulnerability status
        let markerColor = Cesium.Color.CYAN;
        if (cameraData.hasVulnerabilities) {
            markerColor = Cesium.Color.RED;
        } else if (cameraData.hasStreams || (streams && streams.length > 0)) {
            markerColor = Cesium.Color.LIME;
        }

        // Create entity with billboard and label
        const entity = this.viewer.entities.add({
            name: ip,
            position: Cesium.Cartesian3.fromDegrees(lon, lat, 100),
            billboard: {
                image: this.createCameraIcon(markerColor),
                width: 32,
                height: 32,
                verticalOrigin: Cesium.VerticalOrigin.BOTTOM,
                heightReference: Cesium.HeightReference.RELATIVE_TO_GROUND,
                disableDepthTestDistance: Number.POSITIVE_INFINITY
            },
            label: {
                text: ip,
                font: '12px monospace',
                fillColor: Cesium.Color.WHITE,
                outlineColor: Cesium.Color.BLACK,
                outlineWidth: 2,
                style: Cesium.LabelStyle.FILL_AND_OUTLINE,
                verticalOrigin: Cesium.VerticalOrigin.TOP,
                pixelOffset: new Cesium.Cartesian2(0, 8),
                heightReference: Cesium.HeightReference.RELATIVE_TO_GROUND,
                disableDepthTestDistance: Number.POSITIVE_INFINITY,
                show: false // Show on hover/select
            },
            properties: {
                cameraData: new Cesium.ConstantProperty(cameraData)
            }
        });

        this.cameraMarkers.set(ip, entity);
        this.updateCameraCount();

        return entity;
    }

    /**
     * Create a camera icon as a data URL
     */
    createCameraIcon(color) {
        const canvas = document.createElement('canvas');
        canvas.width = 32;
        canvas.height = 32;
        const ctx = canvas.getContext('2d');

        // Camera body
        ctx.fillStyle = color.toCssColorString();
        ctx.beginPath();
        ctx.roundRect(4, 10, 20, 14, 2);
        ctx.fill();

        // Lens
        ctx.beginPath();
        ctx.arc(24, 17, 6, 0, Math.PI * 2);
        ctx.fill();

        // Flash
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.rect(6, 6, 4, 4);
        ctx.fill();

        // Border
        ctx.strokeStyle = '#000000';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.roundRect(4, 10, 20, 14, 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(24, 17, 6, 0, Math.PI * 2);
        ctx.stroke();

        return canvas.toDataURL();
    }

    /**
     * Add multiple cameras from geolocation data
     */
    async addCamerasFromTargets(targets) {
        const results = [];

        for (const target of targets) {
            try {
                // Get geolocation if not already present
                if (!target.lat || !target.lon) {
                    const geoInfo = await window.gridlandAPI.getGeoInfo(target.ip);
                    if (geoInfo && geoInfo.loc) {
                        const [lat, lon] = geoInfo.loc.split(',').map(Number);
                        target.lat = lat;
                        target.lon = lon;
                        target.city = geoInfo.city;
                        target.region = geoInfo.region;
                        target.country = geoInfo.country;
                        target.org = geoInfo.org;
                    }
                }

                if (target.lat && target.lon) {
                    const entity = await this.addCameraMarker(target);
                    results.push({ ip: target.ip, success: true, entity });
                } else {
                    results.push({ ip: target.ip, success: false, error: 'No geolocation' });
                }
            } catch (error) {
                results.push({ ip: target.ip, success: false, error: error.message });
            }
        }

        return results;
    }

    /**
     * Remove a camera marker
     */
    removeCameraMarker(ip) {
        const entity = this.cameraMarkers.get(ip);
        if (entity) {
            this.viewer.entities.remove(entity);
            this.cameraMarkers.delete(ip);
            this.updateCameraCount();
        }
    }

    /**
     * Clear all camera markers
     */
    clearAllMarkers() {
        for (const [ip, entity] of this.cameraMarkers) {
            this.viewer.entities.remove(entity);
        }
        this.cameraMarkers.clear();
        this.updateCameraCount();
    }

    /**
     * Fly to a specific camera
     */
    flyToCamera(ip) {
        const entity = this.cameraMarkers.get(ip);
        if (!entity) return;

        const cameraData = entity.properties.cameraData.getValue();

        this.viewer.flyTo(entity, {
            duration: 2,
            offset: new Cesium.HeadingPitchRange(
                0,
                Cesium.Math.toRadians(-45),
                1000
            )
        }).then(() => {
            // Show camera info after flying
            this.showCameraInfo(cameraData);
        });

        this.updateStatus(`Flying to ${ip}`);
    }

    /**
     * Fly to coordinates
     */
    flyToLocation(lat, lon, height = 10000) {
        this.viewer.camera.flyTo({
            destination: Cesium.Cartesian3.fromDegrees(lon, lat, height),
            duration: 2,
            orientation: {
                heading: 0,
                pitch: Cesium.Math.toRadians(-45),
                roll: 0
            }
        });
    }

    /**
     * Reset view to world
     */
    resetView() {
        this.viewer.camera.flyTo({
            destination: Cesium.Cartesian3.fromDegrees(0, 20, 25000000),
            duration: 2,
            orientation: {
                heading: 0,
                pitch: -Cesium.Math.PI_OVER_TWO,
                roll: 0
            }
        });
        this.hideCameraInfo();
        this.updateStatus('View reset');
    }

    /**
     * Handle camera marker click
     */
    onCameraMarkerClick(entity) {
        const cameraData = entity.properties.cameraData.getValue();
        this.selectedCamera = cameraData;
        this.showCameraInfo(cameraData);

        // Show label
        entity.label.show = true;

        // Hide other labels
        for (const [ip, otherEntity] of this.cameraMarkers) {
            if (ip !== cameraData.ip) {
                otherEntity.label.show = false;
            }
        }
    }

    /**
     * Show camera info overlay
     */
    showCameraInfo(cameraData) {
        const overlay = document.getElementById('cameraInfoOverlay');
        if (!overlay) return;

        document.getElementById('cameraInfoIP').textContent = cameraData.ip || '--';
        document.getElementById('cameraInfoLocation').textContent =
            `${cameraData.city || ''}, ${cameraData.country || ''}`.replace(/^, |, $/g, '') || '--';
        document.getElementById('cameraInfoOrg').textContent = cameraData.org || '--';
        document.getElementById('cameraInfoCoords').textContent =
            cameraData.lat && cameraData.lon
                ? `${cameraData.lat.toFixed(4)}, ${cameraData.lon.toFixed(4)}`
                : '--';
        document.getElementById('cameraInfoPorts').textContent =
            cameraData.ports ? cameraData.ports.join(', ') : (cameraData.port || '--');

        overlay.style.display = 'block';
    }

    /**
     * Hide camera info overlay
     */
    hideCameraInfo() {
        const overlay = document.getElementById('cameraInfoOverlay');
        if (overlay) {
            overlay.style.display = 'none';
        }

        // Hide all labels
        for (const [ip, entity] of this.cameraMarkers) {
            entity.label.show = false;
        }

        this.selectedCamera = null;
    }

    /**
     * Show stream in Picture-in-Picture
     */
    showStreamPIP(streamUrl, title) {
        const pip = document.getElementById('streamPIP');
        const video = document.getElementById('pipVideo');
        const placeholder = document.getElementById('pipPlaceholder');
        const pipTitle = document.getElementById('pipTitle');

        if (!pip || !video) return;

        pipTitle.textContent = title || 'Live Stream';

        if (streamUrl) {
            video.src = streamUrl;
            video.style.display = 'block';
            placeholder.style.display = 'none';
            video.play().catch(console.error);
        } else {
            video.style.display = 'none';
            placeholder.style.display = 'flex';
        }

        pip.style.display = 'block';
    }

    /**
     * Hide PIP
     */
    hideStreamPIP() {
        const pip = document.getElementById('streamPIP');
        const video = document.getElementById('pipVideo');

        if (pip) pip.style.display = 'none';
        if (video) {
            video.pause();
            video.src = '';
        }
    }

    /**
     * Search for a location
     */
    async searchLocation(query) {
        if (!query) return;

        this.updateStatus(`Searching: ${query}`);

        try {
            // Use Cesium's geocoder service
            const resource = await Cesium.IonGeocoderService.fromUrl(
                'https://api.cesium.com/v1/geocode'
            );

            // Simple approach: use Nominatim (OpenStreetMap) for geocoding
            const response = await fetch(
                `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}`
            );
            const results = await response.json();

            if (results && results.length > 0) {
                const { lat, lon, display_name } = results[0];
                this.flyToLocation(parseFloat(lat), parseFloat(lon), 50000);
                this.updateStatus(`Found: ${display_name.substring(0, 50)}...`);
            } else {
                this.updateStatus('Location not found');
            }
        } catch (error) {
            console.error('Search failed:', error);
            this.updateStatus('Search failed');
        }
    }

    /**
     * Update status bar
     */
    updateStatus(message) {
        const statusEl = document.getElementById('mapStatus');
        if (statusEl) {
            statusEl.textContent = message;
        }
    }

    /**
     * Update camera count
     */
    updateCameraCount() {
        const countEl = document.getElementById('mapCameraCount');
        if (countEl) {
            countEl.textContent = `Cameras: ${this.cameraMarkers.size}`;
        }
    }

    /**
     * Update tile status
     */
    updateTileStatus(message) {
        const statusEl = document.getElementById('mapTileStatus');
        if (statusEl) {
            statusEl.textContent = message;
        }
    }

    /**
     * Get all camera markers
     */
    getAllCameras() {
        const cameras = [];
        for (const [ip, entity] of this.cameraMarkers) {
            cameras.push({
                ip,
                data: entity.properties.cameraData.getValue()
            });
        }
        return cameras;
    }

    /**
     * Zoom to fit all cameras
     */
    zoomToAllCameras() {
        if (this.cameraMarkers.size === 0) {
            this.resetView();
            return;
        }

        const entities = Array.from(this.cameraMarkers.values());
        this.viewer.flyTo(entities, {
            duration: 2
        });
    }

    /**
     * Destroy the viewer
     */
    destroy() {
        if (this.viewer) {
            this.viewer.destroy();
            this.viewer = null;
        }
        this.cameraMarkers.clear();
        this.initialized = false;
    }
}

// Create global instance (lazy initialization)
window.gridlandMap = new CesiumMap('cesiumContainer');

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CesiumMap;
}
