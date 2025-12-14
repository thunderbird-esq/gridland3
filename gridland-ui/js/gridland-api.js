/**
 * GRIDLAND v3.0 Backend API Integration
 * Connects to Flask server endpoints for real security reconnaissance.
 *
 * All operations are REAL - no simulation or demo mode.
 */

class GridlandAPI {
    constructor() {
        this.baseUrl = window.location.origin;
        this.eventSources = new Map();
        this.requestId = 0;
    }

    // Generate unique request ID for tracking
    getRequestId() {
        return ++this.requestId;
    }

    // ==========================================================================
    // Discovery API - Shodan Integration
    // ==========================================================================

    /**
     * Discover targets using Shodan API.
     * @param {string} query - Shodan search query (e.g., "port:554 country:US")
     * @param {object} options - Additional options (limit, etc.)
     * @returns {Promise<Array>} - Array of target objects
     */
    async discoverTargets(query, options = {}) {
        const requestData = {
            query: query,
            limit: options.limit || 50,
            ...options
        };

        try {
            const response = await fetch(`${this.baseUrl}/discover`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }

            const targets = await response.json();

            // Transform to consistent format
            return targets.map(ip => ({
                ip: ip,
                port: 80,
                source: 'shodan',
                timestamp: new Date().toISOString()
            }));

        } catch (error) {
            console.error('Discovery failed:', error);
            throw error;
        }
    }

    // ==========================================================================
    // Analysis API - CamXploit Integration
    // ==========================================================================

    /**
     * Start real-time analysis using Server-Sent Events.
     * Uses GET request since EventSource doesn't support POST body.
     *
     * @param {object} target - Target object with ip property
     * @param {function} onProgress - Progress callback(analysisData)
     * @param {function} onComplete - Completion callback(analysisData)
     * @param {function} onError - Error callback(error)
     * @returns {number} - Request ID
     */
    startAnalysis(target, onProgress, onComplete, onError) {
        const requestId = this.getRequestId();

        try {
            // Close any existing EventSource for this target
            const existingKey = `${target.ip}:${target.port || 80}`;
            if (this.eventSources.has(existingKey)) {
                this.eventSources.get(existingKey).close();
            }

            // EventSource uses GET - pass IP as query parameter
            const eventSource = new EventSource(`${this.baseUrl}/scan?ip=${encodeURIComponent(target.ip)}`);

            this.eventSources.set(existingKey, eventSource);

            let analysisData = {
                target: target,
                vulnerabilities: [],
                streams: [],
                rawOutput: [],
                progress: 0,
                status: 'scanning',
                startTime: Date.now()
            };

            eventSource.onmessage = (event) => {
                const line = event.data;

                // Store raw output
                analysisData.rawOutput.push(line);

                // Parse progress and status from output
                this.parseAnalysisOutput(line, analysisData);

                // Call progress callback
                if (onProgress) {
                    onProgress(analysisData);
                }
            };

            eventSource.onerror = (error) => {
                console.log('Analysis stream ended');
                eventSource.close();
                this.eventSources.delete(existingKey);

                // Mark as complete
                analysisData.status = 'complete';
                analysisData.progress = 100;
                analysisData.endTime = Date.now();
                analysisData.duration = analysisData.endTime - analysisData.startTime;

                if (onComplete) {
                    onComplete(analysisData);
                }
            };

            eventSource.addEventListener('error', (e) => {
                if (eventSource.readyState === EventSource.CLOSED) {
                    // Normal close - scan completed
                    return;
                }
                console.error('Analysis stream error:', e);
                if (onError) {
                    onError(new Error('Connection lost'));
                }
            });

            return requestId;

        } catch (error) {
            console.error('Failed to start analysis:', error);
            if (onError) {
                onError(error);
            }
            return null;
        }
    }

    /**
     * Parse CamXploit.py output and extract structured data.
     */
    parseAnalysisOutput(line, analysisData) {
        // Update progress based on output patterns
        if (line.includes('Scanning comprehensive CCTV ports') || line.includes('Starting scan')) {
            analysisData.progress = 10;
            analysisData.status = 'Port scanning...';
        } else if (line.includes('Analyzing Ports') || line.includes('Checking open ports')) {
            analysisData.progress = 30;
            analysisData.status = 'Analyzing services...';
        } else if (line.includes('authentication') || line.includes('login')) {
            analysisData.progress = 50;
            analysisData.status = 'Testing authentication...';
        } else if (line.includes('credentials') || line.includes('password')) {
            analysisData.progress = 70;
            analysisData.status = 'Testing credentials...';
        } else if (line.includes('Live Streams') || line.includes('RTSP') || line.includes('stream')) {
            analysisData.progress = 90;
            analysisData.status = 'Discovering streams...';
        } else if (line.includes('Scan Completed') || line.includes('completed')) {
            analysisData.progress = 100;
            analysisData.status = 'Complete';
        }

        // Extract camera detection
        if (line.includes('Camera Detected') || line.includes('Camera Server Detected') ||
            line.includes('Hikvision') || line.includes('Dahua') || line.includes('Axis')) {
            analysisData.vulnerabilities.push({
                type: 'Camera Detection',
                severity: 'INFO',
                description: line.trim(),
                timestamp: new Date().toISOString()
            });
        }

        // Extract credential findings
        if (line.includes('Default credentials') || line.includes('Success!') ||
            line.includes('authenticated') || line.includes('login successful')) {
            analysisData.vulnerabilities.push({
                type: 'Default Credentials',
                severity: 'CRITICAL',
                description: line.trim(),
                timestamp: new Date().toISOString()
            });
        }

        // Extract CVE findings
        const cveMatch = line.match(/CVE-\d{4}-\d+/g);
        if (cveMatch) {
            cveMatch.forEach(cve => {
                if (!analysisData.vulnerabilities.find(v => v.cve === cve)) {
                    analysisData.vulnerabilities.push({
                        type: 'Known Vulnerability',
                        severity: 'HIGH',
                        cve: cve,
                        description: line.trim(),
                        timestamp: new Date().toISOString()
                    });
                }
            });
        }

        // Extract stream URLs
        const streamRegex = /(rtsp|rtmp|http|https):\/\/[^\s"'<>]+/gi;
        const streamMatches = line.match(streamRegex);
        if (streamMatches) {
            streamMatches.forEach(url => {
                // Clean URL and avoid duplicates
                const cleanUrl = url.replace(/[<>]$/, '');
                if (!analysisData.streams.find(s => s.url === cleanUrl)) {
                    analysisData.streams.push({
                        url: cleanUrl,
                        protocol: cleanUrl.split(':')[0].toUpperCase(),
                        status: 'discovered',
                        quality: 'unknown',
                        timestamp: new Date().toISOString()
                    });
                }
            });
        }

        // Extract device information
        if (line.includes('Model:') || line.includes('Firmware:') || line.includes('Brand:')) {
            if (!analysisData.deviceInfo) {
                analysisData.deviceInfo = {};
            }

            const modelMatch = line.match(/Model:\s*(.+)/i);
            if (modelMatch) {
                analysisData.deviceInfo.model = modelMatch[1].trim();
            }

            const firmwareMatch = line.match(/Firmware:\s*(.+)/i);
            if (firmwareMatch) {
                analysisData.deviceInfo.firmware = firmwareMatch[1].trim();
            }

            const brandMatch = line.match(/Brand:\s*(.+)/i);
            if (brandMatch) {
                analysisData.deviceInfo.brand = brandMatch[1].trim();
            }
        }

        // Extract open ports
        const portMatch = line.match(/Port\s+(\d+)\s+(open|is open)/i);
        if (portMatch) {
            if (!analysisData.openPorts) {
                analysisData.openPorts = [];
            }
            const port = parseInt(portMatch[1]);
            if (!analysisData.openPorts.includes(port)) {
                analysisData.openPorts.push(port);
            }
        }
    }

    /**
     * Stop an active analysis.
     */
    stopAnalysis(target) {
        const key = `${target.ip}:${target.port || 80}`;
        if (this.eventSources.has(key)) {
            this.eventSources.get(key).close();
            this.eventSources.delete(key);
            return true;
        }
        return false;
    }

    // ==========================================================================
    // Stream API
    // ==========================================================================

    /**
     * Test if a stream is accessible.
     */
    async testStream(streamUrl) {
        try {
            const encodedUrl = btoa(streamUrl);
            const testUrl = `${this.baseUrl}/stream/${encodedUrl}`;

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            const response = await fetch(testUrl, {
                method: 'HEAD',
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            return {
                accessible: response.ok,
                contentType: response.headers.get('content-type'),
                status: response.status
            };

        } catch (error) {
            console.error('Stream test failed:', error);
            return {
                accessible: false,
                error: error.message
            };
        }
    }

    /**
     * Get transcoded stream URL for video element.
     */
    getStreamUrl(streamUrl) {
        const encodedUrl = btoa(streamUrl);
        return `${this.baseUrl}/stream/${encodedUrl}`;
    }

    // ==========================================================================
    // Configuration API
    // ==========================================================================

    /**
     * Get current server configuration.
     */
    async getConfiguration() {
        try {
            const response = await fetch(`${this.baseUrl}/api/config`);
            if (!response.ok) {
                throw new Error(`Config fetch failed: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('Failed to get configuration:', error);
            // Return default configuration
            return {
                scan_timeout: 10,
                max_threads: 100,
                default_ports: '80,443,554,8080,8443',
                performance_mode: 'BALANCED'
            };
        }
    }

    /**
     * Update server configuration.
     */
    async saveConfiguration(config) {
        try {
            const response = await fetch(`${this.baseUrl}/api/config`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(config)
            });

            if (!response.ok) {
                throw new Error(`Config save failed: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to save configuration:', error);
            throw error;
        }
    }

    /**
     * Get Shodan API configuration status.
     */
    async getShodanStatus() {
        try {
            const response = await fetch(`${this.baseUrl}/api/config/shodan`);
            if (!response.ok) {
                throw new Error(`Shodan status fetch failed: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('Failed to get Shodan status:', error);
            return {
                available: false,
                configured: false,
                message: 'Unable to check Shodan status'
            };
        }
    }

    /**
     * Configure Shodan API key.
     */
    async setShodanApiKey(apiKey) {
        try {
            const response = await fetch(`${this.baseUrl}/api/config/shodan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ api_key: apiKey })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || `Failed to set API key: ${response.status}`);
            }

            return result;
        } catch (error) {
            console.error('Failed to set Shodan API key:', error);
            throw error;
        }
    }

    // ==========================================================================
    // Plugin API
    // ==========================================================================

    /**
     * Get information about available plugins.
     */
    async getPluginInfo() {
        try {
            const response = await fetch(`${this.baseUrl}/api/plugins`);
            if (!response.ok) {
                throw new Error(`Plugin info fetch failed: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('Failed to get plugin info:', error);
            throw error;
        }
    }

    // ==========================================================================
    // OSINT API
    // ==========================================================================

    /**
     * Get OSINT URLs for an IP address.
     */
    async getOsintUrls(ip) {
        try {
            const response = await fetch(`${this.baseUrl}/api/osint/urls/${ip}`);
            if (!response.ok) {
                throw new Error(`OSINT fetch failed: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('Failed to get OSINT URLs:', error);
            throw error;
        }
    }

    /**
     * Get geolocation information for an IP.
     */
    async getGeoInfo(ip) {
        try {
            const response = await fetch(`${this.baseUrl}/api/osint/geo/${ip}`);
            if (!response.ok) {
                throw new Error(`Geo lookup failed: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('Failed to get geo info:', error);
            throw error;
        }
    }

    // ==========================================================================
    // CVE API
    // ==========================================================================

    /**
     * Get CVEs for a camera brand.
     */
    async getCVEs(brand) {
        try {
            const response = await fetch(`${this.baseUrl}/api/cves/${brand}`);
            if (!response.ok) {
                throw new Error(`CVE fetch failed: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('Failed to get CVEs:', error);
            throw error;
        }
    }

    // ==========================================================================
    // CLI API
    // ==========================================================================

    /**
     * Invoke GRIDLAND CLI commands.
     */
    async invokeCLI(command, args = []) {
        try {
            const response = await fetch(`${this.baseUrl}/api/cli`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    command: command,
                    args: args
                })
            });

            if (!response.ok) {
                throw new Error(`CLI command failed: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('CLI invocation failed:', error);
            throw error;
        }
    }

    // ==========================================================================
    // Health Check
    // ==========================================================================

    /**
     * Check server health status.
     */
    async checkHealth() {
        try {
            const response = await fetch(`${this.baseUrl}/api/health`);
            return await response.json();
        } catch (error) {
            console.error('Health check failed:', error);
            return {
                status: 'unreachable',
                error: error.message
            };
        }
    }

    // ==========================================================================
    // Utility Methods
    // ==========================================================================

    /**
     * Cleanup all active connections.
     */
    cleanup() {
        for (const eventSource of this.eventSources.values()) {
            eventSource.close();
        }
        this.eventSources.clear();
    }
}

// Create global API instance
window.gridlandAPI = new GridlandAPI();

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    window.gridlandAPI.cleanup();
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GridlandAPI;
}
