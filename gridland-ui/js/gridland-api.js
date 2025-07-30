/**
 * GRIDLAND Backend API Integration
 * Connects to existing Flask server endpoints
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
    
    // Discover targets using existing /discover endpoint
    async discoverTargets(query, options = {}) {
        const requestData = {
            query: query,
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
                port: 80, // Default port, will be refined during analysis
                source: 'shodan',
                timestamp: new Date().toISOString()
            }));
            
        } catch (error) {
            console.error('Discovery failed:', error);
            throw error;
        }
    }
    
    // Start analysis using existing /scan endpoint with Server-Sent Events
    startAnalysis(target, onProgress, onComplete, onError) {
        const requestId = this.getRequestId();
        
        try {
            // Close any existing EventSource for this target
            const existingKey = `${target.ip}:${target.port}`;
            if (this.eventSources.has(existingKey)) {
                this.eventSources.get(existingKey).close();
            }
            
            // Create new EventSource connection
            const eventSource = new EventSource(`${this.baseUrl}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ ip: target.ip })
            });
            
            this.eventSources.set(existingKey, eventSource);
            
            let analysisData = {
                target: target,
                vulnerabilities: [],
                streams: [],
                progress: 0,
                status: 'scanning',
                startTime: Date.now()
            };
            
            eventSource.onmessage = (event) => {
                const line = event.data;
                
                // Parse progress and status from output
                this.parseAnalysisOutput(line, analysisData);
                
                // Call progress callback
                if (onProgress) {
                    onProgress(analysisData);
                }
            };
            
            eventSource.onerror = (error) => {
                console.error('Analysis stream error:', error);
                eventSource.close();
                this.eventSources.delete(existingKey);
                
                // Mark as complete
                analysisData.status = 'complete';
                analysisData.endTime = Date.now();
                analysisData.duration = analysisData.endTime - analysisData.startTime;
                
                if (onComplete) {
                    onComplete(analysisData);
                }
            };
            
            return requestId;
            
        } catch (error) {
            console.error('Failed to start analysis:', error);
            if (onError) {
                onError(error);
            }
            return null;
        }
    }
    
    // Parse analysis output from existing CamXploit.py integration
    parseAnalysisOutput(line, analysisData) {
        // Update progress based on output patterns
        if (line.includes('Scanning comprehensive CCTV ports')) {
            analysisData.progress = 10;
            analysisData.status = 'Port scanning...';
        } else if (line.includes('Analyzing Ports for Camera Indicators')) {
            analysisData.progress = 30;
            analysisData.status = 'Analyzing services...';
        } else if (line.includes('Checking for authentication pages')) {
            analysisData.progress = 50;
            analysisData.status = 'Testing authentication...';
        } else if (line.includes('Testing common credentials')) {
            analysisData.progress = 70;
            analysisData.status = 'Testing credentials...';
        } else if (line.includes('Checking for Live Streams')) {
            analysisData.progress = 90;
            analysisData.status = 'Discovering streams...';
        } else if (line.includes('Scan Completed')) {
            analysisData.progress = 100;
            analysisData.status = 'Complete';
        }
        
        // Extract vulnerability information
        if (line.includes('Camera Detected') || line.includes('Camera Server Detected')) {
            analysisData.vulnerabilities.push({
                type: 'Camera Detection',
                severity: 'INFO',
                description: line.trim()
            });
        }
        
        if (line.includes('Default credentials') || line.includes('Success!')) {
            analysisData.vulnerabilities.push({
                type: 'Default Credentials',
                severity: 'CRITICAL',
                description: line.trim()
            });
        }
        
        if (line.includes('CVE-')) {
            const cveMatch = line.match(/CVE-\d{4}-\d+/);
            if (cveMatch) {
                analysisData.vulnerabilities.push({
                    type: 'Known Vulnerability',
                    severity: 'HIGH',
                    cve: cveMatch[0],
                    description: line.trim()
                });
            }
        }
        
        // Extract stream URLs
        const streamRegex = /(rtsp|http|https):\/\/[^\s"']+/gi;
        const streamMatches = line.match(streamRegex);
        if (streamMatches) {
            streamMatches.forEach(url => {
                // Avoid duplicates
                if (!analysisData.streams.find(s => s.url === url)) {
                    analysisData.streams.push({
                        url: url,
                        protocol: url.split(':')[0].toUpperCase(),
                        status: 'discovered',
                        quality: 'unknown'
                    });
                }
            });
        }
        
        // Extract device information
        if (line.includes('Model:') || line.includes('Firmware:') || line.includes('Brand:')) {
            if (!analysisData.deviceInfo) {
                analysisData.deviceInfo = {};
            }
            
            if (line.includes('Model:')) {
                const modelMatch = line.match(/Model:\s*(.+)/);
                if (modelMatch) {
                    analysisData.deviceInfo.model = modelMatch[1].trim();
                }
            }
            
            if (line.includes('Firmware:')) {
                const firmwareMatch = line.match(/Firmware:\s*(.+)/);
                if (firmwareMatch) {
                    analysisData.deviceInfo.firmware = firmwareMatch[1].trim();
                }
            }
            
            if (line.includes('Brand:')) {
                const brandMatch = line.match(/Brand:\s*(.+)/);
                if (brandMatch) {
                    analysisData.deviceInfo.brand = brandMatch[1].trim();
                }
            }
        }
    }
    
    // Stop analysis
    stopAnalysis(target) {
        const key = `${target.ip}:${target.port}`;
        if (this.eventSources.has(key)) {
            this.eventSources.get(key).close();
            this.eventSources.delete(key);
            return true;
        }
        return false;
    }
    
    // Test stream using existing /stream endpoint
    async testStream(streamUrl) {
        try {
            // Encode stream URL for existing endpoint
            const encodedUrl = btoa(streamUrl);
            const testUrl = `${this.baseUrl}/stream/${encodedUrl}`;
            
            // Test if stream is accessible
            const response = await fetch(testUrl, {
                method: 'HEAD',
                timeout: 5000
            });
            
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
    
    // Get stream URL for video element
    getStreamUrl(streamUrl) {
        const encodedUrl = btoa(streamUrl);
        return `${this.baseUrl}/stream/${encodedUrl}`;
    }
    
    // Invoke existing CLI commands via new API endpoints
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
    
    // Get configuration from existing backend
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
    
    // Save configuration to existing backend
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
    
    // Get plugin information
    async getPluginInfo() {
        try {
            const response = await fetch(`${this.baseUrl}/api/plugins`);
            if (!response.ok) {
                throw new Error(`Plugin info fetch failed: ${response.status}`);
            }
            
            return await response.json();
            
        } catch (error) {
            console.error('Failed to get plugin info:', error);
            // Return default plugin info based on existing codebase
            return {
                total_plugins: 6,
                enabled_plugins: 6,
                plugins: [
                    { name: 'Hikvision Scanner', version: '1.0.0', enabled: true },
                    { name: 'Dahua Scanner', version: '1.0.0', enabled: true },
                    { name: 'Axis Scanner', version: '1.0.0', enabled: true },
                    { name: 'Generic Camera Scanner', version: '1.0.0', enabled: true },
                    { name: 'RTSP Stream Scanner', version: '1.0.0', enabled: true },
                    { name: 'Enhanced Banner Grabber', version: '1.0.0', enabled: true }
                ]
            };
        }
    }
    
    // Cleanup all connections
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

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GridlandAPI;
}