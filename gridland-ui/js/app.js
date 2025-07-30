/**
 * GRIDLAND v3.0 - Main Application Logic
 * Integrates Macintosh Plus UI with existing GRIDLAND backend
 */

class GridlandApp {
    constructor() {
        this.targets = new Map();
        this.analysisQueue = [];
        this.currentAnalysis = null;
        this.discoveredTargets = [];
        this.streams = new Map();
        this.config = null;
        
        this.initializeApp();
        this.bindUIEvents();
        this.loadConfiguration();
    }
    
    initializeApp() {
        console.log('🚀 GRIDLAND v3.0 - Macintosh Plus Interface Starting...');
        
        // Initialize status
        this.updateStatus('Ready');
        this.updateCounters();
        
        // Load existing backend configuration
        this.loadBackendConfig();
    }
    
    async loadBackendConfig() {
        try {
            this.config = await window.gridlandAPI.getConfiguration();
            console.log('📋 Configuration loaded:', this.config);
        } catch (error) {
            console.warn('⚠️ Failed to load configuration, using defaults:', error);
            this.config = {
                scan_timeout: 10,
                max_threads: 100,
                default_ports: '80,443,554,8080,8443',
                performance_mode: 'BALANCED'
            };
        }
    }
    
    bindUIEvents() {
        // Discovery panel
        const discoverBtn = document.getElementById('discoverBtn');
        const shodanQuery = document.getElementById('shodanQuery');
        
        if (discoverBtn) {
            discoverBtn.addEventListener('click', () => {
                this.startDiscovery();
            });
        }
        
        if (shodanQuery) {
            shodanQuery.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.startDiscovery();
                }
            });
        }
        
        // Analysis controls
        const addTargetBtn = document.getElementById('addTargetBtn');
        const removeTargetBtn = document.getElementById('removeTargetBtn');
        const startAnalysisBtn = document.getElementById('startAnalysisBtn');
        const stopAnalysisBtn = document.getElementById('stopAnalysisBtn');
        
        if (addTargetBtn) {
            addTargetBtn.addEventListener('click', () => {
                window.macUI.showModal('addTargetDialog');
            });
        }
        
        if (removeTargetBtn) {
            removeTargetBtn.addEventListener('click', () => {
                this.removeSelectedTarget();
            });
        }
        
        if (startAnalysisBtn) {
            startAnalysisBtn.addEventListener('click', () => {
                this.startAnalysis();
            });
        }
        
        if (stopAnalysisBtn) {
            stopAnalysisBtn.addEventListener('click', () => {
                this.stopAnalysis();
            });
        }
        
        // Stream controls
        const fullScreenBtn = document.getElementById('fullScreenBtn');
        const recordBtn = document.getElementById('recordBtn');
        
        if (fullScreenBtn) {
            fullScreenBtn.addEventListener('click', () => {
                this.toggleFullScreen();
            });
        }
        
        if (recordBtn) {
            recordBtn.addEventListener('click', () => {
                this.toggleRecording();
            });
        }
    }
    
    // Discovery functionality
    async startDiscovery() {
        const queryInput = document.getElementById('shodanQuery');
        const query = queryInput ? queryInput.value.trim() : '';
        
        if (!query) {
            window.macUI.showErrorDialog('Invalid Query', 'Please enter a search query.');
            return;
        }
        
        this.updateStatus('Discovering targets...');
        
        try {
            // Use existing /discover endpoint
            const targets = await window.gridlandAPI.discoverTargets(query);
            
            this.discoveredTargets = targets;
            this.displayDiscoveryResults(targets);
            
            window.macSounds.playSuccess();
            this.updateStatus(`Found ${targets.length} targets`);
            
        } catch (error) {
            console.error('Discovery failed:', error);
            window.macUI.showErrorDialog('Discovery Failed', error.message);
            window.macSounds.playError();
            this.updateStatus('Discovery failed');
        }
    }
    
    displayDiscoveryResults(targets) {
        const targetList = document.getElementById('targetList');
        if (!targetList) return;
        
        // Clear existing results
        targetList.innerHTML = '';
        
        if (targets.length === 0) {
            const placeholder = document.createElement('div');
            placeholder.className = 'list-item placeholder';
            placeholder.textContent = 'No targets found';
            targetList.appendChild(placeholder);
            return;
        }
        
        // Add discovered targets
        targets.forEach(target => {
            const item = document.createElement('div');
            item.className = 'list-item';
            item.textContent = target.ip;
            item.dataset.ip = target.ip;
            item.dataset.port = target.port;
            targetList.appendChild(item);
        });
    }
    
    // Target management
    addTarget(target) {
        const targetKey = `${target.ip}:${target.port}`;
        
        if (this.targets.has(targetKey)) {
            window.macUI.showErrorDialog('Duplicate Target', 'This target is already in the queue.');
            return;
        }
        
        // Add to targets map
        this.targets.set(targetKey, {
            ...target,
            status: 'queued',
            progress: 0,
            vulnerabilities: [],
            streams: [],
            addedAt: new Date()
        });
        
        // Add to analysis queue
        this.analysisQueue.push(targetKey);
        
        // Update UI
        this.updateAnalysisQueue();
        this.updateCounters();
        
        window.macSounds.playTick();
        this.updateStatus(`Added target: ${target.ip}`);
    }
    
    removeSelectedTarget() {
        const selectedItem = document.querySelector('.queue-item.selected');
        if (!selectedItem) return;
        
        const ip = selectedItem.querySelector('.col-ip').textContent;
        const targetKey = Array.from(this.targets.keys()).find(key => key.startsWith(ip));
        
        if (targetKey) {
            this.targets.delete(targetKey);
            this.analysisQueue = this.analysisQueue.filter(key => key !== targetKey);
            
            this.updateAnalysisQueue();
            this.updateCounters();
            
            window.macSounds.playTick();
            this.updateStatus(`Removed target: ${ip}`);
        }
    }
    
    updateAnalysisQueue() {
        const queueContent = document.getElementById('queueContent');
        if (!queueContent) return;
        
        // Clear existing items
        queueContent.innerHTML = '';
        
        if (this.targets.size === 0) {
            const placeholder = document.createElement('div');
            placeholder.className = 'queue-item placeholder';
            placeholder.innerHTML = `
                <div class="col-ip">No targets queued</div>
                <div class="col-status">-</div>
                <div class="col-progress">-</div>
                <div class="col-vulns">-</div>
            `;
            queueContent.appendChild(placeholder);
            return;
        }
        
        // Add queue items
        for (const [targetKey, target] of this.targets) {
            const item = document.createElement('div');
            item.className = 'queue-item';
            item.dataset.targetKey = targetKey;
            
            const progressText = target.status === 'scanning' ? `${target.progress}%` : '-';
            const vulnCount = target.vulnerabilities.length;
            
            item.innerHTML = `
                <div class="col-ip">${target.ip}:${target.port}</div>
                <div class="col-status status-${target.status}">${target.status}</div>
                <div class="col-progress">${progressText}</div>
                <div class="col-vulns">${vulnCount}</div>
            `;
            
            queueContent.appendChild(item);
        }
    }
    
    // Analysis functionality
    async startAnalysis() {
        if (this.analysisQueue.length === 0) {
            window.macUI.showErrorDialog('No Targets', 'Please add targets to the analysis queue.');
            return;
        }
        
        if (this.currentAnalysis) {
            window.macUI.showErrorDialog('Analysis Running', 'An analysis is already in progress.');
            return;
        }
        
        // Update UI state
        this.setAnalysisState(true);
        this.updateStatus('Starting analysis...');
        
        // Process queue
        for (const targetKey of this.analysisQueue) {
            if (!this.currentAnalysis) break; // Stopped
            
            const target = this.targets.get(targetKey);
            if (!target) continue;
            
            await this.analyzeTarget(target);
        }
        
        // Analysis complete
        this.setAnalysisState(false);
        this.updateStatus('Analysis complete');
        window.macSounds.playSuccess();
    }
    
    async analyzeTarget(target) {
        const targetKey = `${target.ip}:${target.port}`;
        
        // Update target status
        target.status = 'scanning';
        target.progress = 0;
        this.updateAnalysisQueue();
        
        this.updateStatus(`Analyzing ${target.ip}...`);
        
        return new Promise((resolve) => {
            // Start analysis using existing backend
            this.currentAnalysis = window.gridlandAPI.startAnalysis(
                target,
                // Progress callback
                (analysisData) => {
                    target.progress = analysisData.progress;
                    target.status = analysisData.status;
                    target.vulnerabilities = analysisData.vulnerabilities;
                    target.streams = analysisData.streams;
                    
                    this.updateAnalysisQueue();
                    this.updateCounters();
                    
                    // Update stream monitor if streams found
                    if (analysisData.streams.length > 0) {
                        this.updateStreamMonitor(analysisData.streams[0]);
                    }
                },
                // Complete callback
                (analysisData) => {
                    target.status = 'complete';
                    target.progress = 100;
                    target.endTime = Date.now();
                    
                    this.updateAnalysisQueue();
                    this.updateCounters();
                    
                    // Add to channel guide if streams found
                    if (analysisData.streams.length > 0) {
                        this.addToChannelGuide(target, analysisData.streams);
                    }
                    
                    this.currentAnalysis = null;
                    resolve();
                },
                // Error callback
                (error) => {
                    target.status = 'error';
                    target.error = error.message;
                    
                    this.updateAnalysisQueue();
                    console.error('Analysis error:', error);
                    
                    this.currentAnalysis = null;
                    resolve();
                }
            );
        });
    }
    
    stopAnalysis() {
        if (!this.currentAnalysis) return;
        
        // Stop current analysis
        this.currentAnalysis = null;
        
        // Reset target statuses
        for (const target of this.targets.values()) {
            if (target.status === 'scanning') {
                target.status = 'queued';
                target.progress = 0;
            }
        }
        
        this.setAnalysisState(false);
        this.updateAnalysisQueue();
        this.updateStatus('Analysis stopped');
        
        window.macSounds.playAlert();
    }
    
    setAnalysisState(running) {
        const startBtn = document.getElementById('startAnalysisBtn');
        const stopBtn = document.getElementById('stopAnalysisBtn');
        const addBtn = document.getElementById('addTargetBtn');
        const removeBtn = document.getElementById('removeTargetBtn');
        
        if (startBtn) startBtn.disabled = running;
        if (stopBtn) stopBtn.disabled = !running;
        if (addBtn) addBtn.disabled = running;
        if (removeBtn) removeBtn.disabled = running;
    }
    
    // Stream functionality
    updateStreamMonitor(stream) {
        const streamPreview = document.getElementById('streamPreview');
        const streamVideo = document.getElementById('streamVideo');
        const streamInfo = document.getElementById('streamInfo');
        
        if (!streamPreview || !streamVideo || !streamInfo) return;
        
        // Update stream info
        streamInfo.innerHTML = `
            <div class="info-line">Status: Active</div>
            <div class="info-line">Protocol: ${stream.protocol}</div>
            <div class="info-line">Quality: ${stream.quality}</div>
        `;
        
        // Test stream accessibility
        this.testAndDisplayStream(stream.url);
    }
    
    async testAndDisplayStream(streamUrl) {
        try {
            const streamTest = await window.gridlandAPI.testStream(streamUrl);
            
            if (streamTest.accessible) {
                this.displayStream(streamUrl);
            } else {
                this.showStreamError('Stream not accessible');
            }
        } catch (error) {
            console.error('Stream test failed:', error);
            this.showStreamError('Stream test failed');
        }
    }
    
    displayStream(streamUrl) {
        const streamPreview = document.getElementById('streamPreview');
        const streamVideo = document.getElementById('streamVideo');
        const placeholder = streamPreview.querySelector('.preview-placeholder');
        
        if (!streamVideo) return;
        
        // Hide placeholder
        if (placeholder) {
            placeholder.style.display = 'none';
        }
        
        // Show video element
        streamVideo.style.display = 'block';
        streamVideo.src = window.gridlandAPI.getStreamUrl(streamUrl);
        streamVideo.load();
        streamVideo.play().catch(error => {
            console.error('Stream playback failed:', error);
            this.showStreamError('Playback failed');
        });
    }
    
    showStreamError(message) {
        const streamInfo = document.getElementById('streamInfo');
        if (streamInfo) {
            streamInfo.innerHTML = `
                <div class="info-line">Status: Error</div>
                <div class="info-line">Error: ${message}</div>
                <div class="info-line">-</div>
            `;
        }
    }
    
    toggleFullScreen() {
        const streamVideo = document.getElementById('streamVideo');
        if (!streamVideo) return;
        
        if (document.fullscreenElement) {
            document.exitFullscreen();
        } else {
            streamVideo.requestFullscreen().catch(error => {
                console.error('Fullscreen failed:', error);
            });
        }
    }
    
    toggleRecording() {
        // Implementation for stream recording
        console.log('🎥 Toggle recording (not implemented)');
        window.macUI.showErrorDialog('Not Implemented', 'Stream recording is not yet implemented.');
    }
    
    // Channel guide functionality
    addToChannelGuide(target, streams) {
        const guideContent = document.getElementById('guideContent');
        if (!guideContent) return;
        
        const channelItem = document.createElement('div');
        channelItem.className = 'channel-item';
        channelItem.dataset.ip = target.ip;
        
        const deviceInfo = target.deviceInfo || {};
        const deviceName = deviceInfo.brand || 'Unknown Camera';
        const streamStatus = streams.length > 0 ? 'active' : 'inactive';
        
        channelItem.innerHTML = `
            <div class="channel-ip">📹 ${target.ip}:${target.port}</div>
            <div class="channel-device">${deviceName}</div>
            <div class="channel-status ${streamStatus}">
                ${streamStatus === 'active' ? '✅ Stream Active' : '❌ No Stream'}
            </div>
        `;
        
        channelItem.addEventListener('click', () => {
            if (streams.length > 0) {
                this.displayStream(streams[0].url);
            }
        });
        
        guideContent.appendChild(channelItem);
        
        // Show channel guide if hidden
        const channelGuide = document.getElementById('channelGuide');
        if (channelGuide && !channelGuide.classList.contains('visible')) {
            channelGuide.classList.add('visible');
        }
    }
    
    // UI update methods
    updateStatus(message) {
        const statusText = document.getElementById('statusText');
        if (statusText) {
            statusText.textContent = message;
        }
    }
    
    updateCounters() {
        const targetCount = document.getElementById('targetCount');
        const scanCount = document.getElementById('scanCount');
        const vulnCount = document.getElementById('vulnCount');
        
        const totalTargets = this.targets.size;
        const scannedTargets = Array.from(this.targets.values()).filter(t => t.status === 'complete').length;
        const totalVulns = Array.from(this.targets.values()).reduce((sum, t) => sum + t.vulnerabilities.length, 0);
        
        if (targetCount) targetCount.textContent = `Targets: ${totalTargets}`;
        if (scanCount) scanCount.textContent = `Scanned: ${scannedTargets}`;
        if (vulnCount) vulnCount.textContent = `Vulnerabilities: ${totalVulns}`;
    }
    
    // Configuration management
    async loadConfiguration() {
        try {
            this.config = await window.gridlandAPI.getConfiguration();
        } catch (error) {
            console.warn('Failed to load configuration:', error);
        }
    }
    
    async saveConfiguration() {
        try {
            await window.gridlandAPI.saveConfiguration(this.config);
            this.updateStatus('Configuration saved');
        } catch (error) {
            console.error('Failed to save configuration:', error);
            window.macUI.showErrorDialog('Save Failed', 'Failed to save configuration.');
        }
    }
    
    // Export functionality
    exportResults(format = 'json') {
        const results = {
            timestamp: new Date().toISOString(),
            targets: Array.from(this.targets.values()),
            summary: {
                total_targets: this.targets.size,
                scanned_targets: Array.from(this.targets.values()).filter(t => t.status === 'complete').length,
                total_vulnerabilities: Array.from(this.targets.values()).reduce((sum, t) => sum + t.vulnerabilities.length, 0),
                total_streams: Array.from(this.targets.values()).reduce((sum, t) => sum + t.streams.length, 0)
            }
        };
        
        const dataStr = JSON.stringify(results, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = `gridland-results-${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        
        this.updateStatus('Results exported');
    }
    
    // Cleanup
    cleanup() {
        if (this.currentAnalysis) {
            this.stopAnalysis();
        }
        
        window.gridlandAPI.cleanup();
    }
}

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.gridlandApp = new GridlandApp();
    
    // Bind additional UI events that require the app instance
    const addTargetBtn = document.getElementById('addTargetBtn');
    if (addTargetBtn) {
        addTargetBtn.addEventListener('click', () => {
            window.macUI.showModal('addTargetDialog');
        });
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.gridlandApp) {
        window.gridlandApp.cleanup();
    }
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GridlandApp;
}