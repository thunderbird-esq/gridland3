/**
 * Macintosh Plus UI Interaction Handler
 * Handles all System 6 authentic UI behaviors
 */

class MacUI {
    constructor() {
        this.windows = new Map();
        this.activeWindow = null;
        this.dragState = null;
        this.resizeState = null;
        this.menuState = null;
        this.selectedItems = new Set();
        
        this.initializeUI();
        this.bindEvents();
        this.startClock();
    }
    
    initializeUI() {
        // Initialize main window
        const mainWindow = document.getElementById('mainWindow');
        if (mainWindow) {
            this.windows.set('main', {
                element: mainWindow,
                title: 'GRIDLAND v3.0 - Security Reconnaissance',
                resizable: true,
                movable: true,
                active: true
            });
            this.activeWindow = 'main';
        }
        
        // Set initial window position
        this.centerWindow('main');
        
        // Initialize modal overlay
        this.modalOverlay = document.getElementById('modalOverlay');
        
        // Initialize tooltips
        this.initializeTooltips();
    }
    
    bindEvents() {
        // Window controls
        this.bindWindowControls();
        
        // Menu bar
        this.bindMenuBar();
        
        // Modal dialogs
        this.bindModalDialogs();
        
        // List interactions
        this.bindListInteractions();
        
        // Keyboard shortcuts
        this.bindKeyboardShortcuts();
        
        // Context menus
        this.bindContextMenus();
        
        // Drag and drop
        this.bindDragAndDrop();
    }
    
    bindWindowControls() {
        // Close box
        const closeBox = document.getElementById('closeBox');
        if (closeBox) {
            closeBox.addEventListener('click', (e) => {
                e.preventDefault();
                this.closeWindow('main');
            });
        }
        
        // Zoom box
        const zoomBox = document.getElementById('zoomBox');
        if (zoomBox) {
            zoomBox.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleWindowZoom('main');
            });
        }
        
        // Size box (resize handle)
        const sizeBox = document.getElementById('sizeBox');
        if (sizeBox) {
            sizeBox.addEventListener('mousedown', (e) => {
                this.startResize(e, 'main');
            });
        }
        
        // Title bar dragging
        const titleBar = document.querySelector('.title-bar');
        if (titleBar) {
            titleBar.addEventListener('mousedown', (e) => {
                if (e.target === titleBar || e.target.classList.contains('title')) {
                    this.startDrag(e, 'main');
                }
            });
        }
    }
    
    bindMenuBar() {
        const menuItems = document.querySelectorAll('.menu-item');
        
        menuItems.forEach(item => {
            item.addEventListener('click', (e) => {
                this.handleMenuClick(e.target.textContent.trim());
            });
            
            item.addEventListener('mouseenter', (e) => {
                if (this.menuState && this.menuState.active) {
                    this.showMenu(e.target.textContent.trim());
                }
            });
        });
        
        // Close menus when clicking elsewhere
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.menu-bar')) {
                this.closeAllMenus();
            }
        });
    }
    
    bindModalDialogs() {
        // About dialog
        const aboutOkBtn = document.getElementById('aboutOkBtn');
        if (aboutOkBtn) {
            aboutOkBtn.addEventListener('click', () => {
                this.hideModal('aboutDialog');
            });
        }
        
        // Add target dialog
        const addTargetOkBtn = document.getElementById('addTargetOkBtn');
        const addTargetCancelBtn = document.getElementById('addTargetCancelBtn');
        
        if (addTargetOkBtn) {
            addTargetOkBtn.addEventListener('click', () => {
                this.handleAddTarget();
            });
        }
        
        if (addTargetCancelBtn) {
            addTargetCancelBtn.addEventListener('click', () => {
                this.hideModal('addTargetDialog');
            });
        }
        
        // Progress dialog
        const progressCancelBtn = document.getElementById('progressCancelBtn');
        if (progressCancelBtn) {
            progressCancelBtn.addEventListener('click', () => {
                this.cancelCurrentOperation();
            });
        }
        
        // Error dialog
        const errorOkBtn = document.getElementById('errorOkBtn');
        if (errorOkBtn) {
            errorOkBtn.addEventListener('click', () => {
                this.hideModal('errorDialog');
            });
        }
        
        // Modal overlay click to close
        if (this.modalOverlay) {
            this.modalOverlay.addEventListener('click', (e) => {
                if (e.target === this.modalOverlay) {
                    this.hideAllModals();
                }
            });
        }
    }
    
    bindListInteractions() {
        // Discovery results list
        const targetList = document.getElementById('targetList');
        if (targetList) {
            targetList.addEventListener('click', (e) => {
                if (e.target.classList.contains('list-item') && !e.target.classList.contains('placeholder')) {
                    this.selectListItem(e.target);
                }
            });
            
            targetList.addEventListener('dblclick', (e) => {
                if (e.target.classList.contains('list-item') && !e.target.classList.contains('placeholder')) {
                    this.addTargetFromDiscovery(e.target);
                }
            });
        }
        
        // Analysis queue
        const queueContent = document.getElementById('queueContent');
        if (queueContent) {
            queueContent.addEventListener('click', (e) => {
                if (e.target.closest('.queue-item') && !e.target.closest('.queue-item').classList.contains('placeholder')) {
                    this.selectQueueItem(e.target.closest('.queue-item'));
                }
            });
        }
    }
    
    bindKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Handle keyboard shortcuts
            if (e.metaKey || e.ctrlKey) {
                switch (e.key.toLowerCase()) {
                    case 'n':
                        e.preventDefault();
                        this.newScan();
                        break;
                    case 'o':
                        e.preventDefault();
                        this.openTargetList();
                        break;
                    case 's':
                        e.preventDefault();
                        if (e.shiftKey) {
                            this.saveAs();
                        } else {
                            this.saveResults();
                        }
                        break;
                    case 'p':
                        e.preventDefault();
                        this.printReport();
                        break;
                    case 'q':
                        e.preventDefault();
                        this.quit();
                        break;
                    case 't':
                        e.preventDefault();
                        this.showModal('addTargetDialog');
                        break;
                    case 'd':
                        e.preventDefault();
                        this.focusDiscoveryQuery();
                        break;
                    case 'r':
                        e.preventDefault();
                        this.startAnalysis();
                        break;
                    case '.':
                        e.preventDefault();
                        this.stopAnalysis();
                        break;
                    case ',':
                        e.preventDefault();
                        this.showPreferences();
                        break;
                }
            }
            
            // Escape key
            if (e.key === 'Escape') {
                this.hideAllModals();
                this.closeAllMenus();
            }
            
            // Delete key
            if (e.key === 'Delete' || e.key === 'Backspace') {
                this.removeSelectedTarget();
            }
        });
    }
    
    bindContextMenus() {
        // Right-click context menus
        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            
            if (e.target.closest('.list-item')) {
                this.showContextMenu(e, 'target');
            } else if (e.target.closest('.queue-item')) {
                this.showContextMenu(e, 'queue');
            } else if (e.target.closest('.stream-preview')) {
                this.showContextMenu(e, 'stream');
            }
        });
    }
    
    bindDragAndDrop() {
        // File drop support for target lists
        const dropZones = document.querySelectorAll('.list-content, .queue-content');
        
        dropZones.forEach(zone => {
            zone.addEventListener('dragover', (e) => {
                e.preventDefault();
                zone.classList.add('drag-over');
            });
            
            zone.addEventListener('dragleave', (e) => {
                if (!zone.contains(e.relatedTarget)) {
                    zone.classList.remove('drag-over');
                }
            });
            
            zone.addEventListener('drop', (e) => {
                e.preventDefault();
                zone.classList.remove('drag-over');
                this.handleFileDrop(e);
            });
        });
    }
    
    // Window management
    centerWindow(windowId) {
        const window = this.windows.get(windowId);
        if (!window) return;
        
        const element = window.element;
        const rect = element.getBoundingClientRect();
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        
        const left = Math.max(0, (viewportWidth - rect.width) / 2);
        const top = Math.max(20, (viewportHeight - rect.height) / 2);
        
        element.style.left = `${left}px`;
        element.style.top = `${top}px`;
    }
    
    closeWindow(windowId) {
        if (windowId === 'main') {
            // Show quit confirmation
            this.showConfirmDialog(
                'Quit GRIDLAND?',
                'Are you sure you want to quit GRIDLAND? Any unsaved results will be lost.',
                () => {
                    window.close();
                }
            );
        }
    }
    
    toggleWindowZoom(windowId) {
        const window = this.windows.get(windowId);
        if (!window) return;
        
        const element = window.element;
        
        if (element.classList.contains('zoomed')) {
            // Restore original size
            element.classList.remove('zoomed');
            element.style.width = '760px';
            element.style.height = '520px';
            this.centerWindow(windowId);
        } else {
            // Zoom to fill screen
            element.classList.add('zoomed');
            element.style.left = '10px';
            element.style.top = '30px';
            element.style.width = `${window.innerWidth - 20}px`;
            element.style.height = `${window.innerHeight - 40}px`;
        }
    }
    
    startDrag(e, windowId) {
        const window = this.windows.get(windowId);
        if (!window || !window.movable) return;
        
        const element = window.element;
        const rect = element.getBoundingClientRect();
        
        this.dragState = {
            windowId: windowId,
            startX: e.clientX,
            startY: e.clientY,
            startLeft: rect.left,
            startTop: rect.top
        };
        
        document.addEventListener('mousemove', this.handleDrag.bind(this));
        document.addEventListener('mouseup', this.endDrag.bind(this));
        
        element.style.cursor = 'move';
        e.preventDefault();
    }
    
    handleDrag(e) {
        if (!this.dragState) return;
        
        const deltaX = e.clientX - this.dragState.startX;
        const deltaY = e.clientY - this.dragState.startY;
        
        const newLeft = Math.max(0, this.dragState.startLeft + deltaX);
        const newTop = Math.max(20, this.dragState.startTop + deltaY);
        
        const window = this.windows.get(this.dragState.windowId);
        window.element.style.left = `${newLeft}px`;
        window.element.style.top = `${newTop}px`;
    }
    
    endDrag() {
        if (this.dragState) {
            const window = this.windows.get(this.dragState.windowId);
            window.element.style.cursor = 'default';
            this.dragState = null;
        }
        
        document.removeEventListener('mousemove', this.handleDrag.bind(this));
        document.removeEventListener('mouseup', this.endDrag.bind(this));
    }
    
    startResize(e, windowId) {
        const window = this.windows.get(windowId);
        if (!window || !window.resizable) return;
        
        const element = window.element;
        const rect = element.getBoundingClientRect();
        
        this.resizeState = {
            windowId: windowId,
            startX: e.clientX,
            startY: e.clientY,
            startWidth: rect.width,
            startHeight: rect.height
        };
        
        document.addEventListener('mousemove', this.handleResize.bind(this));
        document.addEventListener('mouseup', this.endResize.bind(this));
        
        e.preventDefault();
    }
    
    handleResize(e) {
        if (!this.resizeState) return;
        
        const deltaX = e.clientX - this.resizeState.startX;
        const deltaY = e.clientY - this.resizeState.startY;
        
        const newWidth = Math.max(400, this.resizeState.startWidth + deltaX);
        const newHeight = Math.max(300, this.resizeState.startHeight + deltaY);
        
        const window = this.windows.get(this.resizeState.windowId);
        window.element.style.width = `${newWidth}px`;
        window.element.style.height = `${newHeight}px`;
    }
    
    endResize() {
        this.resizeState = null;
        document.removeEventListener('mousemove', this.handleResize.bind(this));
        document.removeEventListener('mouseup', this.endResize.bind(this));
    }
    
    // Modal dialog management
    showModal(dialogId) {
        const dialog = document.getElementById(dialogId);
        if (!dialog || !this.modalOverlay) return;
        
        // Hide all other dialogs
        this.hideAllModals();
        
        // Show overlay and dialog
        this.modalOverlay.style.display = 'flex';
        dialog.style.display = 'block';
        
        // Focus first input if available
        const firstInput = dialog.querySelector('input, button');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }
        
        // Play alert sound
        window.macSounds.playAlert();
    }
    
    hideModal(dialogId) {
        const dialog = document.getElementById(dialogId);
        if (dialog) {
            dialog.style.display = 'none';
        }
        
        // Hide overlay if no dialogs are visible
        const visibleDialogs = document.querySelectorAll('.mac-dialog[style*="block"]');
        if (visibleDialogs.length === 0) {
            this.modalOverlay.style.display = 'none';
        }
    }
    
    hideAllModals() {
        const dialogs = document.querySelectorAll('.mac-dialog');
        dialogs.forEach(dialog => {
            dialog.style.display = 'none';
        });
        
        if (this.modalOverlay) {
            this.modalOverlay.style.display = 'none';
        }
    }
    
    showErrorDialog(title, message) {
        const errorDialog = document.getElementById('errorDialog');
        const errorMessage = document.getElementById('errorMessage');
        
        if (errorMessage) {
            errorMessage.textContent = message;
        }
        
        this.showModal('errorDialog');
        window.macSounds.playError();
    }
    
    showConfirmDialog(title, message, onConfirm, onCancel) {
        // Create temporary confirm dialog
        const confirmDialog = document.createElement('div');
        confirmDialog.className = 'mac-dialog confirm-dialog';
        confirmDialog.innerHTML = `
            <div class="dialog-title-bar">
                <div class="dialog-title">${title}</div>
            </div>
            <div class="dialog-content">
                <div class="confirm-content">
                    <div class="confirm-icon">⚠️</div>
                    <div class="confirm-message">${message}</div>
                </div>
                <div class="dialog-buttons">
                    <button class="mac-button" id="confirmCancelBtn">Cancel</button>
                    <button class="mac-button default-button" id="confirmOkBtn">OK</button>
                </div>
            </div>
        `;
        
        this.modalOverlay.appendChild(confirmDialog);
        this.modalOverlay.style.display = 'flex';
        
        const okBtn = confirmDialog.querySelector('#confirmOkBtn');
        const cancelBtn = confirmDialog.querySelector('#confirmCancelBtn');
        
        const cleanup = () => {
            this.modalOverlay.removeChild(confirmDialog);
            this.modalOverlay.style.display = 'none';
        };
        
        okBtn.addEventListener('click', () => {
            cleanup();
            if (onConfirm) onConfirm();
        });
        
        cancelBtn.addEventListener('click', () => {
            cleanup();
            if (onCancel) onCancel();
        });
        
        window.macSounds.playAlert();
    }
    
    // List management
    selectListItem(item) {
        // Clear other selections in same list
        const list = item.closest('.list-content');
        const items = list.querySelectorAll('.list-item');
        items.forEach(i => i.classList.remove('selected'));
        
        // Select this item
        item.classList.add('selected');
        
        // Update UI state
        this.updateUIState();
    }
    
    selectQueueItem(item) {
        // Clear other selections
        const queue = item.closest('.queue-content');
        const items = queue.querySelectorAll('.queue-item');
        items.forEach(i => i.classList.remove('selected'));
        
        // Select this item
        item.classList.add('selected');
        
        // Update UI state
        this.updateUIState();
    }
    
    updateUIState() {
        // Update button states based on selections
        const removeBtn = document.getElementById('removeTargetBtn');
        const selectedQueue = document.querySelector('.queue-item.selected');
        
        if (removeBtn) {
            removeBtn.disabled = !selectedQueue;
        }
    }
    
    // Menu handling
    handleMenuClick(menuName) {
        switch (menuName) {
            case '🍎':
                this.showModal('aboutDialog');
                break;
            case 'File':
                this.showFileMenu();
                break;
            case 'Edit':
                this.showEditMenu();
                break;
            case 'Targets':
                this.showTargetsMenu();
                break;
            case 'Analysis':
                this.showAnalysisMenu();
                break;
            case 'Tools':
                this.showToolsMenu();
                break;
            case 'Window':
                this.showWindowMenu();
                break;
            case 'Help':
                this.showHelpMenu();
                break;
        }
    }
    
    closeAllMenus() {
        // Implementation for closing dropdown menus
        this.menuState = null;
    }
    
    // Clock
    startClock() {
        const updateClock = () => {
            const now = new Date();
            const timeString = now.toLocaleTimeString('en-US', {
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });
            
            const menuClock = document.getElementById('menuClock');
            const timeDisplay = document.getElementById('timeDisplay');
            
            if (menuClock) menuClock.textContent = timeString;
            if (timeDisplay) timeDisplay.textContent = timeString;
        };
        
        updateClock();
        setInterval(updateClock, 1000);
    }
    
    // Tooltips
    initializeTooltips() {
        const elementsWithTooltips = document.querySelectorAll('[data-tooltip]');
        
        elementsWithTooltips.forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(e, element.dataset.tooltip);
            });
            
            element.addEventListener('mouseleave', () => {
                this.hideTooltip();
            });
        });
    }
    
    showTooltip(e, text) {
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = text;
        tooltip.id = 'activeTooltip';
        
        document.body.appendChild(tooltip);
        
        // Position tooltip
        const rect = tooltip.getBoundingClientRect();
        const x = Math.min(e.clientX, window.innerWidth - rect.width - 10);
        const y = e.clientY - rect.height - 10;
        
        tooltip.style.left = `${x}px`;
        tooltip.style.top = `${y}px`;
    }
    
    hideTooltip() {
        const tooltip = document.getElementById('activeTooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }
    
    // Utility methods
    focusDiscoveryQuery() {
        const queryInput = document.getElementById('shodanQuery');
        if (queryInput) {
            queryInput.focus();
            queryInput.select();
        }
    }
    
    // Placeholder methods for menu actions
    newScan() { console.log('New Scan'); }
    openTargetList() { console.log('Open Target List'); }
    saveResults() { console.log('Save Results'); }
    saveAs() { console.log('Save As'); }
    printReport() { console.log('Print Report'); }
    quit() { this.closeWindow('main'); }
    showPreferences() { console.log('Show Preferences'); }
    removeSelectedTarget() { console.log('Remove Selected Target'); }
    startAnalysis() { console.log('Start Analysis'); }
    stopAnalysis() { console.log('Stop Analysis'); }
    
    // File drop handling
    handleFileDrop(e) {
        const files = Array.from(e.dataTransfer.files);
        console.log('Files dropped:', files);
        // Implementation for handling dropped target list files
    }
    
    // Context menu handling
    showContextMenu(e, type) {
        console.log('Show context menu:', type);
        // Implementation for context menus
    }
    
    // Add target from discovery
    addTargetFromDiscovery(item) {
        const ip = item.textContent.trim();
        if (ip && ip !== 'No targets discovered yet') {
            // Add to analysis queue
            window.gridlandApp.addTarget({ ip: ip, port: 80 });
        }
    }
    
    // Handle add target dialog
    handleAddTarget() {
        const ipInput = document.getElementById('targetIp');
        const portInput = document.getElementById('targetPort');
        
        if (!ipInput) return;
        
        const ip = ipInput.value.trim();
        const port = parseInt(portInput.value.trim()) || 80;
        
        if (!ip) {
            this.showErrorDialog('Invalid Input', 'Please enter a valid IP address.');
            return;
        }
        
        // Validate IP format
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            this.showErrorDialog('Invalid IP', 'Please enter a valid IP address format.');
            return;
        }
        
        // Add target
        window.gridlandApp.addTarget({ ip: ip, port: port });
        
        // Clear inputs and close dialog
        ipInput.value = '';
        portInput.value = '';
        this.hideModal('addTargetDialog');
    }
    
    // Cancel current operation
    cancelCurrentOperation() {
        if (window.gridlandApp) {
            window.gridlandApp.stopCurrentAnalysis();
        }
        this.hideModal('progressDialog');
    }
}

// Initialize UI when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.macUI = new MacUI();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MacUI;
}