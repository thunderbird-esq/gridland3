/**
 * Macintosh Plus Sound System
 * Authentic System 6 audio feedback
 */

class MacSounds {
    constructor() {
        this.sounds = {};
        this.enabled = true;
        this.volume = 0.7;
        
        // Load authentic Mac sounds
        this.loadSounds();
        
        // Bind to user interaction for audio context
        this.audioContext = null;
        this.initAudioContext();
    }
    
    initAudioContext() {
        // Modern browsers require user interaction before playing audio
        const initAudio = () => {
            if (!this.audioContext) {
                this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            }
            document.removeEventListener('click', initAudio);
            document.removeEventListener('keydown', initAudio);
        };
        
        document.addEventListener('click', initAudio);
        document.addEventListener('keydown', initAudio);
    }
    
    loadSounds() {
        const soundFiles = {
            startup: 'sounds/mac-startup.wav',
            button: 'sounds/mac-button.wav',
            alert: 'sounds/mac-alert.wav',
            success: 'sounds/mac-success.wav',
            error: 'sounds/mac-error.wav',
            tick: 'sounds/mac-tick.wav'
        };
        
        for (const [name, path] of Object.entries(soundFiles)) {
            this.sounds[name] = new Audio(path);
            this.sounds[name].volume = this.volume;
            this.sounds[name].preload = 'auto';
            
            // Handle loading errors gracefully
            this.sounds[name].addEventListener('error', () => {
                console.warn(`Failed to load sound: ${path}`);
                // Create silent fallback
                this.sounds[name] = {
                    play: () => Promise.resolve(),
                    pause: () => {},
                    currentTime: 0
                };
            });
        }
    }
    
    play(soundName) {
        if (!this.enabled || !this.sounds[soundName]) {
            return Promise.resolve();
        }
        
        try {
            // Reset sound to beginning
            this.sounds[soundName].currentTime = 0;
            return this.sounds[soundName].play();
        } catch (error) {
            console.warn(`Failed to play sound: ${soundName}`, error);
            return Promise.resolve();
        }
    }
    
    setVolume(volume) {
        this.volume = Math.max(0, Math.min(1, volume));
        for (const sound of Object.values(this.sounds)) {
            if (sound.volume !== undefined) {
                sound.volume = this.volume;
            }
        }
    }
    
    setEnabled(enabled) {
        this.enabled = enabled;
    }
    
    // Convenience methods for common sounds
    playStartup() {
        return this.play('startup');
    }
    
    playButton() {
        return this.play('button');
    }
    
    playAlert() {
        return this.play('alert');
    }
    
    playSuccess() {
        return this.play('success');
    }
    
    playError() {
        return this.play('error');
    }
    
    playTick() {
        return this.play('tick');
    }
}

// Create global instance
window.macSounds = new MacSounds();

// Auto-play startup sound when page loads
window.addEventListener('load', () => {
    // Delay startup sound slightly for better UX
    setTimeout(() => {
        window.macSounds.playStartup();
    }, 500);
});

// Add sound effects to common UI interactions
document.addEventListener('DOMContentLoaded', () => {
    // Button click sounds
    document.addEventListener('click', (event) => {
        if (event.target.matches('.mac-button')) {
            window.macSounds.playButton();
        }
    });
    
    // Menu item sounds
    document.addEventListener('click', (event) => {
        if (event.target.matches('.menu-item')) {
            window.macSounds.playTick();
        }
    });
    
    // List item selection sounds
    document.addEventListener('click', (event) => {
        if (event.target.matches('.list-item:not(.placeholder)')) {
            window.macSounds.playTick();
        }
    });
    
    // Window control sounds
    document.addEventListener('click', (event) => {
        if (event.target.matches('.close-box, .zoom-box')) {
            window.macSounds.playButton();
        }
    });
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MacSounds;
}