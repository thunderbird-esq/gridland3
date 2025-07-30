# GRIDLAND v3.0 - Macintosh Plus Native Interface

A pixel-perfect recreation of Apple System 6 user interface for GRIDLAND, the professional security reconnaissance toolkit. This interface provides an authentic 1987 Macintosh Plus experience while seamlessly integrating with the existing GRIDLAND v3.0 backend.

## 🖥️ System Requirements

- Modern web browser (Chrome, Firefox, Safari, Edge)
- GRIDLAND v3.0 backend server running on port 8080
- Audio support for authentic Mac sound effects
- Minimum screen resolution: 800x600

## 🚀 Quick Start

1. **Start GRIDLAND Backend**:
   ```bash
   cd /path/to/HB-v2-gemmy-072525
   python server.py
   ```

2. **Access Mac Interface**:
   Open your browser to: `http://localhost:8080/ui/`

3. **Begin Reconnaissance**:
   - Enter Shodan query in "Target Discovery" panel
   - Click "Discover" to find targets
   - Double-click targets to add to analysis queue
   - Click "Start Analysis" to begin security scanning

## 🎯 Features

### Authentic System 6 Experience
- **Pixel-perfect UI**: Exact recreation of Macintosh Plus interface
- **Chicago Font**: Authentic System 6 typography
- **Classic Sounds**: Original Mac startup chime, button clicks, alerts
- **Window Management**: Draggable windows with resize handles
- **Modal Dialogs**: Period-accurate dialog boxes

### GRIDLAND Integration
- **Backend Compatibility**: Uses existing Flask server endpoints
- **Real-time Analysis**: Server-Sent Events for live scan progress
- **Stream Monitoring**: Integrated RTSP stream viewing
- **Plugin System**: Displays results from 6 security plugins
- **Configuration Sync**: Integrates with existing config system

### Security Features
- **Target Discovery**: Shodan API integration via existing `/discover` endpoint
- **Vulnerability Analysis**: Real-time security scanning via `/scan` endpoint
- **Stream Detection**: Automatic RTSP/HTTP stream discovery
- **Device Fingerprinting**: Camera brand and model identification
- **CVE Correlation**: Known vulnerability detection

## 📁 File Structure

```
gridland-ui/
├── index.html              # Main application shell
├── css/
│   ├── system.css          # Core Macintosh Plus UI framework
│   └── gridland.css        # Application-specific styles
├── js/
│   ├── app.js              # Main application logic
│   ├── ui.js               # UI interaction handlers
│   ├── gridland-api.js     # Backend API integration
│   └── sounds.js           # Audio management
├── sounds/                 # Authentic Mac sound effects
├── fonts/                  # Chicago and Monaco fonts
└── README.md              # This file
```

## 🔧 Backend Integration

### Existing Endpoints Used
- `POST /discover` - Target discovery via Shodan
- `POST /scan` - Security analysis with Server-Sent Events
- `GET /stream/<encoded_url>` - RTSP stream transcoding

### API Integration Pattern
```javascript
// Discovery
const targets = await gridlandAPI.discoverTargets(query);

// Analysis with real-time updates
gridlandAPI.startAnalysis(target, onProgress, onComplete, onError);

// Stream viewing
const streamUrl = gridlandAPI.getStreamUrl(rtspUrl);
```

## 🎨 UI Components

### Main Window (760x520px)
- **Target Discovery Panel**: Shodan query interface and results list
- **Analysis Queue Panel**: Target management and scan progress
- **Stream Monitor Panel**: Live video feed preview

### Modal Dialogs
- **About GRIDLAND**: Application information
- **Add Target**: Manual target entry
- **Progress Dialog**: Real-time scan progress
- **Error Dialogs**: System 6 style error messages

### Menu Bar
```
🍎 | File | Edit | Targets | Analysis | Tools | Window | Help
```

## 🔊 Audio System

Authentic Macintosh Plus sound effects:
- **Startup Chime**: Application launch
- **Button Clicks**: UI interaction feedback
- **Alert Beeps**: Error messages and confirmations
- **Success Chimes**: Completed operations

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| ⌘N | New Scan |
| ⌘O | Open Target List |
| ⌘S | Save Results |
| ⌘T | Add Target |
| ⌘D | Focus Discovery Query |
| ⌘R | Start Analysis |
| ⌘. | Stop Analysis |
| ⌘Q | Quit Application |

## 🔒 Security Considerations

- **Read-Only Backend**: UI does not modify existing GRIDLAND code
- **API Integration**: Uses existing security-validated endpoints
- **Input Validation**: Client-side validation for IP addresses
- **Error Handling**: Graceful degradation for network issues

## 🛠️ Development

### Adding New Features
1. Extend `js/app.js` for application logic
2. Add UI components to `index.html`
3. Style with System 6 patterns in `css/gridland.css`
4. Integrate with backend via `js/gridland-api.js`

### Customization
- Modify color scheme in CSS custom properties
- Add new sound effects in `js/sounds.js`
- Extend menu system in `js/ui.js`

## 🐛 Troubleshooting

### Common Issues

**"No targets discovered"**
- Verify Shodan API key is configured in backend
- Check network connectivity
- Try different search queries

**"Analysis failed"**
- Ensure GRIDLAND backend is running
- Check browser console for errors
- Verify target IP addresses are valid

**"Stream not accessible"**
- Confirm RTSP stream URL is correct
- Check if authentication is required
- Verify GStreamer is installed on backend

### Browser Compatibility
- **Chrome/Edge**: Full feature support
- **Firefox**: Full feature support
- **Safari**: Full feature support (may need audio permission)
- **Mobile**: Basic functionality (not optimized)

## 📚 References

- [GRIDLAND v3.0 Documentation](../DEVLOG.md)
- [Apple System 6 Interface Guidelines](https://en.wikipedia.org/wiki/System_6)
- [system.css Framework](https://github.com/sakofchit/system.css/)

## 🤝 Contributing

This UI is designed to integrate with the existing GRIDLAND codebase without modification. When contributing:

1. **Preserve Backend**: Do not modify any files outside `gridland-ui/`
2. **Maintain Authenticity**: Follow System 6 design patterns
3. **Test Integration**: Verify compatibility with existing endpoints
4. **Document Changes**: Update this README for new features

## 📄 License

This interface extends GRIDLAND v3.0 and inherits its licensing terms. The Macintosh Plus aesthetic is used for educational and research purposes in accordance with fair use principles.

---

**Built with ❤️ for the security research community**  
*Bringing 1987 aesthetics to 2025 security tools*