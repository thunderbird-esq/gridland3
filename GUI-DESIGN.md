# GRIDLAND GUI Design Document

## Design Philosophy

**Professional pentesting tool interface principles:**
- **Function over form** - Every pixel serves a purpose
- **Real-time feedback** - Immediate visibility into scan progress
- **Evidence collection** - Built-in screenshot and documentation tools
- **Client presentation ready** - Professional output suitable for executive briefings
- **Resource aware** - Shows system impact and allows performance tuning

## Target Users

**Primary:** Penetration testers conducting authorized network assessments
**Secondary:** Security consultants preparing client deliverables
**Tertiary:** Network administrators performing internal security audits

## Core Design Requirements

### 1. Performance First
- **Never block the UI thread** - All scanning operations asynchronous
- **Real-time progress** - Live updates with actual scan metrics
- **Resource monitoring** - CPU, memory, network usage visible
- **Pause/resume capability** - Full control over long-running scans

### 2. Professional Output
- **Client-ready reports** - PDF generation with company branding
- **Evidence archival** - Automatic screenshot capture and organization
- **Executive summaries** - High-level risk assessment with business impact
- **Technical details** - Complete technical findings for remediation teams

### 3. Campaign Management
- **Multi-target projects** - Organize scans by client/engagement
- **Progress tracking** - Visual representation of assessment completion
- **Team collaboration** - Share results and coordinate testing efforts
- **Historical comparison** - Track security posture changes over time

## Main Application Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ GRIDLAND Security Assessment Platform                    [_][□][×]│
├─────────────────────────────────────────────────────────────────┤
│ File  Campaign  Scan  Reports  Tools  Help              🔴 REC   │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────────────────────────────────────┐ │
│ │  CAMPAIGNS  │ │             MAIN WORKSPACE                  │ │
│ │             │ │                                             │ │
│ │ ▼ Client A  │ │  ┌─────────────────────────────────────┐   │ │
│ │   Network 1 │ │  │          TARGET CONFIGURATION       │   │ │
│ │   Network 2 │ │  │                                     │   │ │
│ │ ▷ Client B  │ │  │ Target: [192.168.1.0/24        ] [⚙] │   │ │
│ │ ▷ Internal  │ │  │                                     │   │ │
│ │             │ │  │ ☑ Aggressive Scanning               │   │ │
│ │             │ │  │ ☑ Credential Testing               │   │ │
│ │             │ │  │ ☑ Stream Discovery                 │   │ │
│ │             │ │  │ ☑ Evidence Collection              │   │ │
│ │             │ │  │                                     │   │ │
│ │             │ │  │ Threads: [100  ] Timeout: [1.5s]   │   │ │
│ │             │ │  │                                     │   │ │
│ │             │ │  │     [🚀 START SCAN]                 │   │ │
│ │             │ │  └─────────────────────────────────────┘   │ │
│ └─────────────┘ └─────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │                    SCAN PROGRESS                            │ │
│ │                                                             │ │
│ │ Status: Scanning 192.168.1.0/24 (47/254 hosts complete)    │ │
│ │ ████████████████████░░░░░░░░░░░░░░░░░░░░ 67%                │ │
│ │                                                             │ │
│ │ Current: 192.168.1.47 (5 open ports found)                 │ │
│ │ Rate: 15.2 hosts/sec | Threads: 100/100 | Memory: 245MB    │ │
│ │                                                             │ │
│ │ [⏸ PAUSE] [⏹ STOP] [📊 STATS] [⚙ ADJUST]                   │ │
│ └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│ Status: Ready | 15 devices found | 3 high-risk | 🔴 Recording   │
└─────────────────────────────────────────────────────────────────┘
```

## Primary Panels

### 1. Campaign Management Panel (Left Sidebar)

**Purpose:** Organize multiple assessments and track progress

**Features:**
- **Campaign tree structure** - Client → Engagement → Network segments
- **Progress indicators** - Visual completion status for each scope
- **Quick access buttons** - Jump to specific scan results or reports
- **Search and filter** - Find specific campaigns or targets quickly

**Visual Design:**
```
┌─────────────────┐
│  🏢 Acme Corp   │
│  ├─ 📅 Q4 Audit │
│  │  ├─ 🌐 DMZ    │ ███████████████░ 85%
│  │  └─ 🌐 LAN    │ ████████░░░░░░░░ 45%
│  └─ 📅 Incident  │
│     └─ 🌐 Cameras│ ███████████████████ 100%
│                 │
│  🏢 TechStart   │
│  └─ 📅 Initial  │ ░░░░░░░░░░░░░░░░ 0%
└─────────────────┘
```

### 2. Target Configuration Panel

**Purpose:** Configure scan parameters with professional presets

**Features:**
- **Target input** - IP ranges, CIDR notation, file import
- **Scan profiles** - Stealth, Balanced, Aggressive, Custom
- **Performance tuning** - Thread count, timeouts, rate limiting
- **Scope validation** - Verify authorization before scanning

**Configuration Options:**
```
Target Specification:
├─ Single IP: 192.168.1.100
├─ IP Range: 192.168.1.1-192.168.1.254  
├─ CIDR: 192.168.1.0/24
├─ File Import: Browse... (targets.txt)
└─ Exclude List: 192.168.1.1,192.168.1.10

Scan Profile:
├─ 🎯 Stealth (Low threads, long timeouts)
├─ ⚖️ Balanced (Default CamXploit.py settings)
├─ 🔥 Aggressive (High threads, credential testing)
└─ ⚙️ Custom (Manual configuration)

Evidence Collection:
├─ ☑ Auto-screenshot vulnerable interfaces
├─ ☑ Record video of successful logins
├─ ☑ Capture network traffic samples
└─ ☑ Export configuration files
```

### 3. Real-time Results Panel

**Purpose:** Live visualization of scan results as they're discovered

**Features:**
- **Live target list** - Updates as devices are discovered
- **Risk categorization** - Color-coded threat levels
- **Quick actions** - Screenshot, test, investigate buttons
- **Filtering and sorting** - Focus on specific device types or risks

**Results Table:**
```
┌──────────────┬────────────┬──────────────┬──────────────┬─────────────┐
│ IP Address   │ Ports Open │ Device Type  │ Risk Level   │ Actions     │
├──────────────┼────────────┼──────────────┼──────────────┼─────────────┤
│ 192.168.1.10 │ 80,8080    │ 🔴 Hikvision │ 🔥 CRITICAL  │ [📷][🔑][📊] │
│ 192.168.1.15 │ 554,8554   │ 🟡 Generic   │ ⚠️ MEDIUM    │ [📷][🔑][📊] │
│ 192.168.1.23 │ 80,443     │ 🟢 Axis      │ ℹ️ LOW       │ [📷][🔑][📊] │
│ 192.168.1.31 │ 80,8080    │ 🔴 CP Plus   │ 🔥 CRITICAL  │ [📷][🔑][📊] │
└──────────────┴────────────┴──────────────┴──────────────┴─────────────┘

Filters: [All] [Cameras Only] [High Risk] [Compromised] [Has Streams]
Sort by: [Risk Level ▼] [IP Address] [Device Type] [Ports]
```

### 4. Evidence Collection Panel

**Purpose:** Automated documentation and proof-of-concept collection

**Features:**
- **Auto-screenshot** - Capture admin interfaces automatically
- **Video recording** - Record successful authentication attempts  
- **File extraction** - Download configuration files safely
- **Organized storage** - Automatic file naming and organization

**Evidence View:**
```
┌─────────────────────────────────────────┐
│ 📁 Evidence: 192.168.1.10 (Hikvision)  │
│                                         │
│ 📷 Screenshots (4)                      │
│ ├─ login_interface.png                  │
│ ├─ admin_dashboard.png                  │
│ ├─ system_info.png                      │
│ └─ stream_config.png                    │
│                                         │
│ 🎥 Videos (1)                           │
│ └─ successful_login.mp4                 │
│                                         │
│ 📄 Files (2)                            │
│ ├─ system_configuration.xml             │
│ └─ user_accounts.txt                    │
│                                         │
│ [📤 Export All] [🗑️ Delete] [📝 Notes]   │
└─────────────────────────────────────────┘
```

## Secondary Windows

### 1. Device Details Window

**Purpose:** Deep dive into individual device findings

**Features:**
- **Complete port scan results** - All open ports with service detection
- **Vulnerability details** - CVE information with exploit availability
- **Credential test results** - Working username/password combinations
- **Stream information** - Live video feed preview when available

### 2. Report Generation Window

**Purpose:** Create professional client deliverables

**Features:**
- **Template selection** - Executive summary, technical details, compliance
- **Branding customization** - Company logos, colors, contact information
- **Content filtering** - Include/exclude specific findings
- **Export formats** - PDF, HTML, JSON, CSV

### 3. Network Visualization Window

**Purpose:** Visual representation of network topology and relationships

**Features:**
- **Network map** - Graphical representation of discovered devices
- **Relationship lines** - Show network connections and VLANs
- **Risk heat map** - Color-coded security posture visualization
- **Interactive exploration** - Click devices for detailed information

## Technical Implementation

### Framework Selection: Qt6 with Python

**Rationale:**
- **Cross-platform** - Windows, macOS, Linux support
- **Performance** - Native rendering with efficient threading
- **Professional appearance** - Corporate-grade UI components
- **Rich widgets** - Built-in support for complex layouts and controls
- **Python integration** - Seamless integration with existing scanner code

### Architecture Overview

```
GUI Application (Qt6)
├─ MainWindow (QMainWindow)
│  ├─ CampaignPanel (QTreeWidget)
│  ├─ ConfigPanel (QGroupBox)
│  ├─ ResultsPanel (QTableWidget)
│  └─ ProgressPanel (QProgressBar + QLabel)
├─ ScanWorker (QThread)
│  └─ GridlandScanner (from gridland_clean.py)
├─ EvidenceManager (QDialog)
│  ├─ ScreenshotCapture (QPixmap)
│  ├─ VideoRecorder (QMediaRecorder)
│  └─ FileExtractor (QFileDialog)
└─ ReportGenerator (QDialog)
   ├─ TemplateEngine (Jinja2)
   ├─ PDFExporter (ReportLab)
   └─ HTMLExporter (QWebEngine)
```

### Performance Considerations

**Threading Model:**
- **Main UI thread** - Handles all GUI updates and user interactions
- **Scanner worker threads** - Execute scanning operations asynchronously
- **Evidence worker threads** - Handle screenshot/video capture without blocking
- **Report worker threads** - Generate large reports in background

**Memory Management:**
- **Result streaming** - Process and display results as they arrive
- **Evidence caching** - Intelligent caching of screenshots and files
- **Large dataset handling** - Pagination for thousands of results
- **Memory pooling** - Reuse objects for better performance

### Security Features

**Data Protection:**
- **Encrypted storage** - All results and evidence encrypted at rest
- **Secure transmission** - TLS for any network communications
- **Access control** - User authentication and role-based permissions
- **Audit logging** - Complete activity trail for compliance

**Operational Security:**
- **Session management** - Automatic timeout and secure session handling
- **Evidence integrity** - Cryptographic hashing for evidence files
- **Secure deletion** - Proper cleanup of sensitive data
- **Compliance reporting** - Generate audit trails for security reviews

## User Experience Flow

### 1. Campaign Setup
1. Create new campaign with client information
2. Define network scope and exclusions
3. Select scan profile (stealth vs aggressive)
4. Configure evidence collection preferences
5. Validate authorization and scope

### 2. Scanning Execution  
1. Launch scan with real-time progress monitoring
2. View live results as devices are discovered
3. Automatically collect evidence for high-risk findings
4. Pause/adjust scan parameters based on network response
5. Monitor system resources and network impact

### 3. Analysis and Investigation
1. Review discovered devices and vulnerabilities
2. Investigate specific targets with detailed scanning
3. Test credentials and access additional services
4. Capture additional evidence for verification
5. Document findings with screenshots and notes

### 4. Report Generation
1. Select appropriate report template for audience
2. Customize content and branding elements
3. Generate executive summary with business impact
4. Include technical details for remediation teams
5. Export in multiple formats for different stakeholders

This GUI design transforms GRIDLAND from a command-line tool into a professional security assessment platform suitable for enterprise penetration testing engagements.