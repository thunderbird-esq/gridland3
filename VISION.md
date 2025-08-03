# VISION.md: A More Advanced Plugin Architecture

## Introduction

This document outlines the vision for the "Priority 5" architectural enhancements. The goal of these changes was to evolve the plugin system from a simple, linear execution model into a more dynamic and intelligent one, where plugins can interact with each other and adapt to the findings of the scan in real-time.

## The Vision: From Linear to Dynamic

The existing plugin architecture is simple and effective: it runs each plugin one by one. However, this has some limitations:
-   **Inefficiency**: Plugins run regardless of whether their target functionality is present. For example, the `ONVIFScannerPlugin` runs even if the `BannerGrabberPlugin` has already determined that no ONVIF service is present.
-   **Lack of Collaboration**: Plugins cannot share information. For example, the `VulnerabilityScannerPlugin` could be much more effective if it knew the specific server version found by the `BannerGrabberPlugin`.

The "Priority 5" enhancements were designed to address these limitations by introducing two key concepts: **Plugin Chaining** and **Conditional Execution**.

### 1. Plugin Chaining: Sharing Intelligence

Plugin chaining is the ability for one plugin to use the findings of another.

**Example (The Old Way):**
The `VulnerabilityScannerPlugin` identifies the brand of a device and then checks for all known CVEs for that brand. This is good, but it can lead to false positives if the specific version of the software is not vulnerable.

**Example (The Vision):**
1.  The `BannerGrabberPlugin` runs and identifies the exact server header, e.g., `"Hikvision-Webs v5.2.0"`. It creates a `Finding` with this information.
2.  The `PluginManager` passes this finding to the `VulnerabilityScannerPlugin`.
3.  The `VulnerabilityScannerPlugin` now knows the exact version. Instead of just reporting all potential Hikvision CVEs, it can check its `VULNERABLE_VERSIONS` database and report a **confirmed** vulnerability for CVE-2017-7921, which is specific to version 5.2.0.

This makes the scanner much more accurate and reduces noise in the results.

### 2. Conditional Execution: Scanning Smarter

Conditional execution is the ability for a plugin to only run if certain conditions are met, based on the findings of previous plugins.

**Example (The Old Way):**
The `CredentialScannerPlugin` runs on any device that has a web port open. This is inefficient if the web interface is not a login page.

**Example (The Vision):**
1.  The `WebInterfaceScannerPlugin` runs and identifies a login page at `http://192.168.1.100/login.html`. It creates a `Finding` for this.
2.  The `CredentialScannerPlugin` has a dependency on the `WebInterfaceScannerPlugin`. Its `can_scan` method checks the `previous_findings` for a "web_interface" finding with `requires_auth: True`.
3.  If such a finding exists, the `CredentialScannerPlugin` runs. If not, it is skipped, saving time and resources.

## The Implementation Attempt

To achieve this vision, I attempted the following architectural changes:
-   **`get_dependencies()` method**: Added to the `ScannerPlugin` base class for plugins to declare their dependencies.
-   **Topological Sort**: Implemented in the `PluginManager` to create a correct execution order.
-   **Passing `previous_findings`**: Modified the `scan` and `can_scan` methods to accept the list of all previous findings.

Unfortunately, I was unable to get the tests for this new architecture to pass. The interactions between the plugins and the test mocks proved to be too complex for me to debug successfully.

## Conclusion

The vision for a more advanced plugin architecture remains a sound one. It would make the scanner more efficient, more accurate, and more intelligent. I believe the implementation I started is on the right track, but it will require a more experienced developer to resolve the testing issues and bring it to completion.
