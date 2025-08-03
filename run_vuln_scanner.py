import os
from plugins.vulnerability_scanner import VulnerabilityScannerPlugin

if __name__ == "__main__":
    # Create an instance of the plugin
    plugin = VulnerabilityScannerPlugin()

    # Set the proxy URL
    proxy_url = "http://localhost:8080"
    os.environ["PROXY_URL"] = proxy_url

    # Run the scan
    plugin.scan("192.168.1.100")
