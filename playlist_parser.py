#!/usr/bin/env python3
"""
Playlist Parser for HelloBird Test Protocols
Extracts camera endpoints from M3U playlists for validation testing
"""

import re
import requests
from urllib.parse import urlparse
from typing import List, Dict, Tuple
import concurrent.futures
import time

class PlaylistParser:
    def __init__(self, playlist_path: str):
        self.playlist_path = playlist_path
        self.endpoints = []
        
    def parse_m3u(self) -> List[Dict[str, str]]:
        """Parse M3U playlist and extract camera endpoints"""
        endpoints = []
        
        with open(self.playlist_path, 'r') as f:
            lines = f.readlines()
            
        current_title = None
        for line in lines:
            line = line.strip()
            
            if line.startswith('#EXTINF'):
                # Extract title from EXTINF line
                match = re.search(r'#EXTINF:-1,\s*(.+)', line)
                if match:
                    current_title = match.group(1).strip()
                    
            elif line.startswith('http'):
                # This is a URL line
                parsed_url = urlparse(line)
                
                endpoint = {
                    'title': current_title or 'Unknown',
                    'url': line,
                    'ip': parsed_url.hostname,
                    'port': parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
                    'path': parsed_url.path,
                    'scheme': parsed_url.scheme,
                    'brand': self._detect_brand(line),
                    'stream_type': self._detect_stream_type(line)
                }
                endpoints.append(endpoint)
                current_title = None  # Reset for next entry
                
        self.endpoints = endpoints
        return endpoints
    
    def _detect_brand(self, url: str) -> str:
        """Detect camera brand from URL patterns"""
        if 'axis-cgi' in url:
            return 'Axis'
        elif 'nphMotionJpeg' in url:
            return 'Generic MJPEG'
        elif '/control/' in url:
            return 'Generic Control'
        elif 'mjpg/video.mjpg' in url:
            return 'Generic MJPEG'
        elif 'faststream.jpg' in url:
            return 'Generic Faststream'
        elif 'CgiStart' in url:
            return 'Generic CGI'
        return 'Unknown'
    
    def _detect_stream_type(self, url: str) -> str:
        """Detect stream type from URL patterns"""
        if 'mjpeg' in url.lower() or 'mjpg' in url.lower():
            return 'MJPEG'
        elif 'faststream.jpg' in url:
            return 'JPEG'
        elif 'userimage.html' in url:
            return 'HTML'
        elif 'viewer_index.shtml' in url:
            return 'SHTML'
        elif 'live/index.html' in url:
            return 'HTML_LIVE'
        return 'Unknown'
    
    def validate_endpoint(self, endpoint: Dict[str, str], timeout: int = 5) -> Dict[str, any]:
        """Test if an endpoint is accessible"""
        try:
            response = requests.get(
                endpoint['url'], 
                timeout=timeout,
                verify=False,
                allow_redirects=True
            )
            
            return {
                'endpoint': endpoint,
                'accessible': True,
                'status_code': response.status_code,
                'content_type': response.headers.get('content-type', 'unknown'),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'error': None
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'endpoint': endpoint,
                'accessible': False,
                'status_code': None,
                'content_type': None,
                'content_length': 0,
                'response_time': None,
                'error': str(e)
            }
    
    def batch_validate(self, max_workers: int = 20, timeout: int = 5) -> List[Dict[str, any]]:
        """Validate all endpoints concurrently"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_endpoint = {
                executor.submit(self.validate_endpoint, endpoint, timeout): endpoint 
                for endpoint in self.endpoints
            }
            
            for future in concurrent.futures.as_completed(future_to_endpoint):
                result = future.result()
                results.append(result)
                
                # Print progress
                status = "✓" if result['accessible'] else "✗"
                ip = result['endpoint']['ip']
                print(f"{status} {ip}:{result['endpoint']['port']} - {result['endpoint']['brand']}")
                
        return results
    
    def generate_test_targets(self, only_accessible: bool = True) -> List[str]:
        """Generate list of IP addresses for CamXploit testing"""
        if not hasattr(self, 'validation_results'):
            print("Run batch_validate() first to get accessibility data")
            return []
            
        targets = []
        for result in self.validation_results:
            if only_accessible and not result['accessible']:
                continue
                
            ip = result['endpoint']['ip']
            if ip not in targets:
                targets.append(ip)
                
        return targets
    
    def export_accessible_playlist(self, output_path: str):
        """Export only accessible endpoints to new M3U playlist"""
        if not hasattr(self, 'validation_results'):
            print("Run batch_validate() first to get accessibility data")
            return
            
        with open(output_path, 'w') as f:
            f.write("#EXTM3U\n")
            
            for result in self.validation_results:
                if result['accessible']:
                    endpoint = result['endpoint']
                    f.write(f"#EXTINF:-1, {endpoint['title']} [{endpoint['brand']}]\n")
                    f.write(f"{endpoint['url']}\n")

def main():
    parser = PlaylistParser('/Users/michaelraftery/HB-v2-gemmy-072525/gridland/public-ip-cams.md')
    
    print("Parsing M3U playlist...")
    endpoints = parser.parse_m3u()
    print(f"Found {len(endpoints)} camera endpoints")
    
    print("\nValidating endpoints...")
    results = parser.batch_validate(max_workers=10, timeout=3)
    parser.validation_results = results
    
    accessible_count = sum(1 for r in results if r['accessible'])
    print(f"\nValidation complete: {accessible_count}/{len(results)} endpoints accessible")
    
    # Export accessible endpoints
    parser.export_accessible_playlist('gridland/accessible-cams.m3u')
    print("Exported accessible endpoints to gridland/accessible-cams.m3u")
    
    # Generate test targets for CamXploit
    targets = parser.generate_test_targets()
    print(f"\nGenerated {len(targets)} unique IP targets for scanning")
    
    with open('gridland/test-targets.txt', 'w') as f:
        for target in targets:
            f.write(f"{target}\n")
    print("Saved targets to gridland/test-targets.txt")

if __name__ == "__main__":
    main()