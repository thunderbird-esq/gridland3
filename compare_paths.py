#!/usr/bin/env python3
"""Compare stream paths between CamXploit.py and stream_paths.json"""

import json

# CamXploit.py paths (lines 1579-1683)
camxploit_paths = {
    "rtsp": [
        # Generic paths
        "/live.sdp",
        "/h264.sdp",
        "/stream1",
        "/stream2",
        "/main",
        "/sub",
        "/video",
        "/cam/realmonitor",
        "/Streaming/Channels/1",
        "/Streaming/Channels/101",
        # Brand-specific paths
        "/onvif/streaming/channels/1",  # ONVIF
        "/axis-media/media.amp",  # Axis
        "/axis-cgi/mjpg/video.cgi",  # Axis
        "/cgi-bin/mjpg/video.cgi",  # Generic
        "/cgi-bin/hi3510/snap.cgi",  # Hikvision
        "/cgi-bin/snapshot.cgi",  # Generic
        "/cgi-bin/viewer/video.jpg",  # Generic
        "/img/snapshot.cgi",  # Generic
        "/snapshot.jpg",  # Generic
        "/video/mjpg.cgi",  # Generic
        "/video.cgi",  # Generic
        "/videostream.cgi",  # Generic
        "/mjpg/video.mjpg",  # Generic
        "/mjpg.cgi",  # Generic
        "/stream.cgi",  # Generic
        "/live.cgi",  # Generic
        "/live/0/onvif.sdp",  # ONVIF
        "/live/0/h264.sdp",  # Generic
        "/live/0/mpeg4.sdp",  # Generic
        "/live/0/audio.sdp",  # Generic
        "/live/1/onvif.sdp",  # ONVIF
        "/live/1/h264.sdp",  # Generic
        "/live/1/mpeg4.sdp",  # Generic
        "/live/1/audio.sdp",  # Generic
    ],
    "rtmp": [
        "/live",
        "/stream",
        "/hls",
        "/flv",
        "/rtmp",
        "/live/stream",
        "/live/stream1",
        "/live/stream2",
        "/live/main",
        "/live/sub",
        "/live/video",
        "/live/audio",
        "/live/av",
        "/live/rtmp",
        "/live/rtmps",
    ],
    "http": [
        # Generic paths
        "/video",
        "/stream",
        "/mjpg/video.mjpg",
        "/cgi-bin/mjpg/video.cgi",
        "/axis-cgi/mjpg/video.cgi",
        "/cgi-bin/viewer/video.jpg",
        "/snapshot.jpg",
        "/img/snapshot.cgi",
        # Brand-specific paths
        "/onvif/device_service",  # ONVIF
        "/onvif/streaming",  # ONVIF
        "/axis-cgi/com/ptz.cgi",  # Axis
        "/axis-cgi/param.cgi",  # Axis
        "/cgi-bin/snapshot.cgi",  # Generic
        "/cgi-bin/hi3510/snap.cgi",  # Hikvision
        "/video/mjpg.cgi",  # Generic
        "/video.cgi",  # Generic
        "/videostream.cgi",  # Generic
        "/mjpg.cgi",  # Generic
        "/stream.cgi",  # Generic
        "/live.cgi",  # Generic
        # Additional paths
        "/api/video",  # API endpoints
        "/api/stream",
        "/api/live",
        "/api/video/live",
        "/api/stream/live",
        "/api/camera/live",
        "/api/camera/stream",
        "/api/camera/video",
        "/api/camera/snapshot",
        "/api/camera/image",
        "/api/camera/feed",
        "/api/camera/feed/live",
        "/api/camera/feed/stream",
        "/api/camera/feed/video",
        # CP Plus specific paths
        "/cgi-bin/video.cgi",
        "/cgi-bin/stream.cgi",
        "/cgi-bin/live.cgi",
    ],
}

# Load GRIDLAND stream_paths.json
with open("/home/user/gridland3/gridland/data/stream_paths.json") as f:
    gridland_data = json.load(f)


# Flatten GRIDLAND paths by protocol
def flatten_paths(protocol_data):
    """Flatten nested protocol paths into a single list"""
    paths = []
    if isinstance(protocol_data, dict):
        for key, value in protocol_data.items():
            if isinstance(value, list):
                paths.extend(value)
            elif isinstance(value, dict):
                paths.extend(flatten_paths(value))
    elif isinstance(protocol_data, list):
        paths.extend(protocol_data)
    return paths


gridland_paths = {
    "rtsp": flatten_paths(gridland_data["protocols"]["rtsp"]),
    "rtmp": flatten_paths(gridland_data["protocols"]["rtmp"]),
    "http": flatten_paths(gridland_data["protocols"]["http"]),
}

# Find missing paths
print("=" * 80)
print("STREAM PATHS COMPARISON: CamXploit.py vs GRIDLAND")
print("=" * 80)
print()

for protocol in ["rtsp", "rtmp", "http"]:
    camx_set = set(camxploit_paths[protocol])
    grid_set = set(gridland_paths[protocol])

    missing = camx_set - grid_set

    print(f"{protocol.upper()} Protocol:")
    print(f"  CamXploit paths: {len(camx_set)}")
    print(f"  GRIDLAND paths:  {len(grid_set)}")
    print(f"  Missing in GRIDLAND: {len(missing)}")

    if missing:
        print(f"  Missing paths:")
        for path in sorted(missing):
            print(f"    - {path}")
    else:
        print(f"  ✓ All CamXploit paths are present!")
    print()

# Total counts
total_camx = sum(len(camxploit_paths[p]) for p in ["rtsp", "rtmp", "http"])
total_grid = sum(len(gridland_paths[p]) for p in ["rtsp", "rtmp", "http"])

print("=" * 80)
print(f"TOTAL PATHS:")
print(f"  CamXploit.py: {total_camx} paths")
print(f"  GRIDLAND:     {total_grid} paths")
print(f"  Requirement:  138+ paths")
print(f"  Status: {'✓ PASS' if total_grid >= 138 else '✗ FAIL'}")
print("=" * 80)
