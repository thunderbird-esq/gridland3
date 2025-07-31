"""
Stream Interaction CLI for GRIDLAND Phase 4.

Command-line interface for accessing, viewing, and recording
discovered video streams using the python-vlc library.
"""

import click
from urllib.parse import urlparse
import time
import sys
import os
import vlc

from ..core.logger import get_logger

logger = get_logger(__name__)

def _get_vlc_install_instructions():
    """Provide OS-specific instructions for installing VLC."""
    platform = sys.platform
    if platform == "darwin":
        return "Please ensure the VLC application is installed in /Applications/."
    elif platform == "linux":
        return "To install, run: sudo apt-get update && sudo apt-get install -y vlc"
    else:
        return "Please install VLC from https://www.videolan.org/"

@click.command()
@click.argument('stream_url')
@click.option('--record', is_flag=True, help='Record the stream to a file.')
@click.option('--duration', type=int, default=10, help='Recording duration in seconds.')
@click.option('--output', '-o', help='Output file path for recording.')
def stream(stream_url, record, duration, output):
    """
    Access and interact with a discovered video stream.

    STREAM_URL: The full RTSP or HTTP URL of the video stream.
    """
    logger.info(f"Attempting to connect to stream: {stream_url}")

    try:
        instance = vlc.Instance()
    except vlc.VLCException as e:
        logger.error(f"Failed to initialize VLC instance: {e}")
        logger.error("This might be because the VLC application is not found.")
        logger.error(_get_vlc_install_instructions())
        sys.exit(1)

    if record:
        if not output:
            host = urlparse(stream_url).hostname or "stream"
            output = f"{host}_{int(time.time())}.mp4"
        
        sout = f'#standard{{access=file,mux=mp4,dst={os.path.abspath(output)}}}'
        media = instance.media_new(stream_url, f':sout={sout}', ':sout-keep')
        player = instance.media_player_new()
        player.set_media(media)
        
        click.echo(f"Recording for {duration} seconds...")
        player.play()
        
        time.sleep(duration)
        player.stop()
        logger.info(f"Recording saved to {output}")
    else:
        player = instance.media_player_new()
        media = instance.media_new(stream_url)
        player.set_media(media)
        player.play()

        click.echo("Player launched. Press Ctrl+C to stop.")
        try:
            while player.get_state() not in [vlc.State.Ended, vlc.State.Error, vlc.State.Stopped]:
                time.sleep(1)
        except KeyboardInterrupt:
            player.stop()
            logger.info("Player stopped.")

    logger.info("Stream interaction complete.")
