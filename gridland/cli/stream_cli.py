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
@click.option('--duration', type=int, default=5, help='Recording duration in seconds.')
@click.option('--output', '-o', help='Output file path for recording.')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output from VLC.')
def stream(stream_url, record, duration, output, verbose):
    """
    Access and interact with a discovered video stream.

    STREAM_URL: The full RTSP or HTTP URL of the video stream.
    """
    logger.info(f"Attempting to connect to stream: {stream_url}")

    vlc_args = []
    if verbose:
        vlc_args.append('--verbose=2')

    try:
        instance = vlc.Instance(vlc_args)
    except vlc.VLCException as e:
        logger.error(f"Failed to initialize VLC instance: {e}")
        logger.error("This might be because the VLC application is not found.")
        logger.error(_get_vlc_install_instructions())
        sys.exit(1)

    if record:
        logger.info(f"Recording enabled for {duration} seconds.")
        if not output:
            parsed_url = urlparse(stream_url)
            host = parsed_url.hostname or "unknown"
            filename = f"{host}_{int(time.time())}.mp4"
            output = filename
            logger.info(f"No output file specified, using default: {output}")
        
        output_dir = os.path.dirname(output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        abs_output_path = os.path.abspath(output)
        sout = f'#standard{{access=file,mux=mp4,dst={abs_output_path}}}'
        
        media_options = [f':sout={sout}', ':sout-keep']
        
        try:
            player = instance.media_player_new()
            media = instance.media_new(stream_url, *media_options)
            player.set_media(media)

            click.echo(f"Recording stream to '{abs_output_path}'. This will take {duration} seconds.")
            player.play()
            
            time.sleep(duration)
            
            player.stop()
            player.release()
            logger.info(f"Recording finished successfully.")

        except Exception as e:
            logger.error(f"An error occurred during recording with python-vlc: {e}")

    else:
        logger.info(f"Launching VLC to view the stream...")
        try:
            player = instance.media_player_new()
            media = instance.media_new(stream_url)
            player.set_media(media)
            player.play()
            
            click.echo("VLC player launched. Press Ctrl+C in this terminal to stop the player.")
            # Keep the script alive while the player is running
            while player.get_state() not in [vlc.State.Ended, vlc.State.Error, vlc.State.Stopped]:
                time.sleep(1)
            
            player.release()

        except Exception as e:
            logger.error(f"Failed to launch VLC player: {e}")
        except KeyboardInterrupt:
            logger.info("Player stopped by user.")
            player.stop()
            player.release()

    logger.info("Stream interaction complete.")

