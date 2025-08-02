#!/usr/bin/env python3
"""
GRIDLAND Real Scanner - Standalone executable
Based entirely on working CamXploit.py functionality
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from gridland.cli.real_cli import gridland

if __name__ == '__main__':
    gridland()