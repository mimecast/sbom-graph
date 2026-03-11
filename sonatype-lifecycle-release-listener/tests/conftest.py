"""
Pytest configuration and shared fixtures for sonatype-lifecycle-release-listener tests.
"""

import sys
import os

# Add the src directory to the Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Configure logging for tests to avoid logging.conf issues
import logging

logging.basicConfig(level=logging.DEBUG)
