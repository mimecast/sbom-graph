"""
Release Listener - Flask microservice for processing SonaType release scan webhooks.
"""

from sonatype_lifecycle_release_listener.app import create_app, app

__all__ = ["create_app", "app"]
__version__ = "1.0.0"
