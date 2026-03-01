"""
Release Listener - Flask microservice for processing SonaType release scan webhooks.
"""
from release_listener.app import create_app, app

__all__ = ['create_app', 'app']
__version__ = '0.1.0'
