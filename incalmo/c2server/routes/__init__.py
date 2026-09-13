"""
Routes module for the C2 server.
Contains all route blueprints organized by functionality.
"""

from .agent_routes import agent_bp
from .command_routes import command_bp
from .strategy_routes import strategy_bp
from .logging_routes import logging_bp
from .file_routes import file_bp
from .environment_routes import environment_bp
from .llm_routes import llm_bp
from .usage_routes import usage_bp

__all__ = [
    "agent_bp",
    "command_bp",
    "strategy_bp",
    "logging_bp",
    "file_bp",
    "environment_bp",
    "llm_bp",
    "usage_bp",
]
