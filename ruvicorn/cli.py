"""
Command-line interface for Ruvicorn.
"""

import click
import sys
import os
import yaml
from pathlib import Path
from typing import Optional, Dict, Any
import logging
import asyncio
from functools import partial

from .server import RuvicornServer
from .config import Config, AutoConfig, ConfigurationError

def print_version(ctx, param, value):
    """Print the version and exit."""
    if not value or ctx.resilient_parsing:
        return
    import pkg_resources
    version = pkg_resources.get_distribution('ruvicorn').version
    click.echo(f"Ruvicorn {version}")
    ctx.exit()

def load_yaml_config(path: Path) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        click.echo(f"Error loading configuration file: {e}", err=True)
        sys.exit(1)

async def run_server(config: Config):
    """Run the server with the given configuration."""
    server = RuvicornServer(config.app, config=config)
    
    try:
        await server.start()
    except Exception as e:
        click.echo(f"Error starting server: {e}", err=True)
        sys.exit(1)
    finally:
        await server.shutdown()

@click.command()
@click.argument('app', required=False)
@click.option(
    '--config',
    type=click.Path(exists=True, dir_okay=False),
    help='Path to YAML configuration file.'
)
@click.option(
    '--host',
    type=str,
    help='Bind socket to this host.'
)
@click.option(
    '--port',
    type=int,
    help='Bind socket to this port.'
)
@click.option(
    '--reload',
    is_flag=True,
    help='Enable auto-reload with enhanced hot reload capabilities.'
)
@click.option(
    '--workers',
    type=int,
    help='Number of worker processes.'
)
@click.option(
    '--log-level',
    type=click.Choice(
        ['critical', 'error', 'warning', 'info', 'debug'],
        case_sensitive=False
    ),
    help='Log level.'
)
@click.option(
    '--log-format',
    type=click.Choice(['json', 'text'], case_sensitive=False),
    help='Log format.'
)
@click.option(
    '--metrics/--no-metrics',
    default=None,
    help='Enable/disable metrics collection.'
)
@click.option(
    '--prometheus/--no-prometheus',
    default=None,
    help='Enable/disable Prometheus metrics.'
)
@click.option(
    '--ssl-keyfile',
    type=click.Path(exists=True),
    help='SSL key file'
)
@click.option(
    '--ssl-certfile',
    type=click.Path(exists=True),
    help='SSL certificate file'
)
@click.option(
    '--ssl-version',
    type=int,
    help='SSL version to use'
)
@click.option(
    '--ssl-cert-reqs',
    type=int,
    help='Whether client certificate is required'
)
@click.option(
    '--auto-detect/--no-auto-detect',
    default=True,
    help='Enable/disable automatic project detection and optimization.'
)
@click.option(
    '--version',
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help='Show version information and exit.'
)
def main(
    app: Optional[str],
    config: Optional[str],
    **options
):
    """
    Ruvicorn - Enhanced ASGI Server Implementation
    
    Run an ASGI application with enhanced features including automatic
    project detection, improved hot reload, structured logging, and
    comprehensive middleware support.
    
    Examples:
    
    \b
    # Run with automatic project detection
    $ ruvicorn
    
    \b
    # Run a specific application
    $ ruvicorn myapp:app
    
    \b
    # Run with configuration file
    $ ruvicorn --config ruvicorn.yml
    
    \b
    # Run with hot reload and metrics
    $ ruvicorn myapp:app --reload --metrics
    """
    # Load configuration
    if config:
        config_path = Path(config)
        config_data = load_yaml_config(config_path)
        
        # Override with command line options
        for key, value in options.items():
            if value is not None:
                config_data[key] = value
        
        if app:
            config_data['app'] = app
        
        try:
            if config_data.get('auto_detect', True):
                config_obj = AutoConfig(**config_data)
            else:
                config_obj = Config(**config_data)
        except ConfigurationError as e:
            click.echo(f"Configuration error: {e}", err=True)
            sys.exit(1)
    else:
        # Use command line options or defaults
        config_data = {k: v for k, v in options.items() if v is not None}
        if app:
            config_data['app'] = app
        
        try:
            if config_data.get('auto_detect', True):
                config_obj = AutoConfig(**config_data)
            else:
                config_obj = Config(**config_data)
        except ConfigurationError as e:
            click.echo(f"Configuration error: {e}", err=True)
            sys.exit(1)
    
    # Set up logging
    log_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'handlers': {
            'default': {
                'class': 'logging.StreamHandler',
                'formatter': 'colored' if sys.stderr.isatty() else 'simple'
            }
        },
        'formatters': {
            'colored': {
                '()': 'colorlog.ColoredFormatter',
                'format': '%(log_color)s%(levelname)-8s%(reset)s %(message)s'
            },
            'simple': {
                'format': '%(levelname)s: %(message)s'
            }
        },
        'root': {
            'level': config_obj.log_level.upper(),
            'handlers': ['default']
        }
    }
    
    logging.config.dictConfig(log_config)
    
    # Print startup message
    click.echo(
        f"Starting Ruvicorn server at "
        f"{config_obj.host}:{config_obj.port}"
    )
    
    if config_obj.reload:
        click.echo("Enhanced hot reload is active")
    
    if config_obj.metrics_enabled:
        click.echo(
            "Metrics collection is enabled"
            + (" with Prometheus support" if config_obj.prometheus_enabled else "")
        )
    
    # Run the server
    if sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(run_server(config_obj))
    except KeyboardInterrupt:
        click.echo("\nShutting down server")
    finally:
        loop.close()

if __name__ == '__main__':
    main()
