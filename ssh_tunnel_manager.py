#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH Tunnel Manager with Web Interface

This script manages multiple SSH tunnels based on a JSON configuration file or a file containing SSH command strings.
It includes a Flask web interface for real-time monitoring and management of the tunnels.

Features:
- Web interface accessible at http://127.0.0.1:9966 (default)
- Start, stop, restart tunnels from the web interface
- Configure auto-reconnect attempts per tunnel from the panel
- Highlight tunnel rows based on status: green (active), yellow (restarting), red (offline)
- Day/Night mode toggle button
- Emojis and icons added for visual enhancement
- All CSS and JS files are served locally; no external dependencies
- Simple statistics about the number of loaded tunnels and their statuses
- Sorting functionality for the tunnel list
- Config file supports groups and comments for tunnels

**Security Note:**
Storing passwords in plaintext is insecure.
Consider using SSH key authentication for better security.

Author: Your Name
Date: YYYY-MM-DD
"""

import asyncio
import subprocess
import logging
import os
import sys
import time
import signal
import traceback
import json
import argparse
import shutil
from typing import Dict, List
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response

app = Flask(__name__)

# Added NO_HOST_KEY_CHECKING and NO_TTY parameters
NO_HOST_KEY_CHECKING = ["-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no"]
NO_TTY = ["-T", "-N"]

class GlobalSettings:
    """
    Global settings for the SSH tunnel manager.
    """
    def __init__(self):
        self.log_file = "ssh_tunnel_manager.log"
        self.log_level = logging.INFO
        self.config: List[Dict] = []
        self.clients: Dict[str, 'SSHClient'] = {}
        self.stop_event = asyncio.Event()
        self.config_path = None
        self.loop = None
        self.web_host = '127.0.0.1'
        self.web_port = 9966

global_settings = GlobalSettings()

def setup_logging():
    """
    Sets up logging to file and console.
    """
    logger = logging.getLogger()
    logger.setLevel(global_settings.log_level)

    # Formatter for logs
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # File handler
    file_handler = logging.FileHandler(global_settings.log_file)
    file_handler.setLevel(global_settings.log_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(global_settings.log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def log(message, level='INFO'):
    """
    Logs a message with the specified level.
    """
    level = level.upper()
    if level == 'ERROR':
        logging.error(message)
    elif level == 'DEBUG':
        logging.debug(message)
    elif level == 'WARNING':
        logging.warning(message)
    else:
        logging.info(message)

def load_config(config_path):
    """
    Loads the configuration from a JSON file or SSH commands file and validates it.
    """
    if not os.path.exists(config_path):
        log(f"Configuration file '{config_path}' not found.", "ERROR")
        sys.exit(1)
    try:
        with open(config_path, 'r') as f:
            # Check if the file is JSON
            try:
                config = json.load(f)
                validate_config(config)
                global_settings.config = config
            except json.JSONDecodeError:
                # If not JSON, treat it as SSH commands file
                f.seek(0)
                ssh_commands = f.readlines()
                config = parse_ssh_commands(ssh_commands)
                validate_config(config)
                global_settings.config = config
    except Exception as e:
        log(f"Unexpected error loading configuration: {e}", "ERROR")
        sys.exit(1)

def parse_ssh_commands(ssh_commands):
    """
    Parses SSH command strings and converts them into configuration entries.
    """
    config = []
    serial_number = 1
    for cmd in ssh_commands:
        cmd = cmd.strip()
        if not cmd or cmd.startswith('#'):
            continue  # Skip empty lines and comments
        try:
            ssh_config = parse_ssh_command(cmd)
            ssh_config['serial_number'] = serial_number
            serial_number += 1
            config.append(ssh_config)
        except Exception as e:
            log(f"Error parsing SSH command: {cmd}\n{e}", "ERROR")
            sys.exit(1)
    return config

def parse_ssh_command(cmd):
    """
    Parses a single SSH command string into a configuration dictionary.
    """
    import shlex
    tokens = shlex.split(cmd)
    if tokens[0] == 'sshpass':
        if tokens[1] != '-p':
            raise ValueError("Expected '-p' after 'sshpass'")
        password = tokens[2]
        tokens = tokens[3:]
    else:
        password = ''
    if tokens[0] != 'ssh':
        raise ValueError("Expected 'ssh' command")
    ssh_options = []
    user = ''
    host = ''
    port = 22
    local_port = None
    name = ''
    group = 'Default'
    comment = ''
    i = 1
    while i < len(tokens):
        if tokens[i] == '-p':
            port = int(tokens[i+1])
            i += 2
        elif tokens[i] == '-D':
            local_port = int(tokens[i+1])
            i += 2
        elif tokens[i].startswith('-'):
            ssh_options.extend([tokens[i], tokens[i+1]])
            i += 2
        elif '@' in tokens[i]:
            user_host = tokens[i]
            if ':' in user_host:
                user_host, port = user_host.split(':')
                port = int(port)
            if '@' in user_host:
                user, host = user_host.split('@')
            else:
                host = user_host
            i += 1
        else:
            i += 1
    if not host:
        raise ValueError("Host not specified in SSH command")
    if not user:
        raise ValueError("Username not specified in SSH command")
    if not local_port:
        raise ValueError("Local port not specified in SSH command")
    name = f"tunnel_{host}_{local_port}"
    ssh_config = {
        'name': name,
        'host': host,
        'port': port,
        'username': user,
        'password': password,
        'local_port': local_port,
        'group': group,
        'comment': comment,
        'ssh_options': ssh_options
    }
    return ssh_config

def save_config():
    """
    Saves the current configuration to the JSON file.
    """
    try:
        with open(global_settings.config_path, 'w') as f:
            json.dump(global_settings.config, f, indent=4)
        log(f"Configuration saved to '{global_settings.config_path}'", "INFO")
    except Exception as e:
        log(f"Error saving configuration: {e}", "ERROR")

def validate_config(config):
    """
    Validates the configuration file.
    """
    required_keys = {'name', 'host', 'port', 'username', 'password', 'local_port'}
    for idx, ssh_config in enumerate(config):
        if not required_keys.issubset(ssh_config.keys()):
            missing = required_keys - ssh_config.keys()
            log(f"Configuration entry {idx} is missing keys: {missing}", "ERROR")
            sys.exit(1)
        if not isinstance(ssh_config['port'], int) or not isinstance(ssh_config['local_port'], int):
            log(f"Invalid port numbers in configuration entry {idx}.", "ERROR")
            sys.exit(1)

def parse_arguments():
    """
    Parses command-line arguments.
    """
    parser = argparse.ArgumentParser(description='SSH Tunnel Manager with Web Interface')
    parser.add_argument('-c', '--config', required=True, help='Path to JSON configuration file or SSH commands file')
    parser.add_argument('--log-level', default='INFO', help='Set logging level (DEBUG, INFO, WARNING, ERROR)')
    parser.add_argument('--web-host', default='127.0.0.1', help='Host for the web interface (default: 127.0.0.1)')
    parser.add_argument('--web-port', default=9966, type=int, help='Port for the web interface (default: 9966)')
    args = parser.parse_args()
    return args

async def monitor_clients():
    """
    Monitors the state of SSH clients and restarts them if necessary.
    """
    while not global_settings.stop_event.is_set():
        for name, client in global_settings.clients.items():
            if not client.is_running() and client.auto_reconnects > 0 and not client.stop_event.is_set():
                client.status = 'restarting'
                log(f"Tunnel '{name}' is not running. Attempting to restart...", "WARNING")
                asyncio.create_task(client.start())
            elif not client.is_running() and client.auto_reconnects == 0 and not client.stop_event.is_set():
                client.status = 'stopped'
        await asyncio.sleep(5)

class SSHClient:
    """
    Manages an individual SSH connection.
    """
    def __init__(self, ssh_config):
        self.ssh_config = ssh_config
        self.process = None
        self.stop_event = asyncio.Event()
        self.name = ssh_config['name']
        self.group = ssh_config.get('group', 'Default')
        self.comment = ssh_config.get('comment', '')
        self.serial_number = ssh_config.get('serial_number', 0)
        self.status = 'stopped'
        self.auto_reconnects = ssh_config.get('auto_reconnects', 0)
        self.max_reconnects = ssh_config.get('max_reconnects', 0)
        self.reconnect_attempts = 0

        # SSH options
        self.CIPHERS = "3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
        self.MACS = "hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-512,hmac-md5,hmac-md5-96,umac-64@openssh.com,umac-128@openssh.com"
        self.KEX_ALGORITHMS = "diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256,sntrup761x25519-sha512@openssh.com"

    async def start(self):
        """
        Starts the SSH tunnel process asynchronously.
        """
        if self.is_running():
            log(f"SSH tunnel '{self.name}' is already running.", "WARNING")
            return
        self.stop_event.clear()
        self.reconnect_attempts = 0
        while not self.stop_event.is_set():
            try:
                await self.start_ssh_tunnel()
                if not self.stop_event.is_set():
                    self.status = 'stopped'
            except Exception as e:
                log(f"Error in SSHClient '{self.name}': {e}", "ERROR")
                log(traceback.format_exc(), "DEBUG")
            if not self.stop_event.is_set() and self.auto_reconnects > 0:
                self.reconnect_attempts += 1
                if self.reconnect_attempts >= self.max_reconnects:
                    log(f"Max reconnect attempts reached for tunnel '{self.name}'.", "WARNING")
                    self.auto_reconnects = 0
                    self.status = 'stopped'
                    break
                else:
                    log(f"SSH tunnel '{self.name}' disconnected. Restarting in 5 seconds... (Attempt {self.reconnect_attempts}/{self.max_reconnects})", "WARNING")
                    self.status = 'restarting'
                    await asyncio.sleep(5)
            else:
                break

    async def start_ssh_tunnel(self):
        """
        Starts the SSH tunnel process.
        """
        ssh_command = self.build_ssh_command()
        log(f"Starting SSH tunnel '{self.name}'...", "INFO")
        self.status = 'starting'
        self.process = await asyncio.create_subprocess_exec(
            *ssh_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        self.status = 'running'

        # Read and log SSH output
        await asyncio.gather(
            self.read_stream(self.process.stdout, "DEBUG"),
            self.read_stream(self.process.stderr, "ERROR"),
            self.monitor_process()
        )

    async def read_stream(self, stream, log_level):
        """
        Reads an asynchronous stream line by line and logs the output.
        """
        while True:
            line = await stream.readline()
            if line:
                log(f"[{self.name}] {line.decode().strip()}", log_level)
            else:
                break

    async def monitor_process(self):
        """
        Monitors the SSH process and handles its termination.
        """
        try:
            return_code = await self.process.wait()
            if return_code != 0:
                log(f"SSH tunnel '{self.name}' exited with code {return_code}", "ERROR")
                self.status = 'stopped'
            else:
                log(f"SSH tunnel '{self.name}' exited normally.", "INFO")
                self.status = 'stopped'
        except asyncio.CancelledError:
            self.process.terminate()
            await self.process.wait()
            log(f"SSH tunnel '{self.name}' terminated.", "INFO")
            self.status = 'stopped'
        except Exception as e:
            log(f"Error while monitoring SSH tunnel '{self.name}': {e}", "ERROR")
            self.status = 'stopped'

    def build_ssh_command(self):
        """
        Builds the SSH command based on the configuration.
        """
        ssh_config = self.ssh_config
        command = []
        if ssh_config['password']:
            command.extend(['sshpass', '-p', ssh_config['password']])
        command.extend([
            'ssh',
            '-vvv',  # Enable verbose logging
            '-D', str(ssh_config['local_port']),
            '-o', "ServerAliveInterval=60",
            '-o', "ServerAliveCountMax=3",
            '-o', "TCPKeepAlive=yes",
            '-o', "LogLevel=DEBUG",
            '-o', f"Ciphers={self.CIPHERS}",
            '-o', f"MACs={self.MACS}",
            '-o', f"KexAlgorithms={self.KEX_ALGORITHMS}",
        ])
        # Include NO_HOST_KEY_CHECKING and NO_TTY options
        command.extend(NO_HOST_KEY_CHECKING)
        command.extend(NO_TTY)
        # Include any additional SSH options
        if 'ssh_options' in ssh_config and ssh_config['ssh_options']:
            command.extend(ssh_config['ssh_options'])
        command.extend([
            f"{ssh_config['username']}@{ssh_config['host']}",
            '-p', str(ssh_config['port'])
        ])
        return command

    def stop(self):
        """
        Stops the SSH tunnel process.
        """
        self.stop_event.set()
        self.auto_reconnects = 0
        self.reconnect_attempts = 0
        if self.process and self.process.returncode is None:
            try:
                self.process.terminate()
                log(f"SSH tunnel '{self.name}' terminated.", "INFO")
            except ProcessLookupError:
                log(f"SSH tunnel '{self.name}' process already terminated.", "WARNING")
            except Exception as e:
                log(f"Error terminating SSH tunnel '{self.name}': {e}", "ERROR")
                log(traceback.format_exc(), "DEBUG")
        self.status = 'stopped'

    def is_running(self):
        """
        Checks if the SSH tunnel process is running.
        """
        return self.process and self.process.returncode is None

def setup_signal_handlers(loop):
    """
    Sets up signal handlers for graceful shutdown and configuration reload.
    """
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(loop, signal=s)))
    except NotImplementedError:
        # Signal handlers are not implemented on Windows
        pass

async def shutdown(loop, signal=None):
    """
    Performs a graceful shutdown.
    """
    if signal:
        log(f"Received exit signal {signal.name}...", "INFO")

    global_settings.stop_event.set()

    # Cancel all tasks
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    [task.cancel() for task in tasks]

    log("Cancelling outstanding tasks", "DEBUG")
    await asyncio.gather(*tasks, return_exceptions=True)

    log("Stopping clients...", "INFO")
    for client in global_settings.clients.values():
        client.stop()
    await asyncio.sleep(1)

    loop.stop()
    log("Shutdown complete.", "INFO")

async def start_clients():
    """
    Initializes SSH clients based on the current configuration without starting them.
    """
    for ssh_config in global_settings.config:
        name = ssh_config['name']
        if name in global_settings.clients:
            continue
        client = SSHClient(ssh_config)
        global_settings.clients[name] = client

@app.route('/')
def index():
    """
    Renders the main page of the web interface.
    """
    tunnels = []
    for client in global_settings.clients.values():
        tunnels.append({
            'serial_number': client.serial_number,
            'name': client.name,
            'host': client.ssh_config['host'],
            'port': client.ssh_config['port'],
            'username': client.ssh_config['username'],
            'local_port': client.ssh_config['local_port'],
            'status': client.status,
            'group': client.group,
            'comment': client.comment,
            'max_reconnects': client.max_reconnects,
            'auto_reconnects': client.auto_reconnects,
        })
    # Sorting tunnels by serial_number
    tunnels.sort(key=lambda x: x['serial_number'])
    groups = sorted(set(t['group'] for t in tunnels))
    # Statistics
    total_tunnels = len(tunnels)
    active_tunnels = sum(1 for t in tunnels if t['status'] == 'running')

    # Get theme from cookie
    theme = request.cookies.get('theme', 'light')

    return render_template('index.html', tunnels=tunnels, groups=groups, total_tunnels=total_tunnels, active_tunnels=active_tunnels, theme=theme)

def safe_int(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

@app.route('/start/<tunnel_name>', methods=['POST'])
def start_tunnel(tunnel_name):
    """
    Starts a specified tunnel.
    """
    client = global_settings.clients.get(tunnel_name)
    if client:
        max_reconnects = safe_int(request.form.get('max_reconnects', 0))
        client.max_reconnects = max_reconnects
        client.auto_reconnects = max_reconnects
        client.reconnect_attempts = 0
        asyncio.run_coroutine_threadsafe(client.start(), global_settings.loop)
    return redirect(url_for('index'))

@app.route('/stop/<tunnel_name>', methods=['POST'])
def stop_tunnel(tunnel_name):
    """
    Stops a specified tunnel.
    """
    client = global_settings.clients.get(tunnel_name)
    if client:
        client.stop()
    return redirect(url_for('index'))

@app.route('/restart/<tunnel_name>', methods=['POST'])
def restart_tunnel(tunnel_name):
    """
    Restarts a specified tunnel.
    """
    client = global_settings.clients.get(tunnel_name)
    if client:
        client.stop()
        max_reconnects = safe_int(request.form.get('max_reconnects', 0))
        client.max_reconnects = max_reconnects
        client.auto_reconnects = max_reconnects
        client.reconnect_attempts = 0
        asyncio.run_coroutine_threadsafe(client.start(), global_settings.loop)
    return redirect(url_for('index'))

@app.route('/add', methods=['GET', 'POST'])
def add_tunnel():
    """
    Adds a new tunnel.
    """
    if request.method == 'POST':
        serial_number = len(global_settings.config) + 1
        ssh_config = {
            'name': request.form['name'],
            'host': request.form['host'],
            'port': int(request.form['port']),
            'username': request.form['username'],
            'password': request.form['password'],
            'local_port': int(request.form['local_port']),
            'group': request.form.get('group', 'Default'),
            'comment': request.form.get('comment', ''),
            'serial_number': serial_number,
            'max_reconnects': safe_int(request.form.get('max_reconnects', 0)),
        }
        global_settings.config.append(ssh_config)
        save_config()
        # Initialize the new tunnel
        client = SSHClient(ssh_config)
        global_settings.clients[ssh_config['name']] = client
        return redirect(url_for('index'))
    else:
        theme = request.cookies.get('theme', 'light')
        return render_template('add.html', theme=theme)

@app.route('/delete', methods=['POST'])
def delete_tunnels():
    """
    Deletes selected tunnels.
    """
    selected_tunnels = request.form.getlist('selected_tunnels')
    for tunnel_name in selected_tunnels:
        client = global_settings.clients.get(tunnel_name)
        if client:
            client.stop()
            del global_settings.clients[tunnel_name]
            # Remove from config
            global_settings.config = [cfg for cfg in global_settings.config if cfg['name'] != tunnel_name]
    save_config()
    return redirect(url_for('index'))

@app.route('/update/<tunnel_name>', methods=['GET', 'POST'])
def update_tunnel(tunnel_name):
    """
    Updates the configuration of a specified tunnel.
    """
    client = global_settings.clients.get(tunnel_name)
    if not client:
        return redirect(url_for('index'))
    if request.method == 'POST':
        # Stop the tunnel
        client.stop()
        # Update configuration
        client.ssh_config['host'] = request.form['host']
        client.ssh_config['port'] = int(request.form['port'])
        client.ssh_config['username'] = request.form['username']
        client.ssh_config['password'] = request.form['password']
        client.ssh_config['local_port'] = int(request.form['local_port'])
        client.group = request.form.get('group', 'Default')
        client.comment = request.form.get('comment', '')
        client.max_reconnects = safe_int(request.form.get('max_reconnects', 0))
        save_config()
        return redirect(url_for('index'))
    else:
        theme = request.cookies.get('theme', 'light')
        return render_template('update.html', tunnel=client.ssh_config, group=client.group, comment=client.comment, theme=theme)

@app.route('/bulk_action', methods=['POST'])
def bulk_action():
    """
    Performs bulk actions on selected tunnels.
    """
    action = request.form['action']
    max_reconnects = safe_int(request.form.get('max_reconnects', 0))
    selected_tunnels = request.form.getlist('selected_tunnels')
    for tunnel_name in selected_tunnels:
        client = global_settings.clients.get(tunnel_name)
        if client:
            if action == 'start':
                client.max_reconnects = max_reconnects
                client.auto_reconnects = max_reconnects
                client.reconnect_attempts = 0
                asyncio.run_coroutine_threadsafe(client.start(), global_settings.loop)
            elif action == 'stop':
                client.stop()
            elif action == 'restart':
                client.stop()
                client.max_reconnects = max_reconnects
                client.auto_reconnects = max_reconnects
                client.reconnect_attempts = 0
                asyncio.run_coroutine_threadsafe(client.start(), global_settings.loop)
            elif action == 'delete':
                client.stop()
                del global_settings.clients[tunnel_name]
                global_settings.config = [cfg for cfg in global_settings.config if cfg['name'] != tunnel_name]
    save_config()
    return redirect(url_for('index'))

@app.route('/logs')
def logs():
    """
    Returns the last N lines from the log file.
    """
    N = 100  # Number of log lines to display
    theme = request.cookies.get('theme', 'light')
    try:
        with open(global_settings.log_file, 'r') as f:
            lines = f.readlines()
        last_lines = lines[-N:]
    except Exception as e:
        last_lines = [f"Error reading log file: {e}"]
    return render_template('logs.html', logs=last_lines, theme=theme)

@app.route('/toggle_theme', methods=['POST'])
def toggle_theme():
    """
    Toggles the day/night theme.
    """
    theme = request.cookies.get('theme', 'light')
    new_theme = 'dark' if theme == 'light' else 'light'
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('theme', new_theme)
    return resp

async def main():
    """
    Main function to start the SSH tunnel manager and web interface.
    """
    args = parse_arguments()
    global_settings.config_path = args.config
    global_settings.log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    global_settings.web_host = args.web_host
    global_settings.web_port = args.web_port
    setup_logging()
    log("Starting SSH Tunnel Manager...", "INFO")

    # Load configuration
    load_config(args.config)

    # Check required commands
    for cmd in ['ssh', 'sshpass']:
        if not shutil.which(cmd):
            log(f"Command '{cmd}' not found. Please install it.", "ERROR")
            sys.exit(1)

    loop = asyncio.get_running_loop()
    global_settings.loop = loop
    setup_signal_handlers(loop)

    # Initialize SSH clients
    await start_clients()

    # Start monitoring clients
    monitor_task = asyncio.create_task(monitor_clients())

    # Start the web server in a separate thread
    from threading import Thread
    def run_app():
        app.run(host=global_settings.web_host, port=global_settings.web_port, debug=False, use_reloader=False)
    web_thread = Thread(target=run_app)
    web_thread.start()

    # Wait for stop event
    try:
        await global_settings.stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        monitor_task.cancel()
        await asyncio.gather(monitor_task, return_exceptions=True)
        log("SSH Tunnel Manager stopped.", "INFO")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        log(f"Fatal error: {e}", "ERROR")
        log(traceback.format_exc(), "DEBUG")
        sys.exit(1)
