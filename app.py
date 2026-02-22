#!/usr/bin/env python3
"""
NETRA – Network Event & Threat Response Analyst v1.0.0
Developed by MintFire
A comprehensive web-based cybersecurity system monitoring tool.
"""

import os
import sys
import json
import time
import re
import socket
import struct
import hashlib
import platform
import subprocess
import threading
import shutil
import tempfile
import secrets
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, abort
)
from flask_socketio import SocketIO
import psutil
from cryptography.fernet import Fernet

# ─── Configuration ───────────────────────────────────────────────────────────

APP_VERSION = "1.0.0"
DEVELOPER = "MintFire"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ADMIN_DATA_FILE = os.path.join(BASE_DIR, "admin_data.json")
ENCRYPTION_KEY_FILE = os.path.join(BASE_DIR, ".netra_key")
SECRET_KEY_FILE = os.path.join(BASE_DIR, ".netra_secret")
GIT_REPO_URL = "https://github.com/avik-root/Netra.git"

# ─── Rate Limiting ──────────────────────────────────────────────────────────

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 900  # 15 minutes
login_attempts = defaultdict(list)  # IP -> [timestamp, ...]

def is_rate_limited(ip):
    """Check if an IP is rate-limited for login attempts."""
    now = time.time()
    # Clean old entries
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOGIN_WINDOW_SECONDS]
    return len(login_attempts[ip]) >= LOGIN_MAX_ATTEMPTS

def record_login_attempt(ip):
    """Record a failed login attempt."""
    login_attempts[ip].append(time.time())

def get_remaining_lockout(ip):
    """Get seconds remaining in lockout."""
    if not login_attempts[ip]:
        return 0
    oldest = min(login_attempts[ip])
    remaining = LOGIN_WINDOW_SECONDS - (time.time() - oldest)
    return max(0, int(remaining))

# ─── App Setup ──────────────────────────────────────────────────────────────

def get_or_create_secret_key():
    """Get or create a persistent Flask secret key."""
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(key)
    os.chmod(SECRET_KEY_FILE, 0o600)
    return key

app = Flask(__name__)
app.secret_key = get_or_create_secret_key()
app.permanent_session_lifetime = timedelta(hours=8)

# Secure session cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # Set to True when using HTTPS
)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ─── Security Headers ──────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # No-cache for API responses
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    return response

# ─── CSRF Protection ───────────────────────────────────────────────────────

def generate_csrf_token():
    """Generate a CSRF token and store in session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token():
    """Validate CSRF token from form data or JSON body."""
    token = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token', '')
    if not token or token != session.get('_csrf_token'):
        abort(403)

# Make csrf_token available in all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# ─── Encryption Helpers ─────────────────────────────────────────────────────

def get_or_create_key():
    """Get or create Fernet encryption key."""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(ENCRYPTION_KEY_FILE, 0o600)
    return key

def encrypt_value(value):
    """Encrypt a string value."""
    key = get_or_create_key()
    f = Fernet(key)
    return f.encrypt(value.encode()).decode()

def decrypt_value(encrypted_value):
    """Decrypt an encrypted string value."""
    key = get_or_create_key()
    f = Fernet(key)
    return f.decrypt(encrypted_value.encode()).decode()

# ─── Password Strength Validation ──────────────────────────────────────────

def validate_password_strength(password):
    """Validate password meets security requirements.
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Password must contain at least one special character"
    return True, ""

# ─── Admin Data Management ──────────────────────────────────────────────────

def init_admin_data():
    """Initialize admin data with default credentials if not exists."""
    if not os.path.exists(ADMIN_DATA_FILE):
        data = {
            "username": encrypt_value("netra"),
            "password": encrypt_value("pass0000"),
            "first_login": True,
            "version": APP_VERSION,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        save_admin_data(data)
    return load_admin_data()

def load_admin_data():
    """Load admin data from JSON file."""
    try:
        with open(ADMIN_DATA_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return init_admin_data()

def save_admin_data(data):
    """Save admin data to JSON file."""
    data["updated_at"] = datetime.now().isoformat()
    with open(ADMIN_DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def verify_credentials(username, password):
    """Verify login credentials against stored encrypted data."""
    data = load_admin_data()
    try:
        stored_user = decrypt_value(data["username"])
        stored_pass = decrypt_value(data["password"])
        return username == stored_user and password == stored_pass
    except Exception:
        return False

# ─── Auth Decorator ─────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        validate_csrf_token()
        
        client_ip = request.remote_addr
        
        # Check rate limiting
        if is_rate_limited(client_ip):
            remaining = get_remaining_lockout(client_ip)
            mins = remaining // 60
            print(f"[NETRA SECURITY] Rate limited login attempt from {client_ip}")
            return render_template("login.html", 
                error=f"Too many failed attempts. Try again in {mins} minute(s).",
                version=APP_VERSION)
        
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if verify_credentials(username, password):
            # Clear rate limit on success
            login_attempts.pop(client_ip, None)
            session["logged_in"] = True
            session["username"] = username
            session.permanent = True
            print(f"[NETRA] Successful login from {client_ip} as '{username}'")
            
            admin_data = load_admin_data()
            if admin_data.get("first_login", True):
                return redirect(url_for("setup"))
            return redirect(url_for("dashboard"))
        else:
            record_login_attempt(client_ip)
            attempts_left = LOGIN_MAX_ATTEMPTS - len(login_attempts[client_ip])
            print(f"[NETRA SECURITY] Failed login attempt from {client_ip} — {attempts_left} attempts remaining")
            return render_template("login.html", 
                error=f"Invalid credentials. {attempts_left} attempt(s) remaining.",
                version=APP_VERSION)
    
    return render_template("login.html", version=APP_VERSION)

@app.route("/setup", methods=["GET", "POST"])
@login_required
def setup():
    admin_data = load_admin_data()
    if not admin_data.get("first_login", False):
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        validate_csrf_token()
        
        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        if not new_username or not new_password:
            return render_template("setup.html", error="All fields are required", version=APP_VERSION)
        
        # Validate password strength
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return render_template("setup.html", error=error_msg, version=APP_VERSION)
        
        if new_password != confirm_password:
            return render_template("setup.html", error="Passwords do not match", version=APP_VERSION)
        
        admin_data["username"] = encrypt_value(new_username)
        admin_data["password"] = encrypt_value(new_password)
        admin_data["first_login"] = False
        save_admin_data(admin_data)
        
        session["username"] = new_username
        print(f"[NETRA] Initial setup completed by '{new_username}'")
        return redirect(url_for("dashboard"))
    
    return render_template("setup.html", version=APP_VERSION)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        version=APP_VERSION,
        developer=DEVELOPER,
        username=session.get("username", "Admin"),
        hostname=platform.node(),
        os_info=f"{platform.system()} {platform.release()}"
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ─── API Endpoints ──────────────────────────────────────────────────────────

@app.route("/api/system")
@login_required
def api_system():
    """Get comprehensive system information."""
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot_time
    
    # CPU per-core usage
    cpu_per_core = psutil.cpu_percent(percpu=True)
    
    # Disk partitions
    partitions = []
    for p in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(p.mountpoint)
            partitions.append({
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent
            })
        except PermissionError:
            continue
    
    return jsonify({
        "cpu": {
            "percent": psutil.cpu_percent(),
            "count": psutil.cpu_count(),
            "count_logical": psutil.cpu_count(logical=True),
            "freq_current": cpu_freq.current if cpu_freq else 0,
            "freq_max": cpu_freq.max if cpu_freq else 0,
            "per_core": cpu_per_core
        },
        "memory": {
            "total": mem.total,
            "available": mem.available,
            "used": mem.used,
            "percent": mem.percent
        },
        "swap": {
            "total": swap.total,
            "used": swap.used,
            "free": swap.free,
            "percent": swap.percent
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
            "partitions": partitions
        },
        "uptime": str(uptime).split(".")[0],
        "boot_time": boot_time.isoformat(),
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "python": platform.python_version()
    })

@app.route("/api/network")
@login_required
def api_network():
    """Get network interfaces and statistics."""
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io_counters = psutil.net_io_counters(pernic=True)
    
    for iface, addr_list in addrs.items():
        iface_info = {
            "name": iface,
            "addresses": [],
            "is_up": False,
            "speed": 0,
            "mtu": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "packets_sent": 0,
            "packets_recv": 0,
            "errors_in": 0,
            "errors_out": 0,
            "drop_in": 0,
            "drop_out": 0
        }
        
        for addr in addr_list:
            addr_info = {
                "family": str(addr.family),
                "address": addr.address,
                "netmask": addr.netmask,
                "broadcast": addr.broadcast
            }
            # Determine type
            if "AF_INET" in str(addr.family):
                addr_info["type"] = "IPv4"
            elif "AF_INET6" in str(addr.family):
                addr_info["type"] = "IPv6"
            elif "AF_LINK" in str(addr.family) or "AF_PACKET" in str(addr.family):
                addr_info["type"] = "MAC"
            else:
                addr_info["type"] = "Other"
            iface_info["addresses"].append(addr_info)
        
        if iface in stats:
            s = stats[iface]
            iface_info["is_up"] = s.isup
            iface_info["speed"] = s.speed
            iface_info["mtu"] = s.mtu
        
        if iface in io_counters:
            io = io_counters[iface]
            iface_info["bytes_sent"] = io.bytes_sent
            iface_info["bytes_recv"] = io.bytes_recv
            iface_info["packets_sent"] = io.packets_sent
            iface_info["packets_recv"] = io.packets_recv
            iface_info["errors_in"] = io.errin
            iface_info["errors_out"] = io.errout
            iface_info["drop_in"] = io.dropin
            iface_info["drop_out"] = io.dropout
        
        # Classify interface type
        name_lower = iface.lower()
        if any(x in name_lower for x in ["wlan", "wifi", "wi-fi", "airport", "en0"]):
            iface_info["type"] = "WiFi"
        elif any(x in name_lower for x in ["eth", "en1", "en2", "en3", "enp"]):
            iface_info["type"] = "Ethernet"
        elif any(x in name_lower for x in ["bt", "ble", "bluetooth"]):
            iface_info["type"] = "Bluetooth"
        elif "lo" in name_lower:
            iface_info["type"] = "Loopback"
        elif any(x in name_lower for x in ["tun", "tap", "vpn", "wg"]):
            iface_info["type"] = "VPN"
        elif any(x in name_lower for x in ["bridge", "br"]):
            iface_info["type"] = "Bridge"
        elif any(x in name_lower for x in ["docker", "veth"]):
            iface_info["type"] = "Docker"
        else:
            iface_info["type"] = "Other"
        
        interfaces.append(iface_info)
    
    # Network IO total
    io_total = psutil.net_io_counters()
    
    # Active connections
    connections = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            connections.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                "status": conn.status,
                "pid": conn.pid
            })
    except (psutil.AccessDenied, PermissionError):
        pass
    
    return jsonify({
        "interfaces": interfaces,
        "total_io": {
            "bytes_sent": io_total.bytes_sent,
            "bytes_recv": io_total.bytes_recv,
            "packets_sent": io_total.packets_sent,
            "packets_recv": io_total.packets_recv
        },
        "connections": connections[:100],
        "connection_count": len(connections)
    })

@app.route("/api/firewall")
@login_required
def api_firewall():
    """Get firewall rules and packet statistics."""
    firewall_rules = []
    firewall_status = "Unknown"
    
    system = platform.system()
    
    try:
        if system == "Darwin":  # macOS
            # Check pf firewall
            result = subprocess.run(
                ["pfctl", "-sr"], capture_output=True, text=True, timeout=5
            )
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        firewall_rules.append({"rule": line.strip(), "type": "pf"})
            
            # Check if firewall is enabled
            result2 = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                capture_output=True, text=True, timeout=5
            )
            state = result2.stdout.strip()
            firewall_status = "Enabled" if state in ("1", "2") else "Disabled"
        
        elif system == "Linux":
            # iptables
            result = subprocess.run(
                ["iptables", "-L", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        firewall_rules.append({"rule": line.strip(), "type": "iptables"})
            firewall_status = "Active" if firewall_rules else "No rules"
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError):
        firewall_status = "Unable to query (requires privileges)"
    
    # Packet statistics from network counters
    io = psutil.net_io_counters()
    
    return jsonify({
        "status": firewall_status,
        "rules": firewall_rules[:50],
        "rules_count": len(firewall_rules),
        "packets": {
            "sent": io.packets_sent,
            "recv": io.packets_recv,
            "errors_in": io.errin,
            "errors_out": io.errout,
            "drop_in": io.dropin,
            "drop_out": io.dropout
        },
        "bytes": {
            "sent": io.bytes_sent,
            "recv": io.bytes_recv
        }
    })

@app.route("/api/services")
@login_required
def api_services():
    """Get running services/processes."""
    services = []
    for proc in psutil.process_iter(["pid", "name", "status", "cpu_percent", "memory_percent", "username", "create_time"]):
        try:
            info = proc.info
            services.append({
                "pid": info["pid"],
                "name": info["name"],
                "status": info["status"],
                "cpu": round(info["cpu_percent"] or 0, 1),
                "memory": round(info["memory_percent"] or 0, 1),
                "user": info["username"] or "N/A",
                "started": datetime.fromtimestamp(info["create_time"]).strftime("%Y-%m-%d %H:%M") if info["create_time"] else "N/A"
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Sort by CPU usage descending
    services.sort(key=lambda x: x["cpu"], reverse=True)
    
    return jsonify({
        "services": services[:200],
        "total_count": len(services),
        "running": sum(1 for s in services if s["status"] == "running"),
        "sleeping": sum(1 for s in services if s["status"] == "sleeping"),
        "zombie": sum(1 for s in services if s["status"] == "zombie")
    })

@app.route("/api/logs")
@login_required
def api_logs():
    """Get system logs."""
    logs = []
    system = platform.system()
    
    try:
        if system == "Darwin":
            result = subprocess.run(
                ["log", "show", "--last", "5m", "--style", "compact"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                for line in result.stdout.strip().split("\n")[-100:]:
                    if line.strip():
                        logs.append({"message": line.strip(), "source": "system"})
        elif system == "Linux":
            result = subprocess.run(
                ["journalctl", "-n", "100", "--no-pager", "-q"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        logs.append({"message": line.strip(), "source": "journalctl"})
    except (subprocess.SubprocessError, FileNotFoundError):
        logs.append({"message": "Unable to fetch system logs (may require elevated privileges)", "source": "error"})
    
    # Also add NETRA's own log
    logs.append({
        "message": f"NETRA v{APP_VERSION} – System monitoring active",
        "source": "netra",
        "timestamp": datetime.now().isoformat()
    })
    
    return jsonify({"logs": logs, "count": len(logs)})

@app.route("/api/connections")
@login_required
def api_connections():
    """Get detailed active network connections."""
    connections = []
    
    # Try psutil first (requires root on macOS)
    try:
        for conn in psutil.net_connections(kind="all"):
            conn_info = {
                "fd": conn.fd,
                "family": "IPv4" if conn.family == socket.AF_INET else "IPv6" if conn.family == socket.AF_INET6 else str(conn.family),
                "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP" if conn.type == socket.SOCK_DGRAM else str(conn.type),
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                "status": conn.status if conn.status else "N/A",
                "pid": conn.pid or "N/A"
            }
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    conn_info["process"] = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    conn_info["process"] = "Unknown"
            else:
                conn_info["process"] = "N/A"
            connections.append(conn_info)
    except (psutil.AccessDenied, PermissionError):
        pass
    
    # Fallback: parse lsof on macOS / netstat on Linux if psutil returned nothing
    if not connections:
        try:
            system = platform.system()
            if system == "Darwin":
                result = subprocess.run(
                    ["lsof", "-i", "-n", "-P", "+c", "0"],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout:
                    lines = result.stdout.strip().split("\n")
                    for line in lines[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) < 9:
                            continue
                        proc_name = parts[0]
                        pid = parts[1]
                        
                        # Parse protocol (TCP/UDP) and IP version
                        proto_field = parts[7] if len(parts) > 7 else ""
                        node_field = parts[7] if len(parts) > 7 else ""
                        name_field = parts[8] if len(parts) > 8 else ""
                        
                        # Determine protocol
                        proto = "TCP"
                        if "UDP" in node_field.upper():
                            proto = "UDP"
                        
                        # Determine IP family
                        family = "IPv4"
                        type_field = parts[4] if len(parts) > 4 else ""
                        if "6" in type_field:
                            family = "IPv6"
                        
                        # Parse addresses from the NAME column
                        local_addr = "N/A"
                        remote_addr = "N/A"
                        status = "N/A"
                        
                        # Check for status in last field
                        last_part = parts[-1] if parts else ""
                        if last_part.startswith("(") and last_part.endswith(")"):
                            status = last_part[1:-1]  # e.g., (ESTABLISHED) -> ESTABLISHED
                            name_field = parts[-2] if len(parts) > 9 else name_field
                        
                        if "->" in name_field:
                            addr_parts = name_field.split("->")
                            local_addr = addr_parts[0].strip()
                            remote_addr = addr_parts[1].strip()
                        elif name_field and name_field != "*:*":
                            local_addr = name_field
                            if status == "N/A":
                                status = "LISTEN"
                        
                        connections.append({
                            "fd": -1,
                            "family": family,
                            "type": proto,
                            "local_address": local_addr,
                            "remote_address": remote_addr,
                            "status": status,
                            "pid": pid,
                            "process": proc_name
                        })
            elif system == "Linux":
                result = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout:
                    lines = result.stdout.strip().split("\n")
                    for line in lines[1:]:
                        parts = line.split()
                        if len(parts) < 5:
                            continue
                        proto = parts[0].upper()
                        state = parts[1] if len(parts) > 1 else "N/A"
                        local = parts[4] if len(parts) > 4 else "N/A"
                        remote = parts[5] if len(parts) > 5 else "N/A"
                        proc_info = parts[6] if len(parts) > 6 else ""
                        
                        pid_val = "N/A"
                        proc_name = "N/A"
                        if 'pid=' in proc_info:
                            try:
                                pid_val = proc_info.split('pid=')[1].split(',')[0]
                                p = psutil.Process(int(pid_val))
                                proc_name = p.name()
                            except (Exception,):
                                pass
                        
                        connections.append({
                            "fd": -1,
                            "family": "IPv6" if ']:' in local else "IPv4",
                            "type": proto if proto in ("TCP", "UDP") else "TCP",
                            "local_address": local,
                            "remote_address": remote,
                            "status": state,
                            "pid": pid_val,
                            "process": proc_name
                        })
        except (subprocess.SubprocessError, FileNotFoundError, Exception) as e:
            print(f"[NETRA] Connection fallback error: {e}")
    
    # Summary
    tcp_count = sum(1 for c in connections if c["type"] == "TCP")
    udp_count = sum(1 for c in connections if c["type"] == "UDP")
    established = sum(1 for c in connections if c["status"] == "ESTABLISHED")
    listening = sum(1 for c in connections if c["status"] == "LISTEN")
    
    return jsonify({
        "connections": connections[:200],
        "total": len(connections),
        "tcp": tcp_count,
        "udp": udp_count,
        "established": established,
        "listening": listening
    })

@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    """Change admin password with current password verification."""
    validate_csrf_token()
    
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400
    
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")
    
    # Verify current password
    admin_data = load_admin_data()
    try:
        stored_pass = decrypt_value(admin_data["password"])
        if current_password != stored_pass:
            print(f"[NETRA SECURITY] Failed password change attempt by '{session.get('username')}'")
            return jsonify({"status": "error", "message": "Current password is incorrect"}), 403
    except Exception:
        return jsonify({"status": "error", "message": "Error verifying credentials"}), 500
    
    # Validate new password
    if not new_password:
        return jsonify({"status": "error", "message": "New password is required"}), 400
    
    if new_password == current_password:
        return jsonify({"status": "error", "message": "New password must be different from current password"}), 400
    
    is_valid, error_msg = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg}), 400
    
    if new_password != confirm_password:
        return jsonify({"status": "error", "message": "Passwords do not match"}), 400
    
    # Update password
    admin_data["password"] = encrypt_value(new_password)
    save_admin_data(admin_data)
    
    print(f"[NETRA] Password changed successfully by '{session.get('username')}'")
    return jsonify({"status": "success", "message": "Password changed successfully"})

@app.route("/api/update", methods=["POST"])
@login_required
def api_update():
    """Auto-update from git repo, preserving admin data."""
    validate_csrf_token()
    app_dir = os.path.dirname(os.path.abspath(__file__))
    
    try:
        # Step 1: Backup admin data
        backup_files = {}
        for fname in [os.path.basename(ADMIN_DATA_FILE), os.path.basename(ENCRYPTION_KEY_FILE), os.path.basename(SECRET_KEY_FILE)]:
            fpath = os.path.join(app_dir, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    backup_files[fname] = f.read()
        
        # Step 2: Ensure remote is set correctly
        subprocess.run(
            ["git", "remote", "set-url", "origin", GIT_REPO_URL],
            cwd=app_dir, capture_output=True, text=True, timeout=10
        )
        
        # Step 3: Git pull
        result = subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=app_dir, capture_output=True, text=True, timeout=30
        )
        
        # Step 4: Restore admin data
        for fname, content in backup_files.items():
            fpath = os.path.join(app_dir, fname)
            with open(fpath, "wb") as f:
                f.write(content)
        
        if result.returncode == 0:
            return jsonify({
                "status": "success",
                "message": "NETRA updated successfully! Admin data preserved.",
                "output": result.stdout
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Update failed",
                "output": result.stderr
            }), 500
    
    except subprocess.TimeoutExpired:
        return jsonify({
            "status": "error",
            "message": "Update timed out. Check your internet connection."
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/api/info")
@login_required
def api_info():
    """Get NETRA tool info."""
    return jsonify({
        "name": "NETRA",
        "full_name": "Network Event & Threat Response Analyst",
        "version": APP_VERSION,
        "developer": DEVELOPER,
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "python": platform.python_version()
    })

# ─── SocketIO Real-time Data ────────────────────────────────────────────────

def background_metrics():
    """Background thread that pushes system metrics every 2 seconds."""
    prev_net = psutil.net_io_counters()
    prev_time = time.time()
    
    while True:
        try:
            socketio.sleep(2)
            
            # CPU & Memory
            cpu = psutil.cpu_percent()
            cpu_per_core = psutil.cpu_percent(percpu=True)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            
            # Network delta
            curr_net = psutil.net_io_counters()
            curr_time = time.time()
            dt = curr_time - prev_time
            
            bytes_sent_rate = (curr_net.bytes_sent - prev_net.bytes_sent) / dt if dt > 0 else 0
            bytes_recv_rate = (curr_net.bytes_recv - prev_net.bytes_recv) / dt if dt > 0 else 0
            packets_sent_rate = (curr_net.packets_sent - prev_net.packets_sent) / dt if dt > 0 else 0
            packets_recv_rate = (curr_net.packets_recv - prev_net.packets_recv) / dt if dt > 0 else 0
            
            prev_net = curr_net
            prev_time = curr_time
            
            # Temperatures (if available)
            temps = {}
            try:
                t = psutil.sensors_temperatures()
                if t:
                    for name, entries in t.items():
                        temps[name] = [{"label": e.label or name, "current": e.current, "high": e.high, "critical": e.critical} for e in entries]
            except (AttributeError, Exception):
                pass
            
            # Battery (if available)
            battery = None
            try:
                b = psutil.sensors_battery()
                if b:
                    battery = {"percent": b.percent, "plugged": b.power_plugged, "secs_left": b.secsleft}
            except (AttributeError, Exception):
                pass
            
            socketio.emit("system_metrics", {
                "timestamp": datetime.now().isoformat(),
                "cpu": cpu,
                "cpu_per_core": cpu_per_core,
                "memory_percent": mem.percent,
                "memory_used": mem.used,
                "memory_total": mem.total,
                "disk_percent": disk.percent,
                "disk_used": disk.used,
                "disk_total": disk.total,
                "net_sent_rate": round(bytes_sent_rate),
                "net_recv_rate": round(bytes_recv_rate),
                "net_sent_total": curr_net.bytes_sent,
                "net_recv_total": curr_net.bytes_recv,
                "packets_sent_rate": round(packets_sent_rate),
                "packets_recv_rate": round(packets_recv_rate),
                "temperatures": temps,
                "battery": battery
            })
        except Exception as e:
            print(f"[NETRA] Metrics error: {e}")

@socketio.on("connect")
def on_connect():
    print(f"[NETRA] Client connected")

@socketio.on("disconnect")
def on_disconnect():
    print(f"[NETRA] Client disconnected")

# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Initialize admin data
    init_admin_data()
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║          NETRA – Network Event & Threat Response Analyst     ║
║          Version: {APP_VERSION}                                       ║
║          Developed by: {DEVELOPER}                                ║
║          Starting on http://0.0.0.0:5001                     ║
║          Security: Rate Limiting | CSRF | Secure Headers     ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Start background metrics thread
    socketio.start_background_task(background_metrics)
    
    # Run server
    socketio.run(app, host="0.0.0.0", port=5001, debug=False)
