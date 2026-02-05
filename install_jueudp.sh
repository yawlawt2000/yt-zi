#!/usr/bin/env bash
#
# Try `install_jueudp.sh --help` for usage.
#
# (c) 2023 Jue Htet
# Updated with Web Admin Panel
#

set -e

# Domain Name
DOMAIN="yt.yawlawt.com"

# PROTOCOL
PROTOCOL="udp"

# UDP PORT
UDP_PORT=":36712"

# OBFS
OBFS="agnudp"

# PASSWORDS
PASSWORD="ytplus"

# Web Admin Panel Configuration
WEB_PORT="8880"
WEB_USERNAME="yaw"
WEB_PASSWORD="lawtaung"
WEB_SESSION_SECRET="jueudp_secret_key_$(date +%s)"

# Script paths
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
USER_DB="$CONFIG_DIR/udpusers.db"
REPO_URL="https://github.com/apernet/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
API_BASE_URL="https://api.github.com/repos/apernet/hysteria"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)
PACKAGE_MANAGEMENT_INSTALL="${PACKAGE_MANAGEMENT_INSTALL:-}"
SYSTEMD_SERVICE="$SYSTEMD_SERVICES_DIR/hysteria-server.service"
WEB_SYSTEMD_SERVICE="$SYSTEMD_SERVICES_DIR/jueudp-web.service"
WEB_DIR="/var/www/jueudp"
mkdir -p "$CONFIG_DIR"
touch "$USER_DB"

# Other configurations
OPERATING_SYSTEM=""
ARCHITECTURE=""
HYSTERIA_USER=""
HYSTERIA_HOME_DIR=""
VERSION=""
FORCE=""
LOCAL_FILE=""
FORCE_NO_ROOT=""
FORCE_NO_SYSTEMD=""

# Utility functions
has_command() {
    local _command=$1
    type -P "$_command" > /dev/null 2>&1
}

curl() {
    command curl "${CURL_FLAGS[@]}" "$@"
}

mktemp() {
    command mktemp "$@" "hyservinst.XXXXXXXXXX"
}

tput() {
    if has_command tput; then
        command tput "$@"
    fi
}

tred() {
    tput setaf 1
}

tgreen() {
    tput setaf 2
}

tyellow() {
    tput setaf 3
}

tblue() {
    tput setaf 4
}

taoi() {
    tput setaf 6
}

tbold() {
    tput bold
}

treset() {
    tput sgr0
}

note() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tbold)note: $_msg$(treset)"
}

warning() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tyellow)warning: $_msg$(treset)"
}

error() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tred)error: $_msg$(treset)"
}

show_argument_error_and_exit() {
    local _error_msg="$1"
    error "$_error_msg"
    echo "Try \"$0 --help\" for the usage." >&2
    exit 22
}

install_content() {
    local _install_flags="$1"
    local _content="$2"
    local _destination="$3"

    local _tmpfile="$(mktemp)"

    echo -ne "Install $_destination ... "
    echo "$_content" > "$_tmpfile"
    if install "$_install_flags" "$_tmpfile" "$_destination"; then
        echo -e "ok"
    fi

    rm -f "$_tmpfile"
}

remove_file() {
    local _target="$1"

    echo -ne "Remove $_target ... "
    if rm "$_target"; then
        echo -e "ok"
    fi
}

exec_sudo() {
    local _saved_ifs="$IFS"
    IFS=$'\n'
    local _preserved_env=(
        $(env | grep "^PACKAGE_MANAGEMENT_INSTALL=" || true)
        $(env | grep "^OPERATING_SYSTEM=" || true)
        $(env | grep "^ARCHITECTURE=" || true)
        $(env | grep "^HYSTERIA_\w*=" || true)
        $(env | grep "^FORCE_\w*=" || true)
    )
    IFS="$_saved_ifs"

    exec sudo env \
    "${_preserved_env[@]}" \
    "$@"
}

install_software() {
    local package="$1"
    if has_command apt-get; then
        echo "Installing $package using apt-get..."
        apt-get update && apt-get install -y "$package"
    elif has_command dnf; then
        echo "Installing $package using dnf..."
        dnf install -y "$package"
    elif has_command yum; then
        echo "Installing $package using yum..."
        yum install -y "$package"
    elif has_command zypper; then
        echo "Installing $package using zypper..."
        zypper install -y "$package"
    elif has_command pacman; then
        echo "Installing $package using pacman..."
        pacman -Sy --noconfirm "$package"
    else
        echo "Error: No supported package manager found. Please install $package manually."
        exit 1
    fi
}

is_user_exists() {
    local _user="$1"
    id "$_user" > /dev/null 2>&1
}

check_permission() {
    if [[ "$UID" -eq '0' ]]; then
        return
    fi

    note "The user currently executing this script is not root."

    case "$FORCE_NO_ROOT" in
        '1')
            warning "FORCE_NO_ROOT=1 is specified, we will process without root and you may encounter the insufficient privilege error."
            ;;
        *)
            if has_command sudo; then
                note "Re-running this script with sudo, you can also specify FORCE_NO_ROOT=1 to force this script running with current user."
                exec_sudo "$0" "${SCRIPT_ARGS[@]}"
            else
                error "Please run this script with root or specify FORCE_NO_ROOT=1 to force this script running with current user."
                exit 13
            fi
            ;;
    esac
}

check_environment_operating_system() {
    if [[ -n "$OPERATING_SYSTEM" ]]; then
        warning "OPERATING_SYSTEM=$OPERATING_SYSTEM is specified, operating system detection will not be performed."
        return
    fi

    if [[ "x$(uname)" == "xLinux" ]]; then
        OPERATING_SYSTEM=linux
        return
    fi

    error "This script only supports Linux."
    note "Specify OPERATING_SYSTEM=[linux|darwin|freebsd|windows] to bypass this check and force this script running on this $(uname)."
    exit 95
}

check_environment_architecture() {
    if [[ -n "$ARCHITECTURE" ]]; then
        warning "ARCHITECTURE=$ARCHITECTURE is specified, architecture detection will not be performed."
        return
    fi

    case "$(uname -m)" in
        'i386' | 'i686')
            ARCHITECTURE='386'
            ;;
        'amd64' | 'x86_64')
            ARCHITECTURE='amd64'
            ;;
        'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
            ARCHITECTURE='arm'
            ;;
        'armv8' | 'aarch64')
            ARCHITECTURE='arm64'
            ;;
        'mips' | 'mipsle' | 'mips64' | 'mips64le')
            ARCHITECTURE='mipsle'
            ;;
        's390x')
            ARCHITECTURE='s390x'
            ;;
        *)
            error "The architecture '$(uname -a)' is not supported."
            note "Specify ARCHITECTURE=<architecture> to bypass this check and force this script running on this $(uname -m)."
            exit 8
            ;;
    esac
}

check_environment_systemd() {
    if [[ -d "/run/systemd/system" ]] || grep -q systemd <(ls -l /sbin/init); then
        return
    fi

    case "$FORCE_NO_SYSTEMD" in
        '1')
            warning "FORCE_NO_SYSTEMD=1 is specified, we will process as normal even if systemd is not detected by us."
            ;;
        '2')
            warning "FORCE_NO_SYSTEMD=2 is specified, we will process but all systemd related commands will not be executed."
            ;;
        *)
            error "This script only supports Linux distributions with systemd."
            note "Specify FORCE_NO_SYSTEMD=1 to disable this check and force this script running as systemd is detected."
            note "Specify FORCE_NO_SYSTEMD=2 to disable this check along with all systemd related commands."
            ;;
    esac
}

parse_arguments() {
    while [[ "$#" -gt '0' ]]; do
        case "$1" in
            '--remove')
                if [[ -n "$OPERATION" && "$OPERATION" != 'remove' ]]; then
                    show_argument_error_and_exit "Option '--remove' is conflicted with other options."
                fi
                OPERATION='remove'
                ;;
            '--version')
                VERSION="$2"
                if [[ -z "$VERSION" ]]; then
                    show_argument_error_and_exit "Please specify the version for option '--version'."
                fi
                shift
                if ! [[ "$VERSION" == v* ]]; then
                    show_argument_error_and_exit "Version numbers should begin with 'v' (such like 'v1.3.1'), got '$VERSION'"
                fi
                ;;
            '-h' | '--help')
                show_usage_and_exit
                ;;
            '-l' | '--local')
                LOCAL_FILE="$2"
                if [[ -z "$LOCAL_FILE" ]]; then
                    show_argument_error_and_exit "Please specify the local binary to install for option '-l' or '--local'."
                fi
                break
                ;;
            *)
                show_argument_error_and_exit "Unknown option '$1'"
                ;;
        esac
        shift
    done

    if [[ -z "$OPERATION" ]]; then
        OPERATION='install'
    fi

    # validate arguments
    case "$OPERATION" in
        'install')
            if [[ -n "$VERSION" && -n "$LOCAL_FILE" ]]; then
                show_argument_error_and_exit '--version and --local cannot be specified together.'
            fi
            ;;
        *)
            if [[ -n "$VERSION" ]]; then
                show_argument_error_and_exit "--version is only available when installing."
            fi
            if [[ -n "$LOCAL_FILE" ]]; then
                show_argument_error_and_exit "--local is only available when installing."
            fi
            ;;
    esac
}

check_hysteria_homedir() {
    local _default_hysteria_homedir="$1"

    if [[ -n "$HYSTERIA_HOME_DIR" ]]; then
        return
    fi

    if ! is_user_exists "$HYSTERIA_USER"; then
        HYSTERIA_HOME_DIR="$_default_hysteria_homedir"
        return
    fi

    HYSTERIA_HOME_DIR="$(eval echo ~"$HYSTERIA_USER")"
}

download_hysteria() {
    local _version="$1"
    local _destination="$2"

    local _download_url="$REPO_URL/releases/download/v1.3.5/hysteria-$OPERATING_SYSTEM-$ARCHITECTURE"
    echo "Downloading hysteria archive: $_download_url ..."
    if ! curl -R -H 'Cache-Control: no-cache' "$_download_url" -o "$_destination"; then
        error "Download failed! Please check your network and try again."
        return 11
    fi
    return 0
}

check_hysteria_user() {
    local _default_hysteria_user="$1"

    if [[ -n "$HYSTERIA_USER" ]]; then
        return
    fi

    if [[ ! -e "$SYSTEMD_SERVICES_DIR/hysteria-server.service" ]]; then
        HYSTERIA_USER="$_default_hysteria_user"
        return
    fi

    HYSTERIA_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/hysteria-server.service" | tail -1 | cut -d '=' -f 2 || true)"

    if [[ -z "$HYSTERIA_USER" ]]; then
        HYSTERIA_USER="$_default_hysteria_user"
    fi
}

check_environment_curl() {
    if ! has_command curl; then
        install_software "curl"
    fi
}

check_environment_grep() {
    if ! has_command grep; then
        install_software "grep"
    fi
}

check_environment_sqlite3() {
    if ! has_command sqlite3; then
        install_software "sqlite3"
    fi
}

check_environment_pip() {
    if ! has_command pip; then
        install_software "python3-pip"
    fi
}

check_environment_jq() {
    if ! has_command jq; then
        install_software "jq"
    fi
}

check_environment_python3() {
    if ! has_command python3; then
        install_software "python3"
    fi
}

check_environment() {
    check_environment_operating_system
    check_environment_architecture
    check_environment_systemd
    check_environment_curl
    check_environment_grep
    check_environment_pip
    check_environment_sqlite3
    check_environment_jq
    check_environment_python3
}

show_usage_and_exit() {
    echo
    echo -e "\t$(tbold)$SCRIPT_NAME$(treset) - AGN-UDP Server Install Script with Web Admin Panel"
    echo
    echo -e "Usage:"
    echo
    echo -e "$(tbold)Install AGN-UDP with Web Admin$(treset)"
    echo -e "\t$0 [ -f | -l <file> | --version <version> ]"
    echo -e "Flags:"
    echo -e "\t-f, --force\tForce re-install latest or specified version even if it has been installed."
    echo -e "\t-l, --local <file>\tInstall specified AGN-UDP binary instead of download it."
    echo -e "\t--version <version>\tInstall specified version instead of the latest."
    echo
    echo -e "$(tbold)Remove AGN-UDP$(treset)"
    echo -e "\t$0 --remove"
    echo
    echo -e "$(tbold)Check for the update$(treset)"
    echo -e "\t$0 -c"
    echo -e "\t$0 --check"
    echo
    echo -e "$(tbold)Show this help$(treset)"
    echo -e "\t$0 -h"
    echo -e "\t$0 --help"
    echo
    echo -e "$(tbold)Web Admin Panel$(treset)"
    echo -e "\tAfter installation, access the web admin at:"
    echo -e "\t$(tblue)http://your-server-ip:$WEB_PORT$(treset)"
    echo -e "\tDefault username: $WEB_USERNAME"
    echo -e "\tDefault password: $WEB_PASSWORD"
    exit 0
}

tpl_hysteria_server_service_base() {
    local _config_name="$1"

    cat << EOF
[Unit]
Description=AGN-UDP Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
Environment="PATH=/usr/local/bin/hysteria"
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json

[Install]
WantedBy=multi-user.target
EOF
}

tpl_hysteria_server_service() {
    tpl_hysteria_server_service_base 'config'
}

tpl_hysteria_server_x_service() {
    tpl_hysteria_server_service_base '%i'
}

tpl_jueudp_web_service() {
    cat << EOF
[Unit]
Description=JUE-UDP Web Admin Panel
After=network.target hysteria-server.service

[Service]
Type=simple
User=root
WorkingDirectory=$WEB_DIR
Environment="PYTHONPATH=$WEB_DIR"
ExecStart=/usr/bin/python3 $WEB_DIR/web_app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

tpl_etc_hysteria_config_json() {
    local_users=$(fetch_users)

    mkdir -p "$CONFIG_DIR"

    cat << EOF > "$CONFIG_FILE"
{
  "server": "$DOMAIN",
  "listen": "$UDP_PORT",
  "protocol": "$PROTOCOL",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up": "20 Mbps",
  "up_mbps": 20,
  "down": "20 Mbps",
  "down_mbps": 20,
  "disable_udp": false,
  "insecure": true,
  "obfs": "$OBFS",
  "auth": {
 	"mode": "passwords",
  "config": [
      "$(echo $local_users)"
    ]
         }
}
EOF
}

setup_db() {
    echo "Setting up database"
    mkdir -p "$(dirname "$USER_DB")"

    if [[ ! -f "$USER_DB" ]]; then
        # Create the database file
        sqlite3 "$USER_DB" ".databases"
        if [[ $? -ne 0 ]]; then
            echo "Error: Unable to create database file at $USER_DB"
            exit 1
        fi
    fi

    # Create the users table
    sqlite3 "$USER_DB" <<EOF
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1
);
EOF

    # Check if the table 'users' was created successfully
    table_exists=$(sqlite3 "$USER_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    if [[ "$table_exists" == "users" ]]; then
        echo "Database setup completed successfully. Table 'users' exists."
        
        # Add a default user if not already exists
        default_username="default"
        default_password="password"
        user_exists=$(sqlite3 "$USER_DB" "SELECT username FROM users WHERE username='$default_username';")
        
        if [[ -z "$user_exists" ]]; then
            sqlite3 "$USER_DB" "INSERT INTO users (username, password) VALUES ('$default_username', '$default_password');"
            if [[ $? -eq 0 ]]; then
                echo "Default user created successfully."
            else
                echo "Error: Failed to create default user."
            fi
        else
            echo "Default user already exists."
        fi
    else
        echo "Error: Table 'users' was not created successfully."
        # Show the database schema for debugging
        echo "Current database schema:"
        sqlite3 "$USER_DB" ".schema"
        exit 1
    fi
}

fetch_users() {
    DB_PATH="/etc/hysteria/udpusers.db"
    if [[ -f "$DB_PATH" ]]; then
        sqlite3 "$DB_PATH" "SELECT username || ':' || password FROM users WHERE is_active = 1;" | paste -sd, -
    fi
}

create_web_admin() {
    echo "Creating Web Admin Panel..."
    
    # Create web directory
    mkdir -p "$WEB_DIR/templates"
    mkdir -p "$WEB_DIR/static/css"
    
    # Create main web application
    cat << 'EOF' > "$WEB_DIR/web_app.py"
#!/usr/bin/env python3
"""
JUE-UDP Web Admin Panel
"""

import sqlite3
import json
import subprocess
import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask import jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'jueudp_secret_key')

# Configuration
DB_PATH = '/etc/hysteria/udpusers.db'
CONFIG_PATH = '/etc/hysteria/config.json'
SERVICE_NAME = 'hysteria-server.service'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_server_stats():
    """Get server statistics"""
    stats = {
        'total_users': 0,
        'active_users': 0,
        'server_status': 'Unknown'
    }
    
    try:
        # Check service status
        result = subprocess.run(['systemctl', 'is-active', SERVICE_NAME], 
                              capture_output=True, text=True)
        stats['server_status'] = result.stdout.strip()
        
        # Get user statistics
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM users")
        stats['total_users'] = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as active FROM users WHERE is_active = 1")
        stats['active_users'] = cursor.fetchone()['active']
        
        conn.close()
    except Exception as e:
        print(f"Error getting stats: {e}")
    
    return stats

def reload_hysteria_config():
    """Reload Hysteria configuration"""
    try:
        # Update config.json with current users
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM users WHERE is_active = 1")
        users = cursor.fetchall()
        conn.close()
        
        auth_config = [f"{user['username']}:{user['password']}" for user in users]
        
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        
        config['auth']['config'] = auth_config
        
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Reload hysteria service
        subprocess.run(['systemctl', 'restart', SERVICE_NAME], check=True)
        return True, "Configuration updated and service restarted successfully"
    except Exception as e:
        return False, f"Error: {str(e)}"

@app.route('/')
@login_required
def index():
    stats = get_server_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simple hardcoded admin credentials
        if username == os.environ.get('WEB_USERNAME', 'yaw') and password == os.environ.get('WEB_PASSWORD', 'lawtaung'):
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['POST'])
@login_required
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Username and password are required!', 'danger')
        return redirect(url_for('users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (username, password))
        conn.commit()
        conn.close()
        
        # Reload configuration
        success, message = reload_hysteria_config()
        if success:
            flash(f'User {username} added successfully!', 'success')
        else:
            flash(f'User added but {message}', 'warning')
    except sqlite3.IntegrityError:
        flash(f'Username {username} already exists!', 'danger')
    except Exception as e:
        flash(f'Error adding user: {str(e)}', 'danger')
    
    return redirect(url_for('users'))

@app.route('/users/edit/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    username = request.form.get('username')
    password = request.form.get('password')
    is_active = request.form.get('is_active', 0)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET username = ?, password = ?, is_active = ?
            WHERE id = ?
        """, (username, password, is_active, user_id))
        conn.commit()
        conn.close()
        
        # Reload configuration
        success, message = reload_hysteria_config()
        if success:
            flash(f'User {username} updated successfully!', 'success')
        else:
            flash(f'User updated but {message}', 'warning')
    except Exception as e:
        flash(f'Error updating user: {str(e)}', 'danger')
    
    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        # Reload configuration
        success, message = reload_hysteria_config()
        if success:
            flash('User deleted successfully!', 'success')
        else:
            flash(f'User deleted but {message}', 'warning')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('users'))

@app.route('/api/stats')
@login_required
def api_stats():
    stats = get_server_stats()
    return jsonify(stats)

@app.route('/settings')
@login_required
def settings():
    # Read current configuration
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
    
    return render_template('settings.html', config=config)

@app.route('/settings/update', methods=['POST'])
@login_required
def update_settings():
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        
        # Update basic settings
        config['up'] = request.form.get('upload_speed', '100 Mbps')
        config['down'] = request.form.get('download_speed', '100 Mbps')
        config['obfs'] = request.form.get('obfs', 'jaideevpn')
        
        # Convert to Mbps
        up_mbps = request.form.get('upload_mbps', '100')
        down_mbps = request.form.get('download_mbps', '100')
        config['up_mbps'] = int(up_mbps)
        config['down_mbps'] = int(down_mbps)
        
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Reload service
        subprocess.run(['systemctl', 'restart', SERVICE_NAME], check=True)
        flash('Settings updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating settings: {str(e)}', 'danger')
    
    return redirect(url_for('settings'))

@app.route('/service/restart')
@login_required
def restart_service():
    try:
        subprocess.run(['systemctl', 'restart', SERVICE_NAME], check=True)
        flash('Service restarted successfully!', 'success')
    except Exception as e:
        flash(f'Error restarting service: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/service/stop')
@login_required
def stop_service():
    try:
        subprocess.run(['systemctl', 'stop', SERVICE_NAME], check=True)
        flash('Service stopped successfully!', 'info')
    except Exception as e:
        flash(f'Error stopping service: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/service/start')
@login_required
def start_service():
    try:
        subprocess.run(['systemctl', 'start', SERVICE_NAME], check=True)
        flash('Service started successfully!', 'success')
    except Exception as e:
        flash(f'Error starting service: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('WEB_PORT', 8880)))
EOF

    chmod +x "$WEB_DIR/web_app.py"
    
    # Create HTML templates
    cat << 'EOF' > "$WEB_DIR/templates/base.html"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YT-UDP Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        .sidebar {
            min-height: 100vh;
            background: linear-gradient(180deg, #2c3e50 0%, #3498db 100%);
        }
        .sidebar .nav-link {
            color: #fff;
        }
        .sidebar .nav-link:hover {
            background-color: rgba(255,255,255,0.1);
        }
        .sidebar .nav-link.active {
            background-color: #2980b9;
        }
        .card-stat {
            border-radius: 10px;
            transition: transform 0.3s;
        }
        .card-stat:hover {
            transform: translateY(-5px);
        }
        .status-active {
            color: #28a745;
        }
        .status-inactive {
            color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-3 col-lg-2 d-md-block sidebar collapse">
                <div class="position-sticky pt-3">
                    <h4 class="text-center text-white mb-4">
                        <i class="bi bi-shield-check"></i> JUE-UDP
                    </h4>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link {% if request.endpoint == 'index' %}active{% endif %}" href="{{ url_for('index') }}">
                                <i class="bi bi-speedometer2"></i> Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link {% if request.endpoint == 'users' %}active{% endif %}" href="{{ url_for('users') }}">
                                <i class="bi bi-people"></i> Users
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link {% if request.endpoint == 'settings' %}active{% endif %}" href="{{ url_for('settings') }}">
                                <i class="bi bi-gear"></i> Settings
                            </a>
                        </li>
                        <li class="nav-item mt-4">
                            <a class="nav-link text-danger" href="{{ url_for('logout') }}">
                                <i class="bi bi-box-arrow-right"></i> Logout
                            </a>
                        </li>
                    </ul>
                </div>
            </nav>

            <!-- Main content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">{% block title %}{% endblock %}</h1>
                </div>

                <!-- Flash messages -->
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}

                {% block content %}{% endblock %}
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

    cat << 'EOF' > "$WEB_DIR/templates/login.html"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - YT-UDP Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .login-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .login-header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            border-radius: 20px 20px 0 0;
            padding: 2rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="login-card">
                    <div class="login-header text-center">
                        <h2><i class="bi bi-shield-check"></i> JUE-UDP</h2>
                        <p class="mb-0">Admin Panel</p>
                    </div>
                    <div class="card-body p-4">
                        <form method="POST" action="{{ url_for('login') }}">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="bi bi-box-arrow-in-right"></i> Login
                            </button>
                        </form>
                        {% with messages = get_flashed_messages(with_categories=true) %}
                            {% if messages %}
                                {% for category, message in messages %}
                                    <div class="alert alert-{{ category }} mt-3" role="alert">
                                        {{ message }}
                                    </div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF

    cat << 'EOF' > "$WEB_DIR/templates/dashboard.html"
{% extends "base.html" %}

{% block title %}Dashboard{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-3">
        <div class="card card-stat bg-primary text-white mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6 class="card-title">Total Users</h6>
                        <h2 class="mb-0">{{ stats.total_users }}</h2>
                    </div>
                    <div>
                        <i class="bi bi-people-fill" style="font-size: 3rem;"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card card-stat bg-success text-white mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6 class="card-title">Active Users</h6>
                        <h2 class="mb-0">{{ stats.active_users }}</h2>
                    </div>
                    <div>
                        <i class="bi bi-check-circle-fill" style="font-size: 3rem;"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card card-stat bg-info text-white mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6 class="card-title">Server Status</h6>
                        <h4 class="mb-0">
                            {% if stats.server_status == 'active' %}
                                <span class="badge bg-success">RUNNING</span>
                            {% elif stats.server_status == 'inactive' %}
                                <span class="badge bg-danger">STOPPED</span>
                            {% else %}
                                <span class="badge bg-warning">{{ stats.server_status }}</span>
                            {% endif %}
                        </h4>
                    </div>
                    <div>
                        <i class="bi bi-server" style="font-size: 3rem;"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card card-stat bg-warning text-white mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6 class="card-title">Connection Port</h6>
                        <h4 class="mb-0">UDP 36712</h4>
                    </div>
                    <div>
                        <i class="bi bi-router-fill" style="font-size: 3rem;"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Quick Actions</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3">
                        <a href="{{ url_for('users') }}" class="btn btn-outline-primary w-100 mb-2">
                            <i class="bi bi-person-plus"></i> Manage Users
                        </a>
                    </div>
                    <div class="col-md-3">
                        <a href="{{ url_for('restart_service') }}" class="btn btn-outline-success w-100 mb-2">
                            <i class="bi bi-arrow-clockwise"></i> Restart Service
                        </a>
                    </div>
                    <div class="col-md-3">
                        <a href="{{ url_for('settings') }}" class="btn btn-outline-info w-100 mb-2">
                            <i class="bi bi-gear"></i> Server Settings
                        </a>
                    </div>
                    <div class="col-md-3">
                        <button class="btn btn-outline-secondary w-100 mb-2" onclick="refreshStats()">
                            <i class="bi bi-arrow-repeat"></i> Refresh Stats
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Server Information</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <table class="table">
                            <tr>
                                <th>Protocol:</th>
                                <td>UDP</td>
                            </tr>
                            <tr>
                                <th>Port:</th>
                                <td>36712</td>
                            </tr>
                            <tr>
                                <th>Obfuscation:</th>
                                <td>YT-Plus</td>
                            </tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <table class="table">
                            <tr>
                                <th>Upload Speed:</th>
                                <td>20 Mbps</td>
                            </tr>
                            <tr>
                                <th>Download Speed:</th>
                                <td>20 Mbps</td>
                            </tr>
                            <tr>
                                <th>Domain:</th>
                                <td>y.ytudp.com</td>
                            </tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
function refreshStats() {
    $.get('/api/stats', function(data) {
        // Update stats dynamically
        $('.card-stat:nth-child(1) h2').text(data.total_users);
        $('.card-stat:nth-child(2) h2').text(data.active_users);
        
        let statusBadge = $('.card-stat:nth-child(3) .badge');
        statusBadge.removeClass('bg-success bg-danger bg-warning');
        
        if(data.server_status === 'active') {
            statusBadge.text('RUNNING').addClass('bg-success');
        } else if(data.server_status === 'inactive') {
            statusBadge.text('STOPPED').addClass('bg-danger');
        } else {
            statusBadge.text(data.server_status).addClass('bg-warning');
        }
        
        // Show success message
        alert('Stats refreshed successfully!');
    });
}

// Auto-refresh every 30 seconds
setInterval(refreshStats, 30000);
</script>
{% endblock %}
EOF

    cat << 'EOF' > "$WEB_DIR/templates/users.html"
{% extends "base.html" %}

{% block title %}User Management{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2>User Management</h2>
    <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addUserModal">
        <i class="bi bi-person-plus"></i> Add New User
    </button>
</div>

<div class="card">
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.id }}</td>
                        <td>{{ user.username }}</td>
                        <td>
                            <input type="password" value="{{ user.password }}" class="form-control form-control-sm" readonly style="width: 150px;">
                        </td>
                        <td>
                            {% if user.is_active == 1 %}
                                <span class="badge bg-success">Active</span>
                            {% else %}
                                <span class="badge bg-danger">Inactive</span>
                            {% endif %}
                        </td>
                        <td>{{ user.created_at }}</td>
                        <td>
                            <button type="button" class="btn btn-sm btn-warning" data-bs-toggle="modal" data-bs-target="#editUserModal{{ user.id }}">
                                <i class="bi bi-pencil"></i>
                            </button>
                            <a href="{{ url_for('delete_user', user_id=user.id) }}" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure?')">
                                <i class="bi bi-trash"></i>
                            </a>
                        </td>
                    </tr>

                    <!-- Edit User Modal -->
                    <div class="modal fade" id="editUserModal{{ user.id }}" tabindex="-1">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title">Edit User</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                </div>
                                <form method="POST" action="{{ url_for('edit_user', user_id=user.id) }}">
                                    <div class="modal-body">
                                        <div class="mb-3">
                                            <label class="form-label">Username</label>
                                            <input type="text" class="form-control" name="username" value="{{ user.username }}" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Password</label>
                                            <input type="text" class="form-control" name="password" value="{{ user.password }}" required>
                                        </div>
                                        <div class="mb-3">
                                            <div class="form-check">
                                                <input class="form-check-input" type="checkbox" name="is_active" value="1" id="active{{ user.id }}" {% if user.is_active == 1 %}checked{% endif %}>
                                                <label class="form-check-label" for="active{{ user.id }}">
                                                    Active
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                        <button type="submit" class="btn btn-primary">Save Changes</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Add User Modal -->
<div class="modal fade" id="addUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Add New User</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="{{ url_for('add_user') }}">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" class="form-control" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="text" class="form-control" name="password" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add User</button>
                </div>
            </form>
        </div>
    </div>
</div>
{% endblock %}
EOF

    cat << 'EOF' > "$WEB_DIR/templates/settings.html"
{% extends "base.html" %}

{% block title %}Server Settings{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Server Configuration</h5>
            </div>
            <form method="POST" action="{{ url_for('update_settings') }}">
                <div class="card-body">
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Upload Speed</label>
                            <input type="text" class="form-control" name="upload_speed" value="{{ config.up }}">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Upload (Mbps)</label>
                            <input type="number" class="form-control" name="upload_mbps" value="{{ config.up_mbps }}">
                        </div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Download Speed</label>
                            <input type="text" class="form-control" name="download_speed" value="{{ config.down }}">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Download (Mbps)</label>
                            <input type="number" class="form-control" name="download_mbps" value="{{ config.down_mbps }}">
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Obfuscation Password</label>
                        <input type="text" class="form-control" name="obfs" value="{{ config.obfs }}">
                    </div>
                </div>
                <div class="card-footer">
                    <button type="submit" class="btn btn-primary">Save Settings</button>
                </div>
            </form>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Service Control</h5>
            </div>
            <div class="card-body">
                <div class="d-grid gap-2">
                    <a href="{{ url_for('restart_service') }}" class="btn btn-success">
                        <i class="bi bi-arrow-clockwise"></i> Restart Service
                    </a>
                    <a href="{{ url_for('stop_service') }}" class="btn btn-warning">
                        <i class="bi bi-stop-circle"></i> Stop Service
                    </a>
                    <a href="{{ url_for('start_service') }}" class="btn btn-info">
                        <i class="bi bi-play-circle"></i> Start Service
                    </a>
                </div>
            </div>
        </div>
        
        <div class="card mt-3">
            <div class="card-header">
                <h5 class="mb-0">Current Configuration</h5>
            </div>
            <div class="card-body">
                <pre style="font-size: 12px;">{{ config|tojson(indent=2) }}</pre>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

    # Create requirements.txt for Python dependencies
    cat << 'EOF' > "$WEB_DIR/requirements.txt"
Flask==2.3.3
Werkzeug==2.3.7
EOF

    # Install Python dependencies
    echo "Installing Python dependencies..."
    pip3 install -r "$WEB_DIR/requirements.txt"
}

perform_install_hysteria_binary() {
    if [[ -n "$LOCAL_FILE" ]]; then
        note "Performing local install: $LOCAL_FILE"

        echo -ne "Installing hysteria executable ... "

        if install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH"; then
            echo "ok"
        else
            exit 2
        fi

        return
    fi

    local _tmpfile=$(mktemp)

    if ! download_hysteria "$VERSION" "$_tmpfile"; then
        rm -f "$_tmpfile"
        exit 11
    fi

    echo -ne "Installing hysteria executable ... "

    if install -Dm755 "$_tmpfile" "$EXECUTABLE_INSTALL_PATH"; then
        echo "ok"
    else
        exit 13
    fi

    rm -f "$_tmpfile"
}

perform_remove_hysteria_binary() {
    remove_file "$EXECUTABLE_INSTALL_PATH"
}

perform_install_hysteria_example_config() {
    tpl_etc_hysteria_config_json
}

perform_install_hysteria_systemd() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi

    install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"

    systemctl daemon-reload
}

perform_install_web_systemd() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi

    # Create environment file for web service
    cat << EOF > "$WEB_DIR/.env"
WEB_PORT=$WEB_PORT
WEB_USERNAME=$WEB_USERNAME
WEB_PASSWORD=$WEB_PASSWORD
SESSION_SECRET=$WEB_SESSION_SECRET
EOF

    install_content -Dm644 "$(tpl_jueudp_web_service)" "$WEB_SYSTEMD_SERVICE"
    systemctl daemon-reload
}

perform_remove_hysteria_systemd() {
    remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
    
    # Remove web service
    if [[ -f "$WEB_SYSTEMD_SERVICE" ]]; then
        systemctl stop jueudp-web.service 2>/dev/null || true
        systemctl disable jueudp-web.service 2>/dev/null || true
        remove_file "$WEB_SYSTEMD_SERVICE"
    fi

    systemctl daemon-reload
}

perform_install_hysteria_home_legacy() {
    if ! is_user_exists "$HYSTERIA_USER"; then
        echo -ne "Creating user $HYSTERIA_USER ... "
        useradd -r -d "$HYSTERIA_HOME_DIR" -m "$HYSTERIA_USER"
        echo "ok"
    fi
}

perform_install_manager_script() {
    local _manager_script="/usr/local/bin/jueudp_manager.sh"
    local _symlink_path="/usr/local/bin/jueudp"
    
    echo "Downloading manager script..."
    curl -o "$_manager_script" "https://raw.githubusercontent.com/Juessh/Juevpnscript/main/jueudp_manager.sh"
    chmod +x "$_manager_script"
    
    echo "Creating symbolic link to run the manager script using 'jueudp' command..."
    ln -sf "$_manager_script" "$_symlink_path"
    
    echo "Manager script installed at $_manager_script"
    echo "You can now run the manager using the 'jueudp' command."
}

is_hysteria_installed() {
    # RETURN VALUE
    # 0: hysteria is installed
    # 1: hysteria is not installed
    
    if [[ -f "$EXECUTABLE_INSTALL_PATH" || -h "$EXECUTABLE_INSTALL_PATH" ]]; then
        return 0
    fi
    return 1
}

get_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    
    systemctl list-units --state=active --plain --no-legend \
    | grep -o "hysteria-server@*[^\s]*.service" || true
}

restart_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    
    echo "Restarting running service ... "
    
    for service in $(get_running_services()); do
        echo -ne "Restarting $service ... "
        systemctl restart "$service"
        echo "done"
    done
}

stop_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    
    echo "Stopping running service ... "
    
    for service in $(get_running_services()); do
        echo -ne "Stopping $service ... "
        systemctl stop "$service"
        echo "done"
    done
}

perform_install() {
    local _is_fresh_install
    if ! is_hysteria_installed; then
        _is_fresh_install=1
    fi

    perform_install_hysteria_binary
    perform_install_hysteria_example_config
    perform_install_hysteria_home_legacy
    perform_install_hysteria_systemd
    setup_ssl
    start_services
    
    # Install Web Admin Panel
    create_web_admin
    perform_install_web_systemd
    start_web_services
    
    perform_install_manager_script

    if [[ -n "$_is_fresh_install" ]]; then
        echo
        echo -e "$(tbold)Congratulations! JUE-UDP with Web Admin Panel has been successfully installed on your server.$(treset)"
        echo "Use 'jueudp' command to access the manager."
        echo
        echo -e "$(tbold)Web Admin Panel Access:$(treset)"
        echo -e "\tURL: $(tblue)http://$(curl -s ifconfig.me):$WEB_PORT$(treset)"
        echo -e "\tUsername: $(tgreen)$WEB_USERNAME$(treset)"
        echo -e "\tPassword: $(tgreen)$WEB_PASSWORD$(treset)"
        echo
        echo -e "$(tbold)Client app Jaidee VPN:$(treset)"
        echo -e "$(tblue)https://play.google.com/store/apps/details?id=com.jaideevpn.net$(treset)"
        echo
        echo -e "Follow me!"
        echo
        echo -e "\t+ Check out my website at $(tblue)https://t.me/jaideevpn$(treset)"
        echo -e "\t+ Follow me on Telegram: $(tblue)https://t.me/Pussy1990$(treset)"
        echo -e "\t+ Follow me on Facebook: $(tblue)https://www.facebook.com/juehtet2025$(treset)"
        echo
    else
        restart_running_services
        start_services
        start_web_services
        echo
        echo -e "$(tbold)JUE-UDP has been successfully updated to $VERSION.$(treset)"
        echo
        echo -e "$(tbold)Web Admin Panel is running at:$(treset)"
        echo -e "\t$(tblue)http://$(curl -s ifconfig.me):$WEB_PORT$(treset)"
        echo
    fi
}

perform_remove() {
    perform_remove_hysteria_binary
    stop_running_services
    perform_remove_hysteria_systemd

    echo
    echo -e "$(tbold)Congratulations! AGN-UDP has been successfully removed from your server.$(treset)"
    echo
    echo -e "You still need to remove configuration files and ACME certificates manually with the following commands:"
    echo
    echo -e "\t$(tred)rm -rf "$CONFIG_DIR"$(treset)"
    echo -e "\t$(tred)rm -rf "$WEB_DIR"$(treset)"
    if [[ "x$HYSTERIA_USER" != "xroot" ]]; then
        echo -e "\t$(tred)userdel -r "$HYSTERIA_USER"$(treset)"
    fi
    if [[ "x$FORCE_NO_SYSTEMD" != "x2" ]]; then
        echo
        echo -e "You still might need to disable all related systemd services with the following commands:"
        echo
        echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service$(treset)"
        echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server@*.service$(treset)"
        echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/jueudp-web.service$(treset)"
        echo -e "\t$(tred)systemctl daemon-reload$(treset)"
    fi
    echo
}

setup_ssl() {
    echo "Installing SSL certificates"

    openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048

    openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt

    openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr

    openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt
}

start_services() {
    echo "Starting AGN-UDP"
    apt update
    sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
    sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
    apt -y install iptables-persistent
    iptables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    ip6tables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    sysctl net.ipv4.conf.all.rp_filter=0
    sysctl net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0
    echo "net.ipv4.ip_forward = 1
    net.ipv4.conf.all.rp_filter=0
    net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0" > /etc/sysctl.conf
    sysctl -p
    sudo iptables-save > /etc/iptables/rules.v4
    sudo ip6tables-save > /etc/iptables/rules.v6
    systemctl enable hysteria-server.service
    systemctl start hysteria-server.service
}

start_web_services() {
    echo "Starting Web Admin Panel"
    systemctl enable jueudp-web.service
    systemctl start jueudp-web.service
}

main() {
    parse_arguments "$@"
    check_permission
    check_environment
    check_hysteria_user "hysteria"
    check_hysteria_homedir "/var/lib/$HYSTERIA_USER"
    case "$OPERATION" in
        "install")
            setup_db
            perform_install
            ;;
        "remove")
            perform_remove
            ;;
        *)
            error "Unknown operation '$OPERATION'."
            ;;
    esac
}

main "$@"
