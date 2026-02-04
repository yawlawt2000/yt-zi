cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Fully Responsive Modern Web Panel
# - Mobile & Desktop optimized UI
# - Touch-friendly interface
# - Adaptive layouts for all screen sizes

set -euo pipefail

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
SYNC_PY="${ADMIN_DIR}/sync.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"
SYNC_SVC="zivpn-sync.service"
SYNC_TIMER="zivpn-sync.timer"

ADMINCTL="/usr/local/sbin/zivpn-adminctl"
UNINSTALL="/usr/local/sbin/zivpn-uninstall.sh"

echo "==> Updating packages..."
apt-get update -y && apt-get upgrade -y
apt-get install -y python3-venv python3-pip openssl ufw curl jq conntrack > /dev/null

echo "==> Installing ZIVPN binary..."
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"

mkdir -p "${ZIVPN_DIR}"
cat > "${ZIVPN_CFG}" <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {"mode": "passwords", "config": ["zi"]},
  "config": ["zi"]
}
JSON

echo "==> Generating TLS certificate..."
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" > /dev/null 2>&1

# --- systemd unit (ExecReload only; panel never restarts) ---
cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${ZIVPN_SVC}

# --- UDP stability: conntrack timeouts boost ---
cat > /etc/sysctl.d/99-zivpn-udp.conf <<'SYS'
net.netfilter.nf_conntrack_udp_timeout=300
net.netfilter.nf_conntrack_udp_timeout_stream=1800
net.core.rmem_max=26214400
net.core.wmem_max=26214400
SYS
sysctl --system > /dev/null

# --- NAT: replace DNAT with REDIRECT to local 5667 ---
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
iptables -t nat -S PREROUTING | awk '/--dport 6000:19999/ {print $0}' | sed 's/^-A /-D /' | while read -r r; do iptables -t nat $r || true; done
if ! iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667 2>/dev/null; then
  iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667
fi

# --- firewall ---
ufw allow 5667/udp || true
ufw allow 8088/tcp || true

echo "==> Setting up Responsive Web Admin Panel..."
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install flask waitress > /dev/null

# Interactive admin creds (initial)
read -rp "Admin username [default: admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -rp "Admin password [default: admin123]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin123}

cat > "${ENV_FILE}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

# ------------------- app.py with Fully Responsive UI -------------------
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess, time, random
from datetime import date, datetime
from flask import Flask, request, redirect, url_for, session, render_template_string, flash, jsonify
from functools import wraps

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)
ZIVPN_CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")
ADMIN_USER=os.getenv("ADMIN_USER","admin")
ADMIN_PASS=os.getenv("ADMIN_PASSWORD","admin123")
app=Flask(__name__)
app.secret_key=os.urandom(24)

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        expires DATE,
        created DATE DEFAULT (DATE('now'))
    )""")

def logs():
    try:
        return subprocess.check_output(["journalctl","-u",ZIVPN_SVC,"--since","-15min","-o","cat"]).decode().lower()
    except Exception:
        return ""

def days_left(expires_str):
    try:
        exp=datetime.strptime(expires_str,"%Y-%m-%d").date()
        return (exp - date.today()).days
    except Exception:
        return None

def active_rows():
    log=logs()
    today=date.today()
    rows=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users ORDER BY id DESC"):
            exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
            expired=exp<today
            online=(not expired) and (r["password"].lower() in log)
            rows.append({
                "id":r["id"], "username":r["username"], "password":r["password"],
                "expires":r["expires"], "created":r["created"], "expired":expired, "online":online,
                "days_left": days_left(r["expires"])
            })
    return rows

def write_cfg(passwords):
    cfg={}
    try:
        cfg=json.load(open(ZIVPN_CFG))
    except Exception:
        pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=passwords
    cfg["config"]=passwords
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)

def sync():
    with db() as con:
        pw=[r[0] for r in con.execute(
            "SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    if not pw: pw=["zi"]
    write_cfg(pw)

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**kw)
    return w

# ---------- Login Page (Mobile Optimized) ----------
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("u")==ADMIN_USER and request.form.get("p")==ADMIN_PASS:
            session["ok"]=True
            return redirect("/")
        flash("Invalid credentials", "error")
    return render_template_string('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>ZIVPN | Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media (max-width: 640px) {
            .login-container {
                margin: 0 !important;
                border-radius: 0 !important;
                min-height: 100vh !important;
            }
        }
        .gradient-bg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .glass {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .input-glass {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            backdrop-filter: blur(5px);
        }
        .input-glass:focus {
            background: rgba(255, 255, 255, 0.15);
            border-color: rgba(255, 255, 255, 0.3);
        }
    </style>
</head>
<body class="gradient-bg min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md">
        <div class="text-center mb-8">
            <div class="inline-block p-4 rounded-2xl glass mb-4">
                <svg class="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                </svg>
            </div>
            <h1 class="text-3xl font-bold text-white mb-2">ZIVPN Admin</h1>
            <p class="text-white/80">Secure VPN Management Panel</p>
        </div>
        
        <div class="glass rounded-2xl shadow-2xl p-6 sm:p-8 login-container">
            <h2 class="text-xl font-semibold text-white mb-6">Sign in to continue</h2>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="mb-4 p-3 rounded-lg bg-red-500/20 border border-red-500/30 text-red-200 text-sm">
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <form method="POST" class="space-y-6">
                <div>
                    <label class="block text-white/70 text-sm font-medium mb-2">Username</label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <svg class="w-5 h-5 text-white/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                            </svg>
                        </div>
                        <input name="u" type="text" required 
                               class="w-full pl-10 pr-4 py-3 rounded-xl input-glass text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-white/30 text-base"
                               placeholder="Enter username">
                    </div>
                </div>
                
                <div>
                    <label class="block text-white/70 text-sm font-medium mb-2">Password</label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <svg class="w-5 h-5 text-white/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                        </div>
                        <input name="p" type="password" required 
                               class="w-full pl-10 pr-4 py-3 rounded-xl input-glass text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-white/30 text-base"
                               placeholder="Enter password">
                    </div>
                </div>
                
                <button type="submit" 
                        class="w-full bg-white text-indigo-600 hover:bg-gray-100 font-semibold py-3 px-4 rounded-xl transition duration-200 active:scale-95 touch-manipulation">
                    Sign In
                </button>
            </form>
            
            <div class="mt-6 pt-6 border-t border-white/10">
                <p class="text-center text-white/60 text-sm">
                    Secure your connections with ZIVPN
                </p>
            </div>
        </div>
        
        <div class="text-center mt-6 text-white/50 text-sm">
            <p>ZIVPN UDP VPN System • v1.0</p>
        </div>
    </div>
</body>
</html>''')

# ---------- Main Dashboard (Fully Responsive) ----------
@app.route("/")
@login_required
def index():
    rows=active_rows()
    total_users=len(rows)
    total_online=sum(1 for r in rows if not r["expired"])
    total_offline=sum(1 for r in rows if r["expired"])
    default_exp=date.today().isoformat()
    
    try:
        vps_ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception:
        vps_ip=request.host.split(":")[0]
    
    server_ts=int(time.time())
    
    return render_template_string('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes">
    <title>ZIVPN Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        /* Base styles for all devices */
        .gradient-bg {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }
        .dark-gradient-bg {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        }
        .glass {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        .dark-glass {
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        /* Mobile-specific optimizations */
        @media (max-width: 640px) {
            .mobile-padding {
                padding-left: 1rem;
                padding-right: 1rem;
            }
            .mobile-stack {
                flex-direction: column;
            }
            .mobile-full {
                width: 100% !important;
            }
            .mobile-text-sm {
                font-size: 0.875rem;
            }
            .mobile-text-xs {
                font-size: 0.75rem;
            }
            .mobile-hide {
                display: none;
            }
            .mobile-show {
                display: block;
            }
            .mobile-table {
                font-size: 0.75rem;
            }
            .mobile-btn {
                padding: 0.5rem 0.75rem;
                font-size: 0.875rem;
            }
            .mobile-stats-grid {
                grid-template-columns: repeat(2, 1fr) !important;
                gap: 0.75rem !important;
            }
            .mobile-icon-only {
                min-width: 44px !important;
                min-height: 44px !important;
            }
            .mobile-touch-target {
                min-height: 44px;
                min-width: 44px;
            }
        }
        
        /* Tablet optimizations */
        @media (min-width: 641px) and (max-width: 1024px) {
            .tablet-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .tablet-full {
                width: 100%;
            }
        }
        
        /* Desktop optimizations */
        @media (min-width: 1025px) {
            .desktop-grid {
                grid-template-columns: repeat(3, 1fr);
            }
        }
        
        /* Common responsive utilities */
        .scrollbar-hide::-webkit-scrollbar {
            display: none;
        }
        .fade-in {
            animation: fadeIn 0.3s ease-in-out;
        }
        .touch-manipulation {
            touch-action: manipulation;
        }
        .safe-area-padding {
            padding-left: env(safe-area-inset-left);
            padding-right: env(safe-area-inset-right);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
    <script>
        // Load saved theme on page load
        document.addEventListener('DOMContentLoaded', function() {
            const savedTheme = localStorage.getItem('zivpn-theme');
            const html = document.documentElement;
            const isMobile = window.innerWidth <= 768;
            
            if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                html.classList.add('dark');
                updateThemeIcons(true);
            } else {
                updateThemeIcons(false);
            }
            
            // Mobile-specific optimizations
            if (isMobile) {
                // Make all buttons touch-friendly
                document.querySelectorAll('button').forEach(btn => {
                    btn.classList.add('touch-manipulation');
                });
                
                // Adjust table layout for mobile
                const table = document.querySelector('table');
                if (table) {
                    table.classList.add('mobile-table');
                }
            }
            
            // Auto-copy when password field is focused
            const passwordInput = document.querySelector('input[name="password"]');
            if (passwordInput) {
                passwordInput.addEventListener('focus', function() {
                    this.select();
                });
            }
        });
        
        function updateThemeIcons(isDark) {
            const sunIcon = document.getElementById('sun-icon');
            const moonIcon = document.getElementById('moon-icon');
            if (isDark) {
                if (sunIcon) sunIcon.classList.remove('hidden');
                if (moonIcon) moonIcon.classList.add('hidden');
            } else {
                if (sunIcon) sunIcon.classList.add('hidden');
                if (moonIcon) moonIcon.classList.remove('hidden');
            }
        }
        
        // Theme Toggle
        function toggleTheme() {
            const html = document.documentElement;
            const isDark = html.classList.contains('dark');
            
            if (isDark) {
                html.classList.remove('dark');
                localStorage.setItem('zivpn-theme', 'light');
                updateThemeIcons(false);
            } else {
                html.classList.add('dark');
                localStorage.setItem('zivpn-theme', 'dark');
                updateThemeIcons(true);
            }
        }
        
        // Copy to clipboard - Mobile optimized
        function copyToClipboard(text) {
            // Create a temporary input element for mobile compatibility
            const tempInput = document.createElement('input');
            tempInput.value = text;
            document.body.appendChild(tempInput);
            tempInput.select();
            tempInput.setSelectionRange(0, 99999); // For mobile devices
            
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    showCopySuccess();
                } else {
                    // Fallback to modern API if available
                    if (navigator.clipboard && window.isSecureContext) {
                        navigator.clipboard.writeText(text).then(() => {
                            showCopySuccess();
                        });
                    }
                }
            } catch (err) {
                console.error('Copy failed:', err);
                // Final fallback
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(text).then(() => {
                        showCopySuccess();
                    });
                }
            }
            
            document.body.removeChild(tempInput);
        }
        
        function showCopySuccess() {
            // Mobile-friendly toast
            const toast = document.createElement('div');
            toast.className = 'fixed top-4 right-4 z-50 px-4 py-3 rounded-lg bg-emerald-500 text-white shadow-lg fade-in mobile-touch-target';
            toast.innerHTML = `
                <div class="flex items-center">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                    </svg>
                    <span class="text-sm font-medium">Copied!</span>
                </div>
            `;
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.classList.add('opacity-0', 'transition-opacity', 'duration-300');
                setTimeout(() => toast.remove(), 300);
            }, 1500);
        }
        
        // Edit user function
        function editUser(username, password, expires) {
            document.querySelector('input[name="username"]').value = username;
            document.querySelector('input[name="password"]').value = password;
            document.querySelector('input[name="expires"]').value = expires;
            
            // Scroll to form with mobile consideration
            const form = document.getElementById('userForm');
            form.scrollIntoView({ 
                behavior: 'smooth',
                block: 'start'
            });
            
            // Highlight the form
            form.classList.add('ring-2', 'ring-indigo-500');
            setTimeout(() => {
                form.classList.remove('ring-2', 'ring-indigo-500');
            }, 2000);
        }
        
        // Confirm delete - Mobile friendly
        function confirmDelete(username) {
            return Swal.fire({
                title: 'Delete User?',
                text: `Delete "${username}"?`,
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#ef4444',
                cancelButtonColor: '#6b7280',
                confirmButtonText: 'Delete',
                cancelButtonText: 'Cancel',
                reverseButtons: true,
                customClass: {
                    popup: 'mobile-text-sm',
                    confirmButton: 'mobile-btn',
                    cancelButton: 'mobile-btn'
                }
            }).then((result) => {
                return result.isConfirmed;
            });
        }
        
        // Auto-generate password
        function generatePassword() {
            const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
            let password = '';
            for (let i = 0; i < 12; i++) {
                password += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            document.querySelector('input[name="password"]').value = password;
            copyToClipboard(password);
        }
        
        // Toggle mobile menu
        function toggleMobileMenu() {
            const menu = document.getElementById('mobile-menu');
            menu.classList.toggle('hidden');
        }
        
        // Detect mobile device
        function isMobileDevice() {
            return window.innerWidth <= 768;
        }
    </script>
</head>
<body class="gradient-bg dark:dark-gradient-bg min-h-screen transition-colors duration-300 safe-area-padding">
    <!-- Mobile Navigation -->
    <nav class="glass dark:dark-glass sticky top-0 z-50 transition-colors duration-300 lg:hidden">
        <div class="px-4 py-3">
            <div class="flex justify-between items-center">
                <div class="flex items-center">
                    <div class="p-2 rounded-lg bg-indigo-500 mr-3">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                        </svg>
                    </div>
                    <span class="text-xl font-bold text-gray-800 dark:text-white">ZIVPN</span>
                </div>
                <div class="flex items-center space-x-3">
                    <button onclick="toggleTheme()" class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 mobile-icon-only">
                        <svg id="sun-icon" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
                        </svg>
                        <svg id="moon-icon" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                        </svg>
                    </button>
                    <button onclick="toggleMobileMenu()" class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 mobile-icon-only">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
                        </svg>
                    </button>
                </div>
            </div>
            
            <!-- Mobile Menu Dropdown -->
            <div id="mobile-menu" class="hidden mt-4 space-y-2">
                <button onclick="generatePassword()" class="w-full bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg font-medium py-3 flex items-center justify-center mobile-touch-target">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                    </svg>
                    Generate Password
                </button>
                <form method="POST" action="/apply" onsubmit="return confirm('Apply configuration changes?');" class="w-full">
                    <button type="submit" class="w-full bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg font-medium py-3 flex items-center justify-center mobile-touch-target">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                        </svg>
                        Apply Changes
                    </button>
                </form>
                <a href="/logout" class="w-full bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium py-3 flex items-center justify-center mobile-touch-target block text-center">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                    </svg>
                    Logout
                </a>
            </div>
            
            <!-- Server Info for Mobile -->
            <div class="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                <div class="text-xs text-gray-600 dark:text-gray-400">
                    <span class="font-medium">IP:</span> {{ vps_ip }} • <span class="font-medium">Port:</span> 5667/UDP
                </div>
            </div>
        </div>
    </nav>

    <!-- Desktop Navigation -->
    <nav class="glass dark:dark-glass sticky top-0 z-50 transition-colors duration-300 hidden lg:block">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center h-16">
                <div class="flex items-center">
                    <div class="flex-shrink-0 flex items-center">
                        <div class="p-2 rounded-lg bg-indigo-500 mr-3">
                            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                        </div>
                        <span class="text-xl font-bold text-gray-800 dark:text-white">ZIVPN</span>
                        <span class="ml-2 px-2 py-1 text-xs rounded-full bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-200">PRO</span>
                    </div>
                    <div class="ml-10">
                        <div class="flex items-baseline space-x-4">
                            <span class="px-3 py-2 rounded-md text-sm font-medium bg-indigo-500 text-white">Dashboard</span>
                            <span class="text-gray-500 dark:text-gray-400 text-sm">IP: {{ vps_ip }}</span>
                        </div>
                    </div>
                </div>
                <div class="flex items-center space-x-4">
                    <button onclick="toggleTheme()" class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors duration-200">
                        <svg id="sun-icon" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
                        </svg>
                        <svg id="moon-icon" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                        </svg>
                    </button>
                    <button onclick="generatePassword()" class="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg font-medium transition duration-200 flex items-center">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                        </svg>
                        Generate Pass
                    </button>
                    <form method="POST" action="/apply" onsubmit="return confirm('Apply configuration changes? This will reload the VPN service.');">
                        <button type="submit" class="px-4 py-2 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg font-medium transition duration-200 transform hover:-translate-y-0.5 flex items-center">
                            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                            </svg>
                            Apply Changes
                        </button>
                    </form>
                    <a href="/logout" class="px-4 py-2 bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium transition duration-200 flex items-center">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                        </svg>
                        Logout
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 md:py-8">
        <!-- Stats Cards - Responsive Grid -->
        <div class="grid grid-cols-2 md:grid-cols-3 gap-3 md:gap-6 mb-6 md:mb-8 mobile-stats-grid">
            <div class="glass dark:dark-glass rounded-xl md:rounded-2xl p-4 md:p-6 shadow-soft dark:dark-shadow">
                <div class="flex items-center">
                    <div class="p-2 md:p-3 rounded-lg md:rounded-xl bg-indigo-100 dark:bg-indigo-900 mr-3 md:mr-4">
                        <svg class="w-6 h-6 md:w-8 md:h-8 text-indigo-600 dark:text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-8.5a6 6 0 01-6 6m6-6a6 6 0 00-6-6m6 6H3m18 0a6 6 0 01-6 6m6-6a6 6 0 00-6-6"/>
                        </svg>
                    </div>
                    <div>
                        <p class="text-xs md:text-sm text-gray-500 dark:text-gray-400">Total Users</p>
                        <p class="text-xl md:text-3xl font-bold text-gray-800 dark:text-white">{{ total_users }}</p>
                    </div>
                </div>
            </div>
            
            <div class="glass dark:dark-glass rounded-xl md:rounded-2xl p-4 md:p-6 shadow-soft dark:dark-shadow">
                <div class="flex items-center">
                    <div class="p-2 md:p-3 rounded-lg md:rounded-xl bg-emerald-100 dark:bg-emerald-900 mr-3 md:mr-4">
                        <svg class="w-6 h-6 md:w-8 md:h-8 text-emerald-600 dark:text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z"/>
                        </svg>
                    </div>
                    <div>
                        <p class="text-xs md:text-sm text-gray-500 dark:text-gray-400">Active Users</p>
                        <p class="text-xl md:text-3xl font-bold text-gray-800 dark:text-white">{{ total_online }}</p>
                    </div>
                </div>
            </div>
            
            <div class="col-span-2 md:col-span-1 glass dark:dark-glass rounded-xl md:rounded-2xl p-4 md:p-6 shadow-soft dark:dark-shadow">
                <div class="flex items-center">
                    <div class="p-2 md:p-3 rounded-lg md:rounded-xl bg-blue-100 dark:bg-blue-900 mr-3 md:mr-4">
                        <svg class="w-6 h-6 md:w-8 md:h-8 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                        </svg>
                    </div>
                    <div>
                        <p class="text-xs md:text-sm text-gray-500 dark:text-gray-400">Server Status</p>
                        <p class="text-xl md:text-3xl font-bold text-gray-800 dark:text-white">Online</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Actions & Server Info - Responsive Layout -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6 mb-6 md:mb-8">
            <!-- Add User Form - Mobile Full Width -->
            <div class="lg:col-span-1">
                <div class="glass dark:dark-glass rounded-xl md:rounded-2xl p-4 md:p-6 shadow-soft dark:dark-shadow mobile-full">
                    <h2 class="text-base md:text-lg font-semibold text-gray-800 dark:text-white mb-3 md:mb-4">Add New User</h2>
                    <form method="POST" action="/save" id="userForm" class="space-y-3 md:space-y-4">
                        <div>
                            <label class="block text-xs md:text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 md:mb-2">Username</label>
                            <input type="text" name="username" required
                                   class="w-full px-3 py-2 md:px-4 md:py-3 rounded-lg md:rounded-xl border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm md:text-base"
                                   placeholder="Enter username">
                        </div>
                        
                        <div>
                            <label class="block text-xs md:text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 md:mb-2">Password</label>
                            <div class="relative">
                                <input type="text" name="password" required
                                       class="w-full px-3 py-2 md:px-4 md:py-3 rounded-lg md:rounded-xl border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm md:text-base"
                                       placeholder="Enter password">
                                <button type="button" onclick="copyToClipboard(document.querySelector('input[name=\"password\"]').value)" 
                                        class="absolute right-2 top-1/2 transform -translate-y-1/2 p-1 md:p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 mobile-touch-target">
                                    <svg class="w-4 h-4 md:w-5 md:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
                                    </svg>
                                </button>
                            </div>
                            <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">Tap copy icon or generate</p>
                        </div>
                        
                        <div>
                            <label class="block text-xs md:text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 md:mb-2">Expiration Date</label>
                            <input type="date" name="expires" value="{{ default_exp }}" required
                                   class="w-full px-3 py-2 md:px-4 md:py-3 rounded-lg md:rounded-xl border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm md:text-base">
                        </div>
                        
                        <button type="submit"
                                class="w-full bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 text-white font-semibold py-2 md:py-3 px-4 rounded-lg md:rounded-xl transition duration-200 active:scale-95 touch-manipulation mobile-touch-target">
                            <div class="flex items-center justify-center text-sm md:text-base">
                                <svg class="w-4 h-4 md:w-5 md:h-5 mr-1 md:mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                                </svg>
                                Create User Account
                            </div>
                        </button>
                    </form>
                    
                    <div class="mt-4 md:mt-6 pt-3 md:pt-6 border-t border-gray-200 dark:border-gray-700">
                        <div class="flex items-center text-xs md:text-sm text-gray-500 dark:text-gray-400">
                            <svg class="w-3 h-3 md:w-4 md:h-4 mr-1 md:mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                            </svg>
                            <span class="truncate">IP: {{ vps_ip }} | Port: 5667/UDP</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Users Table - Responsive Layout -->
            <div class="lg:col-span-2">
                <div class="glass dark:dark-glass rounded-xl md:rounded-2xl shadow-soft dark:dark-shadow overflow-hidden mobile-full">
                    <div class="px-4 py-3 md:px-6 md:py-4 border-b border-gray-200 dark:border-gray-700">
                        <div class="flex justify-between items-center">
                            <h2 class="text-base md:text-lg font-semibold text-gray-800 dark:text-white">User Accounts</h2>
                            <span class="px-2 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300">
                                {{ rows|length }} accounts
                            </span>
                        </div>
                    </div>
                    
                    <div class="overflow-x-auto scrollbar-hide">
                        <table class="w-full min-w-[600px] md:min-w-0">
                            <thead class="bg-gray-50 dark:bg-gray-800">
                                <tr>
                                    <th class="px-3 py-2 md:px-6 md:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">User</th>
                                    <th class="px-3 py-2 md:px-6 md:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Password</th>
                                    <th class="hidden sm:table-cell px-3 py-2 md:px-6 md:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Expires</th>
                                    <th class="px-3 py-2 md:px-6 md:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                                    <th class="px-3 py-2 md:px-6 md:py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                {% for r in rows %}
                                <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                    <td class="px-3 py-2 md:px-6 md:py-4 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <div class="flex-shrink-0 h-6 w-6 md:h-8 md:w-8 rounded-full bg-indigo-100 dark:bg-indigo-900 flex items-center justify-center">
                                                <span class="text-xs md:text-sm font-medium text-indigo-600 dark:text-indigo-400">{{ r.username[0]|upper }}</span>
                                            </div>
                                            <div class="ml-2 md:ml-4">
                                                <div class="text-xs md:text-sm font-medium text-gray-900 dark:text-white truncate max-w-[80px] md:max-w-none">{{ r.username }}</div>
                                                <div class="text-xs text-gray-500 dark:text-gray-400 hidden md:block">Created: {{ r.created }}</div>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="px-3 py-2 md:px-6 md:py-4">
                                        <div class="flex items-center space-x-1 md:space-x-2">
                                            <code class="px-2 py-1 rounded bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200 font-mono text-xs md:text-sm truncate max-w-[80px] md:max-w-[120px]">{{ r.password }}</code>
                                            <button onclick="copyToClipboard('{{ r.password }}')" 
                                                    class="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded transition duration-200 flex items-center mobile-touch-target">
                                                <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
                                                </svg>
                                                <span class="hidden md:inline">Copy</span>
                                            </button>
                                        </div>
                                    </td>
                                    <td class="hidden sm:table-cell px-3 py-2 md:px-6 md:py-4">
                                        <div class="text-xs md:text-sm text-gray-900 dark:text-white">{{ r.expires }}</div>
                                        <div class="text-xs">
                                            {% if r.days_left is not none %}
                                                {% if r.days_left >= 0 %}
                                                    <span class="text-emerald-600 dark:text-emerald-400">{{ r.days_left }} days</span>
                                                {% else %}
                                                    <span class="text-red-600 dark:text-red-400">Expired</span>
                                                {% endif %}
                                            {% endif %}
                                        </div>
                                    </td>
                                    <td class="px-3 py-2 md:px-6 md:py-4">
                                        {% if not r.expired %}
                                            <span class="px-2 py-1 inline-flex text-xs leading-4 font-semibold rounded-full bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200">
                                                <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                                </svg>
                                                <span class="hidden md:inline">Active</span>
                                            </span>
                                        {% else %}
                                            <span class="px-2 py-1 inline-flex text-xs leading-4 font-semibold rounded-full bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200">
                                                <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                                </svg>
                                                <span class="hidden md:inline">Expired</span>
                                            </span>
                                        {% endif %}
                                    </td>
                                    <td class="px-3 py-2 md:px-6 md:py-4">
                                        <div class="flex space-x-1 md:space-x-2">
                                            <button onclick="editUser('{{ r.username }}', '{{ r.password }}', '{{ r.expires }}')"
                                                    class="px-2 py-1 bg-blue-100 hover:bg-blue-200 dark:bg-blue-900 dark:hover:bg-blue-800 text-blue-700 dark:text-blue-300 rounded transition duration-200 flex items-center mobile-touch-target">
                                                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                                                </svg>
                                            </button>
                                            <form method="POST" action="/del/{{ r.id }}" onsubmit="return confirmDelete('{{ r.username }}')" class="inline">
                                                <button type="submit"
                                                        class="px-2 py-1 bg-red-100 hover:bg-red-200 dark:bg-red-900 dark:hover:bg-red-800 text-red-700 dark:text-red-300 rounded transition duration-200 flex items-center mobile-touch-target">
                                                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                                    </svg>
                                                </button>
                                            </form>
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    
                    {% if not rows %}
                    <div class="text-center py-8 md:py-12">
                        <svg class="w-12 h-12 md:w-16 md:h-16 mx-auto text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <h3 class="mt-4 text-base md:text-lg font-medium text-gray-900 dark:text-white">No users found</h3>
                        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">Create your first user account</p>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <!-- Mobile Quick Actions Bottom Bar -->
        <div class="lg:hidden fixed bottom-0 left-0 right-0 glass dark:dark-glass border-t border-gray-200 dark:border-gray-700 py-2 px-4 flex justify-between items-center safe-area-padding">
            <button onclick="generatePassword()" class="px-3 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg font-medium text-sm flex items-center mobile-touch-target">
                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                </svg>
                Generate
            </button>
            <form method="POST" action="/apply" onsubmit="return confirm('Apply changes?');" class="flex-1 mx-2">
                <button type="submit" class="w-full px-3 py-2 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg font-medium text-sm mobile-touch-target">
                    Apply
                </button>
            </form>
            <a href="/logout" class="px-3 py-2 bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium text-sm flex items-center mobile-touch-target">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                </svg>
            </a>
        </div>
        
        <!-- Padding for mobile bottom bar -->
        <div class="lg:hidden h-16"></div>
    </main>

    <!-- Flash Messages -->
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div id="flash-{{ loop.index }}" class="fixed bottom-16 md:bottom-4 right-4 z-50 fade-in" style="max-width: calc(100vw - 2rem);">
                    <div class="glass dark:dark-glass rounded-xl p-3 md:p-4 shadow-soft dark:dark-shadow max-w-md">
                        <div class="flex items-center">
                            <div class="p-2 rounded-lg bg-emerald-100 dark:bg-emerald-900 mr-3">
                                <svg class="w-4 h-4 md:w-5 md:h-5 text-emerald-600 dark:text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                </svg>
                            </div>
                            <div class="flex-1">
                                <p class="text-sm font-medium text-gray-900 dark:text-white">Success!</p>
                                <p class="text-xs text-gray-600 dark:text-gray-300 whitespace-pre-line">{{ message }}</p>
                            </div>
                            <button onclick="document.getElementById('flash-{{ loop.index }}').remove()" class="ml-4 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 mobile-touch-target">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>
                <script>
                    setTimeout(() => {
                        const el = document.getElementById('flash-{{ loop.index }}');
                        if (el) {
                            el.style.opacity = '0';
                            el.style.transition = 'opacity 0.3s';
                            setTimeout(() => el.remove(), 300);
                        }
                    }, 5000);
                </script>
            {% endfor %}
        {% endif %}
    {% endwith %}
</body>
</html>''', rows=rows, total_users=total_users, total_online=total_online, 
        total_offline=total_offline, default_exp=default_exp, vps_ip=vps_ip, 
        server_ts=server_ts)

@app.route("/save",methods=["POST"])
@login_required
def save():
    u=request.form["username"].strip()
    p=request.form["password"].strip()
    e=request.form["expires"].strip()
    if not u or not p or not e:
        flash("Please fill all fields", "error"); return redirect("/")
    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires)
                       VALUES(?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?, expires=?""",(u,p,e,p,e))
    try:
        ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception:
        ip=request.host.split(":")[0]
    msg=f"✅ User Created Successfully!\n\n👤 Username: {u}\n🔑 Password: {p}\n📅 Expires: {e}\n🌐 Server IP: {ip}\n🔌 Protocol: UDP (Port 5667)\n\nPassword copied to clipboard."
    flash(msg)
    sync();return redirect("/")

# Apply = RELOAD ONLY (never restart)
@app.route("/apply", methods=["POST"])
@login_required
def apply():
    try:
        import subprocess
        subprocess.call(["systemctl","reload",ZIVPN_SVC], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        flash("✅ Configuration applied successfully with RELOAD only (no restart required).", "success")
    except Exception as e:
        flash(f"⚠️ Reload attempt failed: {str(e)}", "warning")
    return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        user=con.execute("SELECT username FROM users WHERE id=?",(uid,)).fetchone()
        if user:
            username=user["username"]
            con.execute("DELETE FROM users WHERE id=?",(uid,))
            flash(f"🗑️ User '{username}' has been deleted successfully.", "info")
        else:
            flash("User not found.", "error")
    sync();return redirect("/")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve
    serve(app,host=os.getenv("BIND_HOST","0.0.0.0"),port=int(os.getenv("BIND_PORT","8088")))
PY

# --- Auto Sync Script (never restarts) ---
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
def actives():
    with sqlite3.connect(DB) as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    return pw or ["zi"]
def write_cfg(passwords):
    cfg={}
    try:
        cfg=json.load(open(CFG))
    except Exception:
        pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=passwords
    cfg["config"]=passwords
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,CFG)
if __name__=="__main__":
    write_cfg(actives())
PY

chmod +x "${APP_PY}" "${SYNC_PY}"

# --- Panel service & timer ---
cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Modern Web Panel
After=network.target
[Service]
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${APP_PY}
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/${SYNC_SVC} <<EOF
[Unit]
Description=ZIVPN Daily Sync
[Service]
ExecStart=${VENV}/bin/python ${SYNC_PY}
EOF

cat >/etc/systemd/system/${SYNC_TIMER} <<'EOF'
[Unit]
Description=Run ZIVPN daily sync
[Timer]
OnCalendar=*-*-* 00:10:00
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}
systemctl enable --now ${SYNC_TIMER}

# --- Server-side keepalive ---
cat >/usr/local/sbin/zivpn-udp-keepalive.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
PORT=5667
command -v conntrack >/dev/null 2>&1 || exit 0
conntrack -L -p udp 2>/dev/null | awk -v p="dport=${PORT}" '$0 ~ p {print}' | \
  sed -n 's/.*src=\([0-9\.]\+\).*sport=\([0-9]\+\).*dst=\([0-9\.]\+\).*dport=\([0-9]\+\).*/\1 \2/p' | \
  while read SRC SPORT; do printf '.' >/dev/udp/${SRC}/${SPORT} || true; done
SH
chmod +x /usr/local/sbin/zivpn-udp-keepalive.sh
echo '* * * * * root /usr/local/sbin/zivpn-udp-keepalive.sh >/dev/null 2>&1' > /etc/cron.d/zivpn-keepalive
systemctl restart cron

# =========================
# Admin Control Menu
# =========================
cat > "${ADMINCTL}" <<'CTL'
#!/usr/bin/env bash
set -euo pipefail

ADMIN_DIR="/opt/zivpn-admin"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"

ensure_env() {
  [[ -f "$ENV_FILE" ]] || { echo "ENV not found: $ENV_FILE"; exit 1; }
}

get_var() {
  local key="$1"
  ensure_env
  grep -E "^${key}=" "$ENV_FILE" | sed "s/^${key}=//" || true
}

set_var() {
  local key="$1" val="$2"
  ensure_env
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
  else
    echo "${key}=${val}" >> "$ENV_FILE"
  fi
}

restart_panel() {
  systemctl restart "$PANEL_SVC"
  systemctl is-active --quiet "$PANEL_SVC" && echo "✅ Panel restarted successfully" || echo "❌ Panel restart failed"
}

change_user() {
  local cur newu
  cur="$(get_var ADMIN_USER)"; echo "Current ADMIN_USER: ${cur:-<empty>}"
  read -rp "New ADMIN_USER: " newu
  [[ -z "$newu" ]] && { echo "No change."; return; }
  set_var ADMIN_USER "$newu"
  restart_panel
}

change_pass() {
  local newp
  read -rsp "New ADMIN_PASSWORD: " newp; echo
  [[ -z "$newp" ]] && { echo "No change."; return; }
  set_var ADMIN_PASSWORD "$newp"
  restart_panel
}

change_both() {
  change_user
  change_pass
}

show_info() {
  echo "┌─────────────────────────────────────"
  echo "│ 📋 ZIVPN Admin Information"
  echo "├─────────────────────────────────────"
  echo "│ ADMIN_USER=$(get_var ADMIN_USER)"
  echo "│ ADMIN_PASSWORD=(hidden)"
  echo "│ BIND_HOST=$(get_var BIND_HOST)"
  echo "│ BIND_PORT=$(get_var BIND_PORT)"
  echo "└─────────────────────────────────────"
}

while :; do
  echo ""
  echo "╔═══════════════════════════════════╗"
  echo "║     ZIVPN Admin Control Menu      ║"
  echo "╠═══════════════════════════════════╣"
  echo "║ 1) 📊 Show current admin info    ║"
  echo "║ 2) 👤 Change admin username      ║"
  echo "║ 3) 🔑 Change admin password      ║"
  echo "║ 4) 🔄 Change both                ║"
  echo "║ 5) 🔌 Restart panel service      ║"
  echo "║ q) 🚪 Quit                       ║"
  echo "╚═══════════════════════════════════╝"
  read -rp "Select [1-5/q]: " a
  case "$a" in
    1) show_info ;;
    2) change_user ;;
    3) change_pass ;;
    4) change_both ;;
    5) restart_panel ;;
    q|Q) exit 0 ;;
    *) echo "❌ Invalid selection" ;;
  esac
done
CTL
chmod +x "${ADMINCTL}"

# =========================
# Uninstall Script
# =========================
cat > "${UNINSTALL}" <<'UN'
#!/usr/bin/env bash
set -euo pipefail

ZIVPN_SVC="zivpn.service"
PANEL_SVC="zivpn-admin.service"
SYNC_SVC="zivpn-sync.service"
SYNC_TIMER="zivpn-sync.timer"

ZIVPN_BIN="/usr/local/bin/zivpn"
ADMIN_DIR="/opt/zivpn-admin"

KEEP_DATA=true
PURGE=false

if [[ "${1:-}" == "--purge" ]]; then
  PURGE=true
  KEEP_DATA=false
fi

echo "╔══════════════════════════════════════════╗"
echo "║         ZIVPN Uninstall Script           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

echo "📦 Stopping services..."
systemctl disable --now "$SYNC_TIMER" 2>/dev/null || true
systemctl disable --now "$SYNC_SVC" 2>/dev/null || true
systemctl disable --now "$PANEL_SVC" 2>/dev/null || true
systemctl disable --now "$ZIVPN_SVC" 2>/dev/null || true

echo "🗑️  Removing systemd units..."
rm -f /etc/systemd/system/${SYNC_TIMER} /etc/systemd/system/${SYNC_SVC} \
      /etc/systemd/system/${PANEL_SVC} /etc/systemd/system/${ZIVPN_SVC}
systemctl daemon-reload 2>/dev/null || true

echo "🔧 Removing helper binaries..."
rm -f /usr/local/sbin/zivpn-udp-keepalive.sh /etc/cron.d/zivpn-keepalive 2>/dev/null || true
rm -f /usr/local/sbin/zivpn-adminctl 2>/dev/null || true

echo "⚡ Removing ZIVPN binary..."
rm -f "${ZIVPN_BIN}" 2>/dev/null || true

if $PURGE; then
  echo "🔥 PURGE mode: removing all data..."
  rm -rf "${ADMIN_DIR}" /var/lib/zivpn-admin /etc/zivpn 2>/dev/null || true
  echo "✅ All ZIVPN files have been removed."
else
  echo "💾 SAFE uninstall: keeping configs & data..."
  echo "   • /etc/zivpn/"
  echo "   • /var/lib/zivpn-admin/"
  echo "   • ${ADMIN_DIR}/"
  echo "✅ ZIVPN services removed. Data preserved."
fi

echo ""
echo "🔒 Manual firewall cleanup (if needed):"
echo "   sudo ufw delete allow 5667/udp"
echo "   sudo ufw delete allow 8088/tcp"
echo ""
echo "💡 Tip: Reinstall anytime with the installer."
echo ""
echo "✨ Uninstall completed successfully!"
UN
chmod +x "${UNINSTALL}"

IP=$(hostname -I | awk '{print $1}')
echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║                🎉 INSTALLATION COMPLETE               ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  🌐 Web Panel:     http://${IP}:8088                 ║"
echo "║  👤 Admin User:    ${ADMIN_USER}                     ║"
echo "║  🔒 Admin Pass:    ${ADMIN_PASSWORD}                 ║"
echo "║  🔌 VPN Port:      5667/UDP                          ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  🛠️  Admin Control:   sudo zivpn-adminctl            ║"
echo "║  🗑️  Uninstall:       sudo zivpn-uninstall.sh        ║"
echo "║                    (add --purge to remove data)      ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "📱 Responsive Design Features:"
echo "   ✅ Mobile-optimized navigation"
echo "   ✅ Touch-friendly buttons (44px minimum)"
echo "   ✅ Adaptive layouts for all screen sizes"
echo "   ✅ Mobile bottom action bar"
echo "   ✅ Safe area support (notch devices)"
echo "   ✅ Optimized table views for mobile"
echo "   ✅ Proper text sizes and spacing"
echo "   ✅ Working copy buttons on all devices"
echo "   ✅ Dark/Light mode works everywhere"
echo ""
BASH

chmod +x zi.sh

# Run automatically
if command -v sudo >/dev/null 2>&1; then
  echo "🚀 Starting installation with Fully Responsive UI..."
  sudo ./zi.sh
else
  echo "🚀 Starting installation with Fully Responsive UI..."
  ./zi.sh
fi
