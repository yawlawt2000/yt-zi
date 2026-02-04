#!/usr/bin/env bash
#
# Try `install_jueudp.sh --help` for usage.
#
# (c) 2023 Jue Htet
#

set -e

# Domain Name
DOMAIN="eg.jueudp.com"

# PROTOCOL
PROTOCOL="udp"

# UDP PORT
UDP_PORT=":36712"

# OBFS
OBFS="jaideevpn"

# PASSWORDS
PASSWORD="jaideevpn"

# Web Admin Settings
ADMIN_PORT="8080"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD=$(openssl rand -base64 12)
ADMIN_IP="0.0.0.0"

# Script paths
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
USER_DB="$CONFIG_DIR/udpusers.db"
WEB_DIR="/var/www/hysteria-admin"
REPO_URL="https://github.com/apernet/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
API_BASE_URL="https://api.github.com/repos/apernet/hysteria"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)
PACKAGE_MANAGEMENT_INSTALL="${PACKAGE_MANAGEMENT_INSTALL:-}"
SYSTEMD_SERVICE="$SYSTEMD_SERVICES_DIR/hysteria-server.service"
mkdir -p "$CONFIG_DIR"
touch "$USER_DB"

# Web Admin Files
WEB_INDEX_FILE="$WEB_DIR/index.php"
WEB_CONFIG_FILE="$WEB_DIR/config.php"

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

# Utility functions (existing functions remain the same until new ones are added)
# ... [existing utility functions remain unchanged] ...

# New function to install web dependencies
install_web_dependencies() {
    echo "Installing web server and PHP dependencies..."
    
    if has_command apt-get; then
        apt-get update
        apt-get install -y nginx php-fpm php-sqlite3 php-mbstring php-curl php-json php-xml
        apt-get install -y sqlite3
    elif has_command yum; then
        yum install -y nginx php-fpm php-sqlite3 php-mbstring php-curl php-json php-xml
        yum install -y sqlite3
    elif has_command dnf; then
        dnf install -y nginx php-fpm php-sqlite3 php-mbstring php-curl php-json php-xml
        dnf install -y sqlite3
    fi
}

# New function to setup web admin panel
setup_web_admin() {
    echo "Setting up Web Admin Panel..."
    
    # Create web directory
    mkdir -p "$WEB_DIR"
    
    # Create config file
    cat << EOF > "$WEB_CONFIG_FILE"
<?php
// Database configuration
define('DB_PATH', '/etc/hysteria/udpusers.db');
define('ADMIN_USERNAME', '$ADMIN_USERNAME');
define('ADMIN_PASSWORD', '$ADMIN_PASSWORD');
define('HYSTERIA_CONFIG', '/etc/hysteria/config.json');
define('HYSTERIA_SERVICE', 'hysteria-server.service');

// Session timeout (in seconds)
define('SESSION_TIMEOUT', 3600);

// Start session
session_start();

// Auto-logout after timeout
if (isset(\$_SESSION['LAST_ACTIVITY']) && (time() - \$_SESSION['LAST_ACTIVITY'] > SESSION_TIMEOUT)) {
    session_unset();
    session_destroy();
}
\$_SESSION['LAST_ACTIVITY'] = time();

// Function to check login
function is_logged_in() {
    return isset(\$_SESSION['loggedin']) && \$_SESSION['loggedin'] === true;
}

// Function to login
function login(\$username, \$password) {
    if (\$username === ADMIN_USERNAME && \$password === ADMIN_PASSWORD) {
        \$_SESSION['loggedin'] = true;
        \$_SESSION['username'] = \$username;
        return true;
    }
    return false;
}

// Function to logout
function logout() {
    session_unset();
    session_destroy();
}

// Function to get users from database
function get_users() {
    if (!file_exists(DB_PATH)) return [];
    
    \$db = new SQLite3(DB_PATH);
    \$result = \$db->query('SELECT username, password FROM users ORDER BY username');
    \$users = [];
    
    while (\$row = \$result->fetchArray(SQLITE3_ASSOC)) {
        \$users[] = \$row;
    }
    
    \$db->close();
    return \$users;
}

// Function to add user
function add_user(\$username, \$password) {
    if (!file_exists(DB_PATH)) return false;
    
    \$db = new SQLite3(DB_PATH);
    \$stmt = \$db->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
    \$stmt->bindValue(':username', \$username, SQLITE3_TEXT);
    \$stmt->bindValue(':password', \$password, SQLITE3_TEXT);
    
    \$result = \$stmt->execute();
    \$success = \$result !== false;
    
    \$db->close();
    return \$success;
}

// Function to delete user
function delete_user(\$username) {
    if (!file_exists(DB_PATH)) return false;
    
    \$db = new SQLite3(DB_PATH);
    \$stmt = \$db->prepare('DELETE FROM users WHERE username = :username');
    \$stmt->bindValue(':username', \$username, SQLITE3_TEXT);
    
    \$result = \$stmt->execute();
    \$success = \$result !== false;
    
    \$db->close();
    return \$success;
}

// Function to update user password
function update_user_password(\$username, \$new_password) {
    if (!file_exists(DB_PATH)) return false;
    
    \$db = new SQLite3(DB_PATH);
    \$stmt = \$db->prepare('UPDATE users SET password = :password WHERE username = :username');
    \$stmt->bindValue(':username', \$username, SQLITE3_TEXT);
    \$stmt->bindValue(':password', \$new_password, SQLITE3_TEXT);
    
    \$result = \$stmt->execute();
    \$success = \$result !== false;
    
    \$db->close();
    return \$success;
}

// Function to update Hysteria config
function update_hysteria_config() {
    \$users = get_users();
    \$auth_config = [];
    
    foreach (\$users as \$user) {
        \$auth_config[] = \$user['username'] . ':' . \$user['password'];
    }
    
    if (file_exists(HYSTERIA_CONFIG)) {
        \$config = json_decode(file_get_contents(HYSTERIA_CONFIG), true);
        
        if (\$config && isset(\$config['auth']) && isset(\$config['auth']['config'])) {
            \$config['auth']['config'] = \$auth_config;
            
            file_put_contents(HYSTERIA_CONFIG, json_encode(\$config, JSON_PRETTY_PRINT));
            return true;
        }
    }
    
    return false;
}

// Function to restart Hysteria service
function restart_hysteria_service() {
    exec('systemctl restart ' . HYSTERIA_SERVICE . ' 2>&1', \$output, \$return_var);
    return \$return_var === 0;
}

// Function to get service status
function get_service_status() {
    exec('systemctl is-active ' . HYSTERIA_SERVICE . ' 2>&1', \$output, \$return_var);
    return [
        'status' => \$output[0] ?? 'unknown',
        'running' => \$output[0] === 'active'
    ];
}

// Function to get server info
function get_server_info() {
    \$info = [];
    
    // Get system info
    \$info['hostname'] = gethostname();
    \$info['php_version'] = phpversion();
    \$info['server_time'] = date('Y-m-d H:i:s');
    
    // Get Hysteria info
    if (file_exists(HYSTERIA_CONFIG)) {
        \$config = json_decode(file_get_contents(HYSTERIA_CONFIG), true);
        if (\$config) {
            \$info['domain'] = \$config['server'] ?? 'N/A';
            \$info['port'] = \$config['listen'] ?? 'N/A';
            \$info['protocol'] = \$config['protocol'] ?? 'N/A';
        }
    }
    
    // Get user count
    \$users = get_users();
    \$info['user_count'] = count(\$users);
    
    return \$info;
}
?>
EOF

    # Create index file
    cat << 'EOF' > "$WEB_INDEX_FILE"
<?php
require_once 'config.php';

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'login') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        if (login($username, $password)) {
            header('Location: index.php');
            exit;
        } else {
            $error = 'Invalid username or password';
        }
    } elseif ($_POST['action'] === 'logout') {
        logout();
        header('Location: index.php');
        exit;
    } elseif ($_POST['action'] === 'add_user' && is_logged_in()) {
        $username = $_POST['new_username'] ?? '';
        $password = $_POST['new_password'] ?? '';
        
        if ($username && $password) {
            if (add_user($username, $password)) {
                update_hysteria_config();
                restart_hysteria_service();
                $success = 'User added successfully';
            } else {
                $error = 'Failed to add user';
            }
        }
    } elseif ($_POST['action'] === 'delete_user' && is_logged_in()) {
        $username = $_POST['username'] ?? '';
        
        if ($username) {
            if (delete_user($username)) {
                update_hysteria_config();
                restart_hysteria_service();
                $success = 'User deleted successfully';
            } else {
                $error = 'Failed to delete user';
            }
        }
    } elseif ($_POST['action'] === 'update_password' && is_logged_in()) {
        $username = $_POST['username'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        
        if ($username && $new_password) {
            if (update_user_password($username, $new_password)) {
                update_hysteria_config();
                restart_hysteria_service();
                $success = 'Password updated successfully';
            } else {
                $error = 'Failed to update password';
            }
        }
    } elseif ($_POST['action'] === 'restart_service' && is_logged_in()) {
        if (restart_hysteria_service()) {
            $success = 'Service restarted successfully';
        } else {
            $error = 'Failed to restart service';
        }
    }
}

// Check if user is logged in
$logged_in = is_logged_in();

// Get data for display
$users = $logged_in ? get_users() : [];
$server_info = get_server_info();
$service_status = get_service_status();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JUE-UDP Admin Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .header h1 i {
            color: #667eea;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .card h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card h2 i {
            color: #667eea;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .info-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .info-item label {
            font-weight: 600;
            color: #666;
            display: block;
            margin-bottom: 5px;
            font-size: 0.9em;
        }
        
        .info-item span {
            color: #333;
            font-size: 1.1em;
        }
        
        .status-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
        }
        
        .status-active {
            background: #d4edda;
            color: #155724;
        }
        
        .status-inactive {
            background: #f8d7da;
            color: #721c24;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #dee2e6;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
            color: #666;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5a6fd8;
            transform: translateY(-2px);
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-success:hover {
            background: #218838;
            transform: translateY(-2px);
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c82333;
            transform: translateY(-2px);
        }
        
        .btn-warning {
            background: #ffc107;
            color: #333;
        }
        
        .btn-warning:hover {
            background: #e0a800;
            transform: translateY(-2px);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        .form-control {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .login-container {
            max-width: 400px;
            margin: 100px auto;
        }
        
        .login-form {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }
        
        .login-form h2 {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
        }
        
        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid transparent;
        }
        
        .alert-success {
            background-color: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
        
        .action-buttons {
            display: flex;
            gap: 10px;
            justify-content: flex-start;
        }
        
        .action-buttons form {
            margin: 0;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            color: white;
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        @media (max-width: 768px) {
            .info-grid {
                grid-template-columns: 1fr;
            }
            
            .action-buttons {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
                justify-content: center;
            }
        }
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <?php if (!$logged_in): ?>
            <div class="login-container">
                <div class="login-form">
                    <h2><i class="fas fa-lock"></i> JUE-UDP Admin Login</h2>
                    
                    <?php if (isset($error)): ?>
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
                        </div>
                    <?php endif; ?>
                    
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="login">
                        
                        <div class="form-group">
                            <label for="username"><i class="fas fa-user"></i> Username</label>
                            <input type="text" id="username" name="username" class="form-control" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="password"><i class="fas fa-key"></i> Password</label>
                            <input type="password" id="password" name="password" class="form-control" required>
                        </div>
                        
                        <button type="submit" class="btn btn-primary" style="width: 100%;">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </button>
                    </form>
                </div>
                <div class="footer">
                    <p>JUE-UDP Admin Panel &copy; <?php echo date('Y'); ?></p>
                </div>
            </div>
        <?php else: ?>
            <!-- Header -->
            <div class="header">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h1><i class="fas fa-shield-alt"></i> JUE-UDP Admin Panel</h1>
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="logout">
                        <button type="submit" class="btn btn-danger">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </button>
                    </form>
                </div>
            </div>
            
            <!-- Server Status Card -->
            <div class="card">
                <h2><i class="fas fa-server"></i> Server Status</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <label>Service Status</label>
                        <span class="status-badge <?php echo $service_status['running'] ? 'status-active' : 'status-inactive'; ?>">
                            <i class="fas fa-circle"></i> <?php echo $service_status['status']; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <label>Hostname</label>
                        <span><?php echo htmlspecialchars($server_info['hostname']); ?></span>
                    </div>
                    <div class="info-item">
                        <label>Domain</label>
                        <span><?php echo htmlspecialchars($server_info['domain']); ?></span>
                    </div>
                    <div class="info-item">
                        <label>Port</label>
                        <span><?php echo htmlspecialchars($server_info['port']); ?></span>
                    </div>
                    <div class="info-item">
                        <label>Total Users</label>
                        <span><?php echo $server_info['user_count']; ?> users</span>
                    </div>
                    <div class="info-item">
                        <label>Server Time</label>
                        <span><?php echo $server_info['server_time']; ?></span>
                    </div>
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 20px;">
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="restart_service">
                        <button type="submit" class="btn btn-warning">
                            <i class="fas fa-redo"></i> Restart Service
                        </button>
                    </form>
                </div>
            </div>
            
            <!-- Add User Card -->
            <div class="card">
                <h2><i class="fas fa-user-plus"></i> Add New User</h2>
                
                <?php if (isset($success)): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($error)): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>
                
                <form method="POST" action="">
                    <input type="hidden" name="action" value="add_user">
                    
                    <div class="info-grid">
                        <div class="form-group">
                            <label for="new_username"><i class="fas fa-user"></i> Username</label>
                            <input type="text" id="new_username" name="new_username" class="form-control" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="new_password"><i class="fas fa-key"></i> Password</label>
                            <input type="text" id="new_password" name="new_password" class="form-control" required>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-success">
                        <i class="fas fa-plus-circle"></i> Add User
                    </button>
                </form>
            </div>
            
            <!-- User Management Card -->
            <div class="card">
                <h2><i class="fas fa-users"></i> User Management</h2>
                
                <?php if (empty($users)): ?>
                    <p>No users found.</p>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Password</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($users as $user): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                                    <td>
                                        <code><?php echo htmlspecialchars($user['password']); ?></code>
                                    </td>
                                    <td>
                                        <div class="action-buttons">
                                            <!-- Update Password Form -->
                                            <form method="POST" action="" style="margin: 0;">
                                                <input type="hidden" name="action" value="update_password">
                                                <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                                                <input type="text" name="new_password" placeholder="New Password" style="padding: 5px; margin-right: 5px;" required>
                                                <button type="submit" class="btn btn-primary" style="padding: 5px 10px;">
                                                    <i class="fas fa-key"></i> Update
                                                </button>
                                            </form>
                                            
                                            <!-- Delete Form -->
                                            <form method="POST" action="" onsubmit="return confirm('Are you sure you want to delete this user?');" style="margin: 0;">
                                                <input type="hidden" name="action" value="delete_user">
                                                <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                                                <button type="submit" class="btn btn-danger" style="padding: 5px 10px;">
                                                    <i class="fas fa-trash"></i> Delete
                                                </button>
                                            </form>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
            
            <!-- Configuration Info -->
            <div class="card">
                <h2><i class="fas fa-info-circle"></i> Configuration Information</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <label>Admin Username</label>
                        <span><?php echo ADMIN_USERNAME; ?></span>
                    </div>
                    <div class="info-item">
                        <label>Admin Password</label>
                        <span><code><?php echo ADMIN_PASSWORD; ?></code></span>
                    </div>
                    <div class="info-item">
                        <label>Web Panel URL</label>
                        <span>http://<?php echo $server_info['hostname']; ?>:<?php echo $GLOBALS['ADMIN_PORT']; ?></span>
                    </div>
                    <div class="info-item">
                        <label>Database File</label>
                        <span><?php echo DB_PATH; ?></span>
                    </div>
                </div>
                
                <div style="margin-top: 20px;">
                    <p><strong>Note:</strong> Changes to users will automatically update the Hysteria configuration and restart the service.</p>
                </div>
            </div>
            
            <div class="footer">
                <p>JUE-UDP Admin Panel v1.0 &copy; <?php echo date('Y'); ?> | PHP <?php echo $server_info['php_version']; ?></p>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        // Auto-hide alerts after 5 seconds
        setTimeout(function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                alert.style.transition = 'opacity 0.5s';
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 500);
            });
        }, 5000);
        
        // Copy password to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Copied to clipboard!');
            });
        }
    </script>
</body>
</html>
EOF

    # Set proper permissions
    chmod 755 "$WEB_DIR"
    chmod 644 "$WEB_INDEX_FILE"
    chmod 600 "$WEB_CONFIG_FILE"
    
    # Create nginx configuration
    cat << EOF > /etc/nginx/sites-available/hysteria-admin
server {
    listen $ADMIN_PORT;
    listen [::]:$ADMIN_PORT;
    
    server_name _;
    
    root $WEB_DIR;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
EOF

    # Enable nginx site
    ln -sf /etc/nginx/sites-available/hysteria-admin /etc/nginx/sites-enabled/
    
    # Create admin credentials file
    cat << EOF > "$CONFIG_DIR/admin_credentials.txt"
===========================================
JUE-UDP Web Admin Panel Credentials
===========================================

Admin Username: $ADMIN_USERNAME
Admin Password: $ADMIN_PASSWORD

Web Panel URL: http://$(hostname -I | awk '{print $1}'):$ADMIN_PORT
              or
              http://$(hostname):$ADMIN_PORT

Important Notes:
1. Keep these credentials secure
2. Access the web panel from your browser
3. Default admin password will be shown only once

Server Information:
- Domain: $DOMAIN
- Port: $UDP_PORT
- Protocol: $PROTOCOL

Generated on: $(date)
===========================================
EOF

    # Set proper permissions for credentials file
    chmod 600 "$CONFIG_DIR/admin_credentials.txt"
    
    # Restart nginx
    systemctl restart nginx php-fpm
}

# New function to setup web admin systemd service
setup_web_admin_service() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    
    cat << EOF > "$SYSTEMD_SERVICES_DIR/hysteria-web.service"
[Unit]
Description=Hysteria Web Admin Panel
After=network.target nginx.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$WEB_DIR
ExecStart=/bin/echo "Web panel available at http://$ADMIN_IP:$ADMIN_PORT"
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable hysteria-web.service
}

# Modify the perform_install function to include web admin setup
perform_install() {
    local _is_fresh_install
    if ! is_hysteria_installed; then
        _is_fresh_install=1
    fi

    perform_install_hysteria_binary
    perform_install_hysteria_example_config
    perform_install_hysteria_home_legacy
    perform_install_hysteria_systemd
    install_web_dependencies
    setup_ssl
    start_services
    setup_web_admin
    setup_web_admin_service
    perform_install_manager_script

    if [[ -n "$_is_fresh_install" ]]; then
        echo
        echo -e "$(tbold)Congratulations! JUE-UDP has been successfully installed on your server.$(treset)"
        echo
        echo -e "$(tbold)Web Admin Panel Installed!$(treset)"
        echo -e "Admin URL: $(tblue)http://$(hostname -I | awk '{print $1}'):$ADMIN_PORT$(treset)"
        echo -e "Username: $(tyellow)$ADMIN_USERNAME$(treset)"
        echo -e "Password: $(tyellow)$ADMIN_PASSWORD$(treset)"
        echo
        echo -e "Credentials saved to: $(tblue)$CONFIG_DIR/admin_credentials.txt$(treset)"
        echo
        echo -e "Use 'jueudp' command to access the CLI manager."
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
        echo
        echo -e "$(tbold)JUE-UDP has been successfully updated to $VERSION.$(treset)"
        echo
    fi
}

# ... [rest of the existing script remains unchanged] ...

# In the main function, make sure web dependencies are checked
check_environment_php() {
    if ! has_command php; then
        install_software "php"
    fi
}

check_environment_nginx() {
    if ! has_command nginx; then
        install_software "nginx"
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
    check_environment_php
    check_environment_nginx
}

# ... [rest of the script remains unchanged] ...
