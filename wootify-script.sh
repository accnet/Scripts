#!/bin/bash

# ==============================================================================
# WordPress Management Script for RHEL Stack (AlmaLinux)
#
# Version: 4.7-RHEL + LE auto-renew
#
# Main features:
# - Install LEMP, create/delete/clone/list sites, install SSL, restart services.
# - Use EPEL & Remi repositories, automatic firewalld management.
# - Automated MariaDB security configuration, create and save root password.
# - Automatic SELinux context handling for webroot and socket.
# - Create separate FPM Pool and system user for each site to enhance security.
# - Auto-renew Let's Encrypt certificates (systemd timer if available, else cron).
# ==============================================================================

# --- SAFE SETTINGS ---
set -e
set -u
set -o pipefail

# --- GLOBAL VARIABLES AND CONSTANTS ---
readonly DEFAULT_PHP_VERSION="8.3"
readonly LEMP_INSTALLED_FLAG="/var/local/lemp_installed_rhel.flag"
readonly WP_CLI_PATH="/usr/local/bin/wp"

# Colors for interface
readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[0;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'

# --- UTILITY FUNCTIONS ---
info() {
    echo -e "${C_CYAN}INFO:${C_RESET} $1"
}
warn() {
    echo -e "${C_YELLOW}WARN:${C_RESET} $1"
}
menu_error() {
    echo -e "${C_RED}ERROR:${C_RESET} $1"
}
fatal_error() {
    echo -e "${C_RED}FATAL ERROR:${C_RESET} $1"
    exit 1
}
success() {
    echo -e "${C_GREEN}SUCCESS:${C_RESET} $1"
}

sanitize_username() {
    local raw="$1"
    echo "$raw" | tr 'A-Z' 'a-z' | tr '.@' '_' | tr -cd 'a-z0-9_-' | cut -c 1-32
}

normalize_domain() {
    local raw="$1"
    echo "$raw" | tr 'A-Z' 'a-z' | sed 's/[[:space:]]//g'
}

is_valid_domain() {
    local domain="$1"
    [[ "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]
}

is_valid_email() {
    local email="$1"
    [[ "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

require_valid_domain() {
    local domain="$1"
    if ! is_valid_domain "$domain"; then
        fatal_error "Invalid domain '$domain'. Use a real domain like example.com, without protocol, path, spaces, or special characters."
    fi
}

require_valid_email() {
    local email="$1"
    if ! is_valid_email "$email"; then
        fatal_error "Invalid email '$email'."
    fi
}

generate_sql_password() {
    openssl rand -hex 24
}

get_site_user_from_webroot() {
    local webroot="$1"
    if [ ! -d "$webroot" ]; then
        fatal_error "Webroot $webroot does not exist."
    fi
    stat -c '%U' "$webroot"
}

sed_escape_pattern() {
    printf '%s' "$1" | sed 's/[][\/.^$*+?{}()|]/\\&/g'
}

sed_escape_replacement() {
    printf '%s' "$1" | sed 's/[\/&]/\\&/g'
}

selinux_regex_escape_path() {
    sed_escape_pattern "$1"
}

ensure_wp_cli() {
    if [ -x "$WP_CLI_PATH" ]; then
        return 0
    fi

    if command -v wp &>/dev/null; then
        sudo install -m 755 "$(command -v wp)" "$WP_CLI_PATH"
        return 0
    fi

    info "WP-CLI not installed, installing now..."
    local tmp_wp_cli="/tmp/wp-cli.phar"
    curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o "$tmp_wp_cli"
    chmod +x "$tmp_wp_cli"
    sudo mv "$tmp_wp_cli" "$WP_CLI_PATH"
}

is_selinux_enabled() {
    if ! command -v getenforce &>/dev/null; then
        return 1
    fi

    [ "$(getenforce 2>/dev/null)" != "Disabled" ]
}

allow_httpd_network_connect() {
    info ">> SELinux: Allowing web server to make network connections..."

    if ! is_selinux_enabled; then
        warn "SELinux is disabled or unavailable. Skipping SELinux boolean configuration."
        return 0
    fi

    if ! command -v getsebool &>/dev/null || ! getsebool -a 2>/dev/null | grep -q '^httpd_can_network_connect[[:space:]]'; then
        warn "SELinux boolean 'httpd_can_network_connect' is not available on this system. Skipping."
        return 0
    fi

    sudo setsebool -P httpd_can_network_connect on
}

set_webroot_selinux_context() {
    local webroot="$1"
    local mode="${2:-add}"
    local webroot_regex
    local wp_content_regex
    webroot_regex=$(selinux_regex_escape_path "$webroot")
    wp_content_regex=$(selinux_regex_escape_path "$webroot/wp-content")

    if ! is_selinux_enabled; then
        warn "SELinux is disabled or unavailable. Skipping SELinux context update for $webroot."
        return 0
    fi

    if ! command -v semanage &>/dev/null || ! command -v restorecon &>/dev/null; then
        warn "SELinux management tools are not available. Skipping SELinux context update for $webroot."
        return 0
    fi

    case "$mode" in
        add)
            sudo semanage fcontext -a -t httpd_sys_content_t "${webroot_regex}(/.*)?" || \
                sudo semanage fcontext -m -t httpd_sys_content_t "${webroot_regex}(/.*)?"
            sudo semanage fcontext -a -t httpd_sys_rw_content_t "${wp_content_regex}(/.*)?" || \
                sudo semanage fcontext -m -t httpd_sys_rw_content_t "${wp_content_regex}(/.*)?"
            sudo restorecon -R "$webroot"
            ;;
        delete)
            sudo semanage fcontext -d "${wp_content_regex}(/.*)?" || true
            sudo semanage fcontext -d "${webroot_regex}(/.*)?" || true
            ;;
        *)
            warn "Unknown SELinux context mode '$mode' for $webroot."
            ;;
    esac
}

set_php_fpm_socket_selinux_context() {
    local socket_path="$1"
    local mode="${2:-add}"
    local socket_regex
    socket_regex=$(selinux_regex_escape_path "$socket_path")

    if ! is_selinux_enabled; then
        warn "SELinux is disabled or unavailable. Skipping PHP-FPM socket context update for $socket_path."
        return 0
    fi

    if ! command -v semanage &>/dev/null || ! command -v restorecon &>/dev/null; then
        warn "SELinux management tools are not available. Skipping PHP-FPM socket context update for $socket_path."
        return 0
    fi

    case "$mode" in
        add)
            sudo semanage fcontext -a -t httpd_var_run_t "$socket_regex" || \
                sudo semanage fcontext -m -t httpd_var_run_t "$socket_regex"
            if [ -e "$socket_path" ]; then
                sudo restorecon "$socket_path"
            else
                sudo restorecon "$(dirname "$socket_path")" || true
            fi
            ;;
        delete)
            sudo semanage fcontext -d "$socket_regex" || true
            ;;
        *)
            warn "Unknown SELinux socket context mode '$mode' for $socket_path."
            ;;
    esac
}

configure_nftables_fallback() {
    if ! command -v nft &>/dev/null; then
        return 1
    fi

    info "Trying firewall fallback with nftables..."

    if ! sudo nft list table inet filter >/dev/null 2>&1; then
        sudo nft add table inet filter
    fi

    if ! sudo nft list chain inet filter input >/dev/null 2>&1; then
        sudo nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
    fi

    if ! sudo nft list chain inet filter input | grep -q 'tcp dport 80 accept'; then
        sudo nft add rule inet filter input tcp dport 80 accept
    fi

    if ! sudo nft list chain inet filter input | grep -q 'tcp dport 443 accept'; then
        sudo nft add rule inet filter input tcp dport 443 accept
    fi

    success "Opened HTTP/HTTPS ports with nftables."
    return 0
}

configure_iptables_fallback() {
    if ! command -v iptables &>/dev/null; then
        return 1
    fi

    info "Trying firewall fallback with iptables..."

    if ! sudo iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
        sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
    fi

    if ! sudo iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1; then
        sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
    fi

    success "Opened HTTP/HTTPS ports with iptables."
    warn "iptables rules were applied in runtime only. Save them manually if you need persistence after reboot."
    return 0
}

configure_firewall() {
    info "Checking and configuring firewall..."

    if ! command -v systemctl &>/dev/null; then
        warn "systemctl is not available on this system. Skipping firewalld and trying direct firewall fallback."
        configure_nftables_fallback || configure_iptables_fallback || warn "No supported firewall tool was configured automatically."
        return 0
    fi

    if ! command -v firewall-cmd &>/dev/null; then
        warn "firewalld not installed. Installing..."
        sudo dnf install -y firewalld
    fi

    if ! sudo systemctl enable firewalld >/dev/null 2>&1; then
        warn "Could not enable firewalld service automatically."
    fi

    if ! sudo systemctl is-active --quiet firewalld; then
        warn "firewalld is installed but not running. Attempting to start service..."
        if ! sudo systemctl start firewalld; then
            warn "Could not start firewalld. Trying fallback firewall configuration."
            configure_nftables_fallback || configure_iptables_fallback || warn "HTTP/HTTPS ports were not opened automatically."
            return 0
        fi
    fi

    if ! sudo firewall-cmd --state >/dev/null 2>&1; then
        warn "firewalld command is available but daemon is not ready. Trying fallback firewall configuration."
        configure_nftables_fallback || configure_iptables_fallback || warn "HTTP/HTTPS ports were not opened automatically."
        return 0
    fi

    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=https
    sudo firewall-cmd --reload
    success "firewalld is running and HTTP/HTTPS services were allowed."
}

# --- MAIN FUNCTIONS ---
create_swap_if_needed() {
    if sudo swapon --show | grep -q '/'; then
        info "Swap is already enabled on the system. Skipping."
        sudo swapon --show
        return
    fi

    warn "No swap found. Creating swap file."
    local total_ram_mb
    total_ram_mb=$(free -m | awk '/^Mem:/{print $2}')

    local swap_size_mb
    swap_size_mb=$((total_ram_mb * 2))

    info "Total RAM: ${total_ram_mb}MB. Creating swap file with size: ${swap_size_mb}MB."
    sudo fallocate -l "${swap_size_mb}M" /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile

    if ! grep -q "/swapfile" /etc/fstab; then
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    fi
    success "Swap file created and activated successfully."
    sudo free -h
}

install_lemp() {
    info "Starting LEMP stack installation on AlmaLinux..."
    create_swap_if_needed

    info "Updating system..."
    sudo dnf update -y

    if sudo dnf list installed httpd &>/dev/null; then
        warn "Detected httpd (Apache). Removing to avoid conflicts."
        sudo systemctl stop httpd || true && sudo systemctl disable httpd || true
        sudo dnf remove httpd* -y
        success "Successfully removed httpd."
    fi

    info "Installing EPEL and Remi repositories..."
    sudo dnf install -y epel-release
    sudo dnf install -y https://rpms.remirepo.net/enterprise/remi-release-$(rpm -E %rhel).rpm

    info "Enabling PHP ${DEFAULT_PHP_VERSION} module from Remi..."
    sudo dnf module reset php -y
    sudo dnf module enable "php:remi-${DEFAULT_PHP_VERSION}" -y

    info "Installing Nginx, MariaDB, PHP and necessary extensions..."
    sudo dnf install -y nginx mariadb-server php php-fpm php-mysqlnd php-curl \
        php-xml php-mbstring php-zip php-gd php-intl php-bcmath php-soap \
        php-exif php-opcache php-cli php-readline wget unzip \
        policycoreutils-python-utils openssl cronie

    info "Optimizing PHP configuration..."
    local php_ini_path="/etc/php.ini"
    if [ -f "$php_ini_path" ]; then
        sudo sed -i 's/^;*upload_max_filesize = .*/upload_max_filesize = 512M/' "$php_ini_path"
        sudo sed -i 's/^;*post_max_size = .*/post_max_size = 512M/' "$php_ini_path"
        sudo sed -i 's/^;*max_execution_time = .*/max_execution_time = 600/' "$php_ini_path"
        sudo sed -i 's/^;*max_input_time = .*/max_input_time = 600/' "$php_ini_path"
        sudo sed -i 's/^;*memory_limit = .*/memory_limit = 512M/' "$php_ini_path"
        sudo sed -i 's/^;*max_input_vars = .*/max_input_vars = 5000/' "$php_ini_path"
        sudo sed -i 's/^;*realpath_cache_size = .*/realpath_cache_size = 4096K/' "$php_ini_path"
        sudo sed -i 's/^;*realpath_cache_ttl = .*/realpath_cache_ttl = 600/' "$php_ini_path"
    fi

    local opcache_ini="/etc/php.d/10-opcache.ini"
    if [ -f "$opcache_ini" ]; then
        sudo sed -i 's/^;*opcache.enable=.*/opcache.enable=1/' "$opcache_ini"
        sudo sed -i 's/^;*opcache.memory_consumption=.*/opcache.memory_consumption=192/' "$opcache_ini"
        sudo sed -i 's/^;*opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=16/' "$opcache_ini"
        sudo sed -i 's/^;*opcache.max_accelerated_files=.*/opcache.max_accelerated_files=20000/' "$opcache_ini"
        sudo sed -i 's/^;*opcache.validate_timestamps=.*/opcache.validate_timestamps=1/' "$opcache_ini"
        sudo sed -i 's/^;*opcache.revalidate_freq=.*/opcache.revalidate_freq=60/' "$opcache_ini"
    fi

    info "Optimizing Nginx configuration..."
    local nginx_conf_path="/etc/nginx/nginx.conf"
    sudo sed -i 's/^\s*worker_connections\s*.*/    worker_connections 1024;/' "$nginx_conf_path"
    sudo sed -i 's/^\s*user\s*.*/user nginx;/' "$nginx_conf_path"

    if ! grep -q "client_max_body_size" "$nginx_conf_path"; then
        info "Increasing file upload limit for Nginx..."
        sudo sed -i '/http {/a \    client_max_body_size 512M;' "$nginx_conf_path"
    fi

    configure_firewall

    allow_httpd_network_connect

    info "Starting and enabling main services..."
    sudo systemctl enable --now nginx mariadb php-fpm crond

    info "Automatically configuring MariaDB security..."
    local mariadb_root_pass=""
    if sudo test -f /root/.my.cnf && sudo mysql -e "SELECT 1;" >/dev/null 2>&1; then
        warn "MariaDB root credentials already work from /root/.my.cnf. Keeping existing root password."
    else
        mariadb_root_pass=$(generate_sql_password)
        sudo mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$mariadb_root_pass'; FLUSH PRIVILEGES;"
        sudo tee /root/.my.cnf >/dev/null <<EOL
[client]
user=root
password="$mariadb_root_pass"
EOL
        sudo chmod 600 /root/.my.cnf
    fi

    sudo mysql <<EOF
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    success "MariaDB has been automatically secured."
    if [ -n "$mariadb_root_pass" ]; then
        warn "MariaDB root password has been created and saved to /root/.my.cnf"
        echo -e "${C_YELLOW}🔑 Your MariaDB root password is:${C_RESET} ${mariadb_root_pass}"
        echo -e "${C_YELLOW}Please save this password in a safe place!${C_RESET}"
    fi

    sudo touch "$LEMP_INSTALLED_FLAG"
    success "LEMP stack installation completed!"
}

create_site() {
    info "Starting creation of new WordPress site..."
    read -p "Enter domain (example: mydomain.com): " domain
    domain=$(normalize_domain "$domain")
    if [ -z "$domain" ]; then
        fatal_error "Domain cannot be empty."
    fi
    require_valid_domain "$domain"

    local webroot="/var/www/$domain"
    if [ -e "$webroot" ]; then
        fatal_error "Webroot $webroot already exists."
    fi
    if [ -f "/etc/nginx/conf.d/$domain.conf" ] || [ -f "/etc/php-fpm.d/$domain.conf" ]; then
        fatal_error "Nginx or PHP-FPM configuration for $domain already exists."
    fi

    local site_user
    site_user=$(sanitize_username "$domain")
    if [ -z "$site_user" ]; then
        fatal_error "Could not derive a valid system username from domain '$domain'."
    fi

    if ! id -u "$site_user" >/dev/null 2>&1; then
        info "Creating system user '$site_user' for site..."
        sudo useradd -r -s /sbin/nologin -d "$webroot" -g nginx "$site_user"
    else
        warn "User '$site_user' already exists. Will use this user."
    fi

    local random_suffix
    random_suffix=$(openssl rand -hex 4)
    local safe_domain
    safe_domain=$(echo "${domain//./_}")

    local db_name
    db_name=$(echo "${safe_domain}" | cut -c -55)_${random_suffix}
    local db_user
    db_user=$(echo "${safe_domain}" | cut -c -23)_u${random_suffix}
    local db_pass
    db_pass=$(generate_sql_password)

    local admin_user=""
    local admin_email=""
    local admin_pass=""

    while [ -z "$admin_user" ]; do
        read -p "Enter WordPress admin username: " admin_user
        if [ -z "$admin_user" ]; then
            warn "Username cannot be empty. Please try again."
        fi
    done

    while [ -z "$admin_email" ]; do
        read -p "Enter WordPress admin email: " admin_email
        if [ -z "$admin_email" ]; then
            warn "Email cannot be empty. Please try again."
        elif ! is_valid_email "$admin_email"; then
            warn "Invalid email format. Please try again."
            admin_email=""
        fi
    done

    while [ -z "$admin_pass" ]; do
        read -s -p "Enter WordPress admin password: " admin_pass
        echo
        if [ -z "$admin_pass" ]; then
            warn "Password cannot be empty. Please try again."
        fi
    done

    info "Downloading and installing WordPress..."
    sudo mkdir -p "$webroot"
    rm -rf /tmp/wordpress /tmp/latest.tar.gz
    wget -q https://wordpress.org/latest.tar.gz -O /tmp/latest.tar.gz
    tar -xzf /tmp/latest.tar.gz -C /tmp && sudo cp -r /tmp/wordpress/* "$webroot" && sudo chown -R "$site_user":nginx "$webroot"

    info ">> SELinux: Setting context for webroot..."
    set_webroot_selinux_context "$webroot"

    info "Creating Database and User..."
    sudo mysql -e "CREATE DATABASE IF NOT EXISTS \`$db_name\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    sudo mysql -e "CREATE USER IF NOT EXISTS \`$db_user\`@'localhost' IDENTIFIED BY '$db_pass';"
    sudo mysql -e "GRANT ALL PRIVILEGES ON \`$db_name\`.* TO \`$db_user\`@'localhost';"
    sudo mysql -e "FLUSH PRIVILEGES;"

    info "Creating Nginx configuration file..."
    local nginx_conf="/etc/nginx/conf.d/$domain.conf"
    local fpm_sock="/var/run/php-fpm/${domain}.sock"
    sudo tee "$nginx_conf" >/dev/null <<EOL
server {
    listen 80;
    server_name $domain www.$domain;
    root $webroot;
    index index.php index.html;

    client_max_body_size 512M;

    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    location ^~ /.well-known/acme-challenge/ {
        allow all;
        root $webroot;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location = /xmlrpc.php {
        deny all;
    }

    location ~* /(wp-config.php|readme.html|license.txt|\.user.ini|composer\.(json|lock)|package(-lock)?\.json)$ {
        deny all;
    }

    location ~* /(?:uploads|files)/.*\.php\$ {
        deny all;
    }

    location ~* \.(?:css|js|jpg|jpeg|gif|png|webp|avif|svg|ico|woff2?|ttf|eot|otf|mp4|webm)$ {
        expires 30d;
        access_log off;
        log_not_found off;
        add_header Cache-Control "public, no-transform";
        try_files \$uri =404;
    }

    location ~ \.php\$ {
        try_files \$uri =404;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTPS \$https if_not_empty;
        fastcgi_param HTTP_PROXY "";
        fastcgi_pass unix:$fpm_sock;
        fastcgi_read_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_connect_timeout 60;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 256 16k;
        fastcgi_busy_buffers_size 256k;
        fastcgi_temp_file_write_size 256k;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }
}
EOL

    info "Creating dedicated FPM Pool for site..."
    local pool_conf="/etc/php-fpm.d/${domain}.conf"
    sudo tee "$pool_conf" >/dev/null <<EOL
[$domain]
user = $site_user
group = nginx
listen = $fpm_sock
listen.owner = nginx
listen.group = nginx
listen.mode = 0660
pm = dynamic
pm.max_children = 16
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 6
pm.max_requests = 500
php_admin_value[upload_max_filesize] = 512M
php_admin_value[post_max_size] = 512M
php_admin_value[memory_limit] = 512M
php_admin_value[max_execution_time] = 600
php_admin_value[max_input_time] = 600
EOL

    info ">> SELinux: Setting context for PHP-FPM socket..."
    set_php_fpm_socket_selinux_context "$fpm_sock"

    info "Checking configuration and reloading services..."
    if ! sudo nginx -t; then
        fatal_error "Nginx configuration for site $domain is invalid."
    fi
    sudo systemctl reload php-fpm
    set_php_fpm_socket_selinux_context "$fpm_sock"
    sudo systemctl reload nginx

    info "Installing WordPress with WP-CLI..."
    ensure_wp_cli

    sudo -u "$site_user" "$WP_CLI_PATH" core config --dbname="$db_name" --dbuser="$db_user" --dbpass="$db_pass" --path="$webroot" --skip-check
    sudo -u "$site_user" "$WP_CLI_PATH" core install --url="http://$domain" --title="Website $domain" --admin_user="$admin_user" --admin_password="$admin_pass" --admin_email="$admin_email" --path="$webroot"

    info "Installing and activating desired plugins..."
    sudo -u "$site_user" "$WP_CLI_PATH" plugin install contact-form-7 woocommerce classic-editor classic-widgets autoptimize wp-fastest-cache wp-mail-smtp redis-cache --activate --path="$webroot"
    
    info "Installing and activating Storefront theme as default..."
    sudo -u "$site_user" "$WP_CLI_PATH" theme install storefront --activate --path="$webroot"

    # ==============================================================================
    # >>> MODIFICATION START: Clean up default themes and plugins <<<
    # ==============================================================================
    info "Cleaning up default themes and plugins..."
    # Note: Using '|| true' to prevent script from failing if a theme/plugin doesn't exist
    sudo -u "$site_user" "$WP_CLI_PATH" theme delete twentytwentyfive twentytwentyfour twentytwentythree --path="$webroot" || true
    sudo -u "$site_user" "$WP_CLI_PATH" plugin delete akismet hello --path="$webroot" || true
    # ==============================================================================
    # >>> MODIFICATION END <<<
    # ==============================================================================

    info "Creating and setting permissions for WooCommerce log directory..."
    sudo -u "$site_user" mkdir -p "$webroot/wp-content/uploads/wc-logs"
    sudo find "$webroot/wp-content" -type d -exec chmod 775 {} +
    sudo find "$webroot/wp-content" -type f -exec chmod 664 {} +

    success "Site http://$domain created successfully!"
    echo -e "----------------------------------------"
    echo -e "📁 ${C_BLUE}Webroot:${C_RESET}       $webroot"
    echo -e "🛠️ ${C_BLUE}Database:${C_RESET}    $db_name"
    echo -e "👤 ${C_BLUE}DB User:${C_RESET}       $db_user"
    echo -e "🔑 ${C_BLUE}DB Password:${C_RESET} $db_pass"
    echo -e "👤 ${C_BLUE}WP Admin:${C_RESET}     $admin_user"
    echo -e "🔑 ${C_BLUE}WP Password:${C_RESET} $admin_pass"
    echo -e "----------------------------------------"

    read -p "🔐 Do you want to install Let's Encrypt SSL for this site? (y/N): " install_ssl_choice
    if [[ "${install_ssl_choice,,}" == "y" ]]; then
        if ! install_ssl "$domain" "$admin_email"; then
            warn "SSL installation failed. Your website was still created successfully at http://$domain."
            warn "You can try installing SSL later using option 4 in the main menu."
        fi
    fi
}

list_sites() {
    info "Retrieving list of sites..."
    local sites_path="/etc/nginx/conf.d"
    local sites
    sites=($(find "$sites_path" -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" | sed 's/\.conf$//'))

    if [ ${#sites[@]} -eq 0 ]; then
        warn "No sites found."
        return 1
    fi

    echo "📋 List of existing sites:"
    for i in "${!sites[@]}"; do
        echo "   $((i + 1)). ${sites[$i]}"
    done
    return 0
}

delete_site() {
    info "Starting WordPress site deletion process."
    list_sites || return

    local sites_path="/etc/nginx/conf.d"
    local sites
    sites=($(find "$sites_path" -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" | sed 's/\.conf$//'))
    echo "   0. 🔙 Back to main menu"

    read -p "Enter your choice: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt ${#sites[@]} ]; then
        menu_error "Invalid choice."
        return
    fi
    if [ "$choice" -eq 0 ]; then
        info "Deletion cancelled."
        return
    fi
    local domain="${sites[$((choice - 1))]}"
    require_valid_domain "$domain"

    warn "ARE YOU SURE YOU WANT TO COMPLETELY DELETE SITE '$domain'?"
    warn "This action is irreversible and will permanently delete the webroot, database, and user."
    read -p "Type the domain name '$domain' to confirm: " confirmation
    if [ "$confirmation" != "$domain" ]; then
        info "Confirmation mismatch. Deletion cancelled."
        return
    fi

    info "Starting deletion of site '$domain'..."
    local webroot="/var/www/$domain"
    local site_user
    site_user=$(get_site_user_from_webroot "$webroot")
    ensure_wp_cli
    local db_name
    db_name=$(sudo -u "$site_user" "$WP_CLI_PATH" config get DB_NAME --path="$webroot" --skip-plugins --skip-themes)
    local db_user
    db_user=$(sudo -u "$site_user" "$WP_CLI_PATH" config get DB_USER --path="$webroot" --skip-plugins --skip-themes)

    local backup_dir="/root/wp-backups/${domain}-$(date +%Y%m%d-%H%M%S)"
    info "Creating safety backup before deletion at $backup_dir..."
    sudo mkdir -p "$backup_dir"
    sudo mysqldump --single-transaction --quick "$db_name" | gzip | sudo tee "$backup_dir/database.sql.gz" >/dev/null
    sudo tar -C /var/www -czf "$backup_dir/files.tar.gz" "$domain"
    sudo chmod -R go-rwx "$backup_dir"

    info "Deleting Nginx, FPM, and Cron configuration files..."
    sudo rm -f "/etc/nginx/conf.d/${domain}.conf" "/etc/php-fpm.d/${domain}.conf" "/etc/cron.d/wp-cron-${domain}"

    if command -v certbot &>/dev/null; then
        info "Deleting Let's Encrypt certificate if it exists..."
        sudo certbot delete --cert-name "$domain" --non-interactive >/dev/null 2>&1 || true
    fi

    info "Reloading services..."
    sudo nginx -t && sudo systemctl reload nginx && sudo systemctl reload php-fpm

    info "Deleting database and user..."
    sudo mysql -e "DROP DATABASE IF EXISTS \`$db_name\`;"
    sudo mysql -e "DROP USER IF EXISTS \`$db_user\`@'localhost';"

    info "Ensuring all processes for user '$site_user' are stopped..."
    sudo pkill -u "$site_user" || true
    sleep 1

    info ">> SELinux: Removing webroot context..."
    set_webroot_selinux_context "$webroot" delete
    set_php_fpm_socket_selinux_context "/var/run/php-fpm/${domain}.sock" delete

    info "Deleting system user and webroot..."
    if id -u "$site_user" >/dev/null 2>&1; then
        sudo userdel -r "$site_user"
    fi

    if [ -d "$webroot" ]; then
        info "Deleting residual webroot directory..."
        sudo rm -rf "$webroot"
    fi

    success "Site '$domain' completely deleted."
}

clone_site() {
    info "Starting WordPress site cloning process."
    list_sites || return

    local sites_path="/etc/nginx/conf.d"
    local sites
    sites=($(find "$sites_path" -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" | sed 's/\.conf$//'))
    echo "   0. 🔙 Back to main menu"

    read -p "Enter source site choice: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt ${#sites[@]} ]; then
        menu_error "Invalid choice."
        return
    fi
    if [ "$choice" -eq 0 ]; then
        info "Cloning cancelled."
        return
    fi

    local src_domain="${sites[$((choice - 1))]}"
    require_valid_domain "$src_domain"
    read -p "Enter new domain for the clone: " new_domain
    new_domain=$(normalize_domain "$new_domain")
    if [ -z "$new_domain" ]; then
        fatal_error "New domain cannot be empty."
    fi
    require_valid_domain "$new_domain"
    if [ -d "/var/www/$new_domain" ]; then
        fatal_error "Directory /var/www/$new_domain already exists."
    fi
    if [ -f "/etc/nginx/conf.d/$new_domain.conf" ] || [ -f "/etc/php-fpm.d/$new_domain.conf" ]; then
        fatal_error "Nginx or PHP-FPM configuration for $new_domain already exists."
    fi

    info "Starting clone from '$src_domain' to '$new_domain'..."
    local src_webroot="/var/www/$src_domain"
    local new_webroot="/var/www/$new_domain"
    local src_site_user
    src_site_user=$(get_site_user_from_webroot "$src_webroot")
    local new_site_user
    new_site_user=$(sanitize_username "$new_domain")
    if [ -z "$new_site_user" ]; then
        fatal_error "Could not derive a valid system username from domain '$new_domain'."
    fi

    ensure_wp_cli

    local src_db_name
    src_db_name=$(sudo -u "$src_site_user" "$WP_CLI_PATH" config get DB_NAME --path="$src_webroot")

    local random_suffix
    random_suffix=$(openssl rand -hex 4)
    local new_safe_domain
    new_safe_domain=$(echo "${new_domain//./_}")
    local new_db_name
    new_db_name=$(echo "${new_safe_domain}" | cut -c -55)_${random_suffix}
    local new_db_user
    new_db_user=$(echo "${new_safe_domain}" | cut -c -23)_u${random_suffix}
    local new_db_pass
    new_db_pass=$(generate_sql_password)

    info "Copying files..."
    sudo cp -a "$src_webroot" "$new_webroot"

    info "Creating and setting permissions for new system user..."
    if ! id -u "$new_site_user" >/dev/null 2>&1; then
        sudo useradd -r -s /sbin/nologin -d "$new_webroot" -g nginx "$new_site_user"
    else
        warn "User '$new_site_user' already exists. Will use this user."
    fi
    sudo chown -R "$new_site_user":nginx "$new_webroot"

    info ">> SELinux: Assigning context for new webroot..."
    set_webroot_selinux_context "$new_webroot"

    info "Creating and copying database..."
    sudo mysql -e "CREATE DATABASE IF NOT EXISTS \`$new_db_name\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    sudo mysql -e "CREATE USER IF NOT EXISTS \`$new_db_user\`@'localhost' IDENTIFIED BY '$new_db_pass';"
    sudo mysql -e "GRANT ALL PRIVILEGES ON \`$new_db_name\`.* TO \`$new_db_user\`@'localhost';"
    sudo mysql -e "FLUSH PRIVILEGES;"
    sudo mysqldump --single-transaction --quick "$src_db_name" | sudo mysql "$new_db_name"

    info "Updating WordPress configuration (wp-config.php)..."
    sudo -u "$new_site_user" "$WP_CLI_PATH" config set DB_NAME "$new_db_name" --path="$new_webroot"
    sudo -u "$new_site_user" "$WP_CLI_PATH" config set DB_USER "$new_db_user" --path="$new_webroot"
    sudo -u "$new_site_user" "$WP_CLI_PATH" config set DB_PASSWORD "$new_db_pass" --path="$new_webroot"

    info "Replacing domain in database..."
    sudo -u "$new_site_user" "$WP_CLI_PATH" search-replace "$src_domain" "$new_domain" --all-tables --skip-columns=guid --precise --path="$new_webroot"
    sudo -u "$new_site_user" "$WP_CLI_PATH" option update home "http://$new_domain" --path="$new_webroot"
    sudo -u "$new_site_user" "$WP_CLI_PATH" option update siteurl "http://$new_domain" --path="$new_webroot"

    info "Creating Nginx configuration and FPM Pool for new site..."
    local new_nginx_conf="/etc/nginx/conf.d/$new_domain.conf"
    local new_fpm_sock="/var/run/php-fpm/${new_domain}.sock"
    sudo cp "/etc/nginx/conf.d/$src_domain.conf" "$new_nginx_conf"
    local src_domain_pattern
    local new_domain_replacement
    src_domain_pattern=$(sed_escape_pattern "$src_domain")
    new_domain_replacement=$(sed_escape_replacement "$new_domain")
    sudo sed -i "s/${src_domain_pattern}/${new_domain_replacement}/g" "$new_nginx_conf"
    sudo sed -i "s|/var/run/php-fpm/${src_domain_pattern}\.sock|${new_fpm_sock}|" "$new_nginx_conf"

    local new_pool_conf="/etc/php-fpm.d/${new_domain}.conf"
    sudo cp "/etc/php-fpm.d/$src_domain.conf" "$new_pool_conf"
    sudo sed -i "s/\[${src_domain_pattern}\]/\[${new_domain_replacement}\]/" "$new_pool_conf"
    sudo sed -i "s/user = $src_site_user/user = $new_site_user/" "$new_pool_conf"
    sudo sed -i "s|listen = /var/run/php-fpm/${src_domain_pattern}\.sock|listen = ${new_fpm_sock}|" "$new_pool_conf"

    info ">> SELinux: Setting context for new PHP-FPM socket..."
    set_php_fpm_socket_selinux_context "$new_fpm_sock"

    info "Reloading services..."
    sudo nginx -t
    sudo systemctl reload php-fpm
    set_php_fpm_socket_selinux_context "$new_fpm_sock"
    sudo systemctl reload nginx

    success "Site cloned successfully!"
    echo -e "----------------------------------------"
    echo -e "✅ New site: http://$new_domain"
    echo -e "🔑 New DB Password: $new_db_pass"
    echo -e "----------------------------------------"
}

# === NEW: Ensure Let's Encrypt auto-renew is configured (systemd timer preferred, cron fallback) ===
ensure_le_autorenew() {
  # 1) Deploy hook: reload Nginx after successful renewal
  sudo install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
  sudo tee /etc/letsencrypt/renewal-hooks/deploy/000-reload-nginx.sh >/dev/null <<'HOOK'
#!/usr/bin/env bash
if command -v nginx >/dev/null 2>&1; then
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx || true
  fi
fi
HOOK
  sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/000-reload-nginx.sh

  # 2) Prefer systemd timer if available
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -qE '^certbot-renew\.timer'; then
        if ! sudo systemctl enable --now certbot-renew.timer 2>/dev/null; then
            echo '0 3,15 * * * root certbot renew -q' | sudo tee /etc/cron.d/certbot >/dev/null
            sudo chmod 644 /etc/cron.d/certbot
            sudo systemctl enable --now crond 2>/dev/null || true
        fi
    else
        # 3) Fallback cron (twice daily, quiet)
        echo '0 3,15 * * * root certbot renew -q' | sudo tee /etc/cron.d/certbot >/dev/null
        sudo chmod 644 /etc/cron.d/certbot
        sudo systemctl enable --now crond 2>/dev/null || true
    fi
}

install_ssl() {
    local domain=$1
    local email=$2
    domain=$(normalize_domain "$domain")
    require_valid_domain "$domain"
    require_valid_email "$email"
    info "Starting SSL installation for domain: $domain"
    sudo dnf install -y certbot python3-certbot-nginx

    if sudo certbot --nginx -d "$domain" -d "www.$domain" --agree-tos --no-eff-email --redirect --email "$email"; then
        # NEW: configure auto-renew after successful issuance
        ensure_le_autorenew

    info "Updating URL in WordPress to use HTTPS..."
    local webroot="/var/www/$domain"
    local site_user
    site_user=$(get_site_user_from_webroot "$webroot")
    ensure_wp_cli
    sudo -u "$site_user" "$WP_CLI_PATH" option update home "https://$domain" --path="$webroot"
        sudo -u "$site_user" "$WP_CLI_PATH" option update siteurl "https://$domain" --path="$webroot"
        success "SSL installation for https://$domain successful!"
        return 0
    else
        warn "SSL installation process with Certbot failed."
        warn "Please verify that your domain's DNS A record points to this VPS IP, then use menu option 4 to retry Let's Encrypt SSL."
        return 1
    fi
}

install_self_signed_ssl() {
    info "Bắt đầu cài đặt Self-Signed SSL..."
    list_sites || return

    local sites_path="/etc/nginx/conf.d"
    local sites
    sites=($(find "$sites_path" -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" | sed 's/\.conf$//'))
    echo "   0. 🔙 Trở về menu chính"

    read -p "Chọn trang web để cài đặt SSL: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt ${#sites[@]} ]; then
        menu_error "Lựa chọn không hợp lệ."
        return
    fi
    if [ "$choice" -eq 0 ]; then
        info "Đã hủy thao tác."
        return
    fi
    local domain="${sites[$((choice - 1))]}"
    require_valid_domain "$domain"

    info "Đang cài đặt cho tên miền: $domain"

    info "Đảm bảo OpenSSL đã được cài đặt..."
    sudo dnf install -y openssl

    local key_path="/etc/pki/tls/private/${domain}.key"
    local cert_path="/etc/pki/tls/certs/${domain}.crt"

    if [ -f "$cert_path" ]; then
        warn "Chứng chỉ SSL cho $domain dường như đã tồn tồn tại. Bỏ qua bước tạo mới."
    else
        info "Tạo chứng chỉ tự ký (Self-Signed) có hiệu lực 365 ngày..."
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$key_path" \
            -out "$cert_path" \
            -subj "/CN=$domain"
    fi

    info "Cập nhật cấu hình Nginx cho $domain..."
    local nginx_conf="/etc/nginx/conf.d/${domain}.conf"
    local webroot
    webroot=$(grep -oP '^\s*root\s+\K[^;]+' "$nginx_conf")
    local fpm_sock
    fpm_sock=$(grep -oP '^\s*fastcgi_pass\s+unix:\K[^;]+' "$nginx_conf")

    sudo tee "$nginx_conf" >/dev/null <<EOL
# Chuyển hướng từ HTTP sang HTTPS
server {
    listen 80;
    server_name $domain www.$domain;
    return 301 https://\$server_name\$request_uri;
}

# Cấu hình HTTPS
server {
    listen 443 ssl http2;
    server_name $domain www.$domain;
    root $webroot;
    index index.php index.html;

    client_max_body_size 512M;

    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;

    # Cấu hình SSL/TLS tối ưu
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    location ^~ /.well-known/acme-challenge/ {
        allow all;
        root $webroot;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location = /xmlrpc.php {
        deny all;
    }

    location ~* /(wp-config.php|readme.html|license.txt|\.user.ini|composer\.(json|lock)|package(-lock)?\.json)$ {
        deny all;
    }

    location ~* /(?:uploads|files)/.*\.php\$ {
        deny all;
    }

    location ~* \.(?:css|js|jpg|jpeg|gif|png|webp|avif|svg|ico|woff2?|ttf|eot|otf|mp4|webm)$ {
        expires 30d;
        access_log off;
        log_not_found off;
        add_header Cache-Control "public, no-transform";
        try_files \$uri =404;
    }

    location ~ \.php\$ {
        try_files \$uri =404;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTPS \$https if_not_empty;
        fastcgi_param HTTP_PROXY "";
        fastcgi_pass unix:$fpm_sock;
        fastcgi_read_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_connect_timeout 60;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 256 16k;
        fastcgi_busy_buffers_size 256k;
        fastcgi_temp_file_write_size 256k;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }
}
EOL

    info "Kiểm tra cấu hình Nginx và tải lại dịch vụ..."
    if ! sudo nginx -t; then
        fatal_error "Cấu hình Nginx cho $domain không hợp lệ. Vui lòng kiểm tra lại."
        return 1
    fi
    sudo systemctl reload nginx

    info "Cập nhật đường dẫn trong WordPress sang HTTPS..."
    local site_user
    site_user=$(get_site_user_from_webroot "$webroot")
    ensure_wp_cli
    sudo -u "$site_user" "$WP_CLI_PATH" option update home "https://$domain" --path="$webroot"
    sudo -u "$site_user" "$WP_CLI_PATH" option update siteurl "https://$domain" --path="$webroot"

    success "Đã cài đặt Self-Signed SSL thành công cho https://$domain"
    warn "LƯU Ý: Vì đây là chứng chỉ tự ký, trình duyệt sẽ hiển thị cảnh báo bảo mật. Bạn cần chấp nhận rủi ro để tiếp tục."
}


# --- OPTIMIZATION MENU ---
optimize_wp_cron() {
    info "Optimizing WP-Cron by using a system cron job."
    list_sites || return

    local sites_path="/etc/nginx/conf.d"
    local sites
    sites=($(find "$sites_path" -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" | sed 's/\.conf$//'))
    echo "   0. 🔙 Back to main menu"

    read -p "Select site to optimize WP-Cron: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt ${#sites[@]} ]; then
        menu_error "Invalid choice."
        return
    fi
    if [ "$choice" -eq 0 ]; then
        info "Operation cancelled."
        return
    fi

    local domain="${sites[$((choice - 1))]}"
    require_valid_domain "$domain"
    local webroot="/var/www/$domain"
    local site_user
    site_user=$(get_site_user_from_webroot "$webroot")
    ensure_wp_cli
    local config_file="$webroot/wp-config.php"
    local cron_file="/etc/cron.d/wp-cron-$domain"

    info "Disabling default WP-Cron in wp-config.php..."
    if sudo grep -q "DISABLE_WP_CRON" "$config_file"; then
        warn "WP-Cron is already disabled in wp-config.php."
    else
        sudo sed -i "/\/\* That's all, stop editing!/i define('DISABLE_WP_CRON', true);" "$config_file"
        success "Added define('DISABLE_WP_CRON', true); to $config_file."
    fi

    info "Creating system cron job..."
    if [ -f "$cron_file" ]; then
        warn "Cron job for domain '$domain' already exists at $cron_file."
        echo "Current content:"
        sudo cat "$cron_file"
    else
        local site_url
        site_url=$(sudo -u "$site_user" "$WP_CLI_PATH" option get siteurl --path="$webroot")
        local cron_command="*/5 * * * * nginx wget -q -O - ${site_url}/wp-cron.php?doing_wp_cron >/dev/null 2>&1"
        echo "$cron_command" | sudo tee "$cron_file" >/dev/null
        sudo chmod 644 "$cron_file"
        success "Cron job created at $cron_file, runs every 5 minutes."
    fi
}

optimize_menu() {
    while true; do
        clear
        echo -e "\n${C_BLUE}========= WORDPRESS OPTIMIZATION MENU =========${C_RESET}"
        echo "1. Optimize WP-Cron (Separate from user tasks)"
        echo "0. 🔙 Back to main menu"
        echo "----------------------------------------"
        read -p "Enter your choice: " choice

        case "$choice" in
        1) optimize_wp_cron ;;
        0) return ;;
        *) menu_error "Invalid choice." ;;
        esac
        echo -e "\n${C_CYAN}Press any key to return...${C_RESET}"
        read -n 1 -s -r
    done
}

restart_services() {
    info "Restarting Nginx, PHP, and MariaDB..."
    sudo systemctl restart nginx php-fpm mariadb
    success "Services have been restarted."
}

chmod_site_permissions() {
    info "Starting WordPress site permissions configuration."
    list_sites || return

    local sites_path="/etc/nginx/conf.d"
    local sites
    sites=($(find "$sites_path" -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" | sed 's/\.conf$//'))
    echo "   0. 🔙 Back to main menu"

    read -p "Enter your choice for the site to configure permissions: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt ${#sites[@]} ]; then
        menu_error "Invalid choice."
        return
    fi
    if [ "$choice" -eq 0 ]; then
        info "Operation cancelled."
        return
    fi
    local domain="${sites[$((choice - 1))]}"
    require_valid_domain "$domain"
    local webroot="/var/www/$domain"
    local site_user
    site_user=$(get_site_user_from_webroot "$webroot")

    if [ ! -d "$webroot" ]; then
        fatal_error "Webroot $webroot does not exist. Cannot set permissions."
    fi

    info "Applying recommended WordPress permissions for $webroot..."

    # Set directory permissions to 755
    sudo find "$webroot" -type d -exec chmod 755 {} +
    # Set file permissions to 644
    sudo find "$webroot" -type f -exec chmod 644 {} +

    # Set specific permissions for wp-content/uploads (required for media uploads)
    info "Setting specific permissions for wp-content/uploads to 775..."
    sudo install -d -m 775 -o "$site_user" -g nginx "$webroot/wp-content/uploads"
    sudo find "$webroot/wp-content/uploads" -type d -exec chmod 775 {} +
    sudo find "$webroot/wp-content/uploads" -type f -exec chmod 664 {} +

    # Ensure ownership is correct
    info "Ensuring correct ownership for $webroot (user: $site_user, group: nginx)..."
    sudo chown -R "$site_user":nginx "$webroot"

    # Set SELinux context (already handled during site creation, but good to re-apply)
    info ">> SELinux: Re-applying context for webroot..."
    set_webroot_selinux_context "$webroot"

    success "Permissions for site '$domain' have been set to recommended WordPress values."
    warn "It's always recommended to check your specific WordPress setup for any custom permission requirements."
}

# --- REDIS INSTALLATION FUNCTION ---
install_redis() {
    info "Starting Redis and PHP-Redis installation..."

    if [ ! -f "$LEMP_INSTALLED_FLAG" ]; then
        warn "LEMP stack flag not found. It's highly recommended to install LEMP first (Option 1)."
        read -p "Do you want to continue with the installation anyway? (y/N): " continue_choice
        if [[ "${continue_choice,,}" != "y" ]]; then
            info "Redis installation cancelled."
            return
        fi
    fi

    info "Installing Redis server from system repositories..."
    sudo dnf install -y redis

    info "Installing PHP Redis extension to match your PHP version..."
    # This will install the correct php-redis package for the enabled Remi module
    sudo dnf install -y php-redis

    info "Enabling and starting the Redis service..."
    sudo systemctl enable --now redis

    if [ -f /etc/redis/redis.conf ] && ! grep -q '^maxmemory-policy ' /etc/redis/redis.conf; then
        echo 'maxmemory-policy allkeys-lru' | sudo tee -a /etc/redis/redis.conf >/dev/null
        sudo systemctl restart redis
    fi

    info "Restarting PHP-FPM to load the new Redis extension..."
    sudo systemctl restart php-fpm

    if [ -d /etc/nginx/conf.d ]; then
        ensure_wp_cli
        local sites_path="/etc/nginx/conf.d"
        local sites
        sites=($(find "$sites_path" -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" | sed 's/\.conf$//'))
        for domain in "${sites[@]}"; do
            local webroot="/var/www/$domain"
            [ -f "$webroot/wp-config.php" ] || continue
            local site_user
            site_user=$(get_site_user_from_webroot "$webroot")
            sudo -u "$site_user" "$WP_CLI_PATH" plugin install redis-cache --activate --path="$webroot" || true
            sudo -u "$site_user" "$WP_CLI_PATH" redis enable --path="$webroot" || true
        done
    fi

    success "Redis and the PHP-Redis extension have been installed successfully!"
    info "You can verify the PHP module with: php --ri redis"
    info "Next, install a plugin like 'Redis Object Cache' in WordPress to use it."
}

# --- MAIN MENU ---
main_menu() {
    while true; do
        clear
        echo -e "\n${C_BLUE}========= WORDPRESS MANAGER (v4.7-RHEL) =========${C_RESET}"
        echo "1. Install LEMP stack"
        echo "2. Create new WordPress site"
        echo "3. Clone WordPress site"
        echo "4. Install SSL for an existing site (Let's Encrypt)"
        echo "5. List sites"
        echo "6. Restart services (Nginx, PHP, DB)"
        echo "7. Optimize WordPress"
        echo "8. Delete WordPress site"
        echo "9. Configure WordPress Site Permissions (CHMOD)"
        echo "10. Install Redis & PHP-Redis"
        echo "11. Install Self-Signed SSL (for local/test)"
        echo -e "${C_YELLOW}0. Exit${C_RESET}"
        echo "----------------------------------------"
        read -p "Enter your choice: " choice

        case "$choice" in
        1) install_lemp ;;
        2) create_site ;;
        3) clone_site ;;
        4)
            list_sites || continue
            local sites_path="/etc/nginx/conf.d"
            local sites
            sites=($(find "$sites_path" -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" | sed 's/\.conf$//'))
            echo "   0. 🔙 Back to main menu"

            read -p "Select site number for SSL installation: " ssl_choice
            if ! [[ "$ssl_choice" =~ ^[0-9]+$ ]] || [ "$ssl_choice" -gt ${#sites[@]} ]; then
                menu_error "Invalid choice."
                continue
            fi
            if [ "$ssl_choice" -eq 0 ]; then
                info "Operation cancelled."
                continue
            fi

            local ssl_domain="${sites[$((ssl_choice - 1))]}"
            local ssl_email=""
            while [ -z "$ssl_email" ]; do
                read -p "Enter your email: " ssl_email
                if ! is_valid_email "$ssl_email"; then
                    menu_error "Invalid email format."
                    ssl_email=""
                fi
            done
            install_ssl "$ssl_domain" "$ssl_email" || true
            ;;
        5) list_sites ;;
        6) restart_services ;;
        7) optimize_menu ;;
        8) delete_site ;;
        9) chmod_site_permissions ;;
        10) install_redis ;;
        11) install_self_signed_ssl ;;
        0)
            info "Goodbye!"
            exit 0
            ;;
        *)
            menu_error "Invalid choice. Please try again."
            ;;
        esac
        echo -e "\n${C_CYAN}Press any key to return to the main menu...${C_RESET}"
        read -n 1 -s -r
    done
}

# --- START SCRIPT ---
main_menu
