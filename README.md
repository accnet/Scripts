sudo curl -L https://raw.githubusercontent.com/accnet/Scripts/refs/heads/main/wootify-script.sh -o /usr/local/bin/wpmanager && \
sudo chmod +x /usr/local/bin/wpmanager && \
/usr/local/bin/wpmanager



script đặt lại pass:

# Lấy domain đầu tiên trong danh sách site (giống cách list_sites lấy từ /etc/nginx/conf.d)
domain=$(find /etc/nginx/conf.d -maxdepth 1 -type f -name "*.conf" ! -name "php-fpm.conf" -printf "%f\n" \
    | sed 's/\.conf$//' | sort | head -n1)

if [ -z "$domain" ]; then
    echo "Không tìm thấy site nào."
    exit 1
fi

webroot="/var/www/$domain"
site_user=$(stat -c '%U' "$webroot")   # tương đương get_site_user_from_webroot

# Đảm bảo wp-cli đã sẵn sàng
WP_CLI_PATH="/usr/local/bin/wp"

# Lấy username admin đầu tiên (role administrator)
admin_user=$(sudo -u "$site_user" "$WP_CLI_PATH" user list --role=administrator --field=user_login --path="$webroot" | head -n1)

if [ -z "$admin_user" ]; then
    echo "Không tìm thấy user admin."
    exit 1
fi

# Sinh mật khẩu ngẫu nhiên mạnh (dùng openssl, giống style generate_sql_password của script)
new_pass=$(openssl rand -base64 18)

# Đổi mật khẩu
sudo -u "$site_user" "$WP_CLI_PATH" user update "$admin_user" --user_pass="$new_pass" --path="$webroot"

echo "----------------------------------------"
echo "🌐 Site:         $domain"
echo "👤 Admin user:   $admin_user"
echo "🔑 New password: $new_pass"
echo "----------------------------------------"
