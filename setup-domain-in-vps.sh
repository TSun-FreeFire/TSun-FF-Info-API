#!/bin/bash
set -e

# === Configuration ===
DOMAIN="${DOMAIN:-ffinfo.tsunstudio.pw}"
EMAIL="${EMAIL:-admin@tsunstudio.pw}"
APP_PORT="${APP_PORT:-8075}"
PROJECT_DIR="${PROJECT_DIR:-/root/TSun-FF-Info-API}"
IMAGE_NAME="${IMAGE_NAME:-tsun-ff-info-api}"
CONTAINER_NAME="${CONTAINER_NAME:-tsun-ff-info-api}"

echo "============================================"
echo "  VPS Deployment Setup"
echo "  Domain:    $DOMAIN"
echo "  Port:      $APP_PORT"
echo "  Project:   $PROJECT_DIR"
echo "  Container: $CONTAINER_NAME"
echo "============================================"

# === Project Validation ===
echo ""
echo "[1/6] Validating project structure..."

if [ ! -f "$PROJECT_DIR/app.py" ]; then
    echo "ERROR: app.py not found in $PROJECT_DIR"
    exit 1
fi

if [ ! -f "$PROJECT_DIR/Dockerfile" ]; then
    echo "ERROR: Dockerfile not found in $PROJECT_DIR"
    exit 1
fi

if [ ! -f "$PROJECT_DIR/requirements.txt" ]; then
    echo "ERROR: requirements.txt not found in $PROJECT_DIR"
    exit 1
fi

echo "Project structure validated successfully."

# === .env Validation ===
if [ ! -f "$PROJECT_DIR/.env" ] && [ -f "$PROJECT_DIR/.env.example" ]; then
    echo "WARNING: .env not found. Creating from .env.example..."
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    echo "Please review and update $PROJECT_DIR/.env with actual values."
fi

# === Install Docker ===
echo ""
echo "[2/6] Installing Docker..."

if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    echo "Docker installed successfully."
else
    echo "Docker already installed: $(docker --version)"
fi

# === Install Nginx & Certbot ===
echo ""
echo "[3/6] Installing Nginx & Certbot..."

if ! command -v nginx &> /dev/null; then
    apt-get update -y
    apt-get install -y nginx
    systemctl enable nginx
    systemctl start nginx
    echo "Nginx installed successfully."
else
    echo "Nginx already installed: $(nginx -v 2>&1)"
fi

if ! command -v certbot &> /dev/null; then
    apt-get install -y certbot python3-certbot-nginx
    echo "Certbot installed successfully."
else
    echo "Certbot already installed: $(certbot --version 2>&1)"
fi

# === Build & Start Docker Container ===
echo ""
echo "[4/6] Building and starting Docker container..."

cd "$PROJECT_DIR"

# Stop existing container if running
docker compose down 2>/dev/null || true

# Build and start
docker compose up -d --build

echo "Container '$CONTAINER_NAME' started successfully."

# Wait for container to be healthy
echo "Waiting for container to be ready..."
sleep 10

# Verify container is running
if docker ps --filter "name=$CONTAINER_NAME" --filter "status=running" | grep -q "$CONTAINER_NAME"; then
    echo "Container is running."
else
    echo "WARNING: Container may not be running. Check logs with: docker logs $CONTAINER_NAME"
fi

# === Nginx Configuration ===
echo ""
echo "[5/6] Configuring Nginx reverse proxy..."

cat > /etc/nginx/sites-available/$DOMAIN << 'NGINX_EOF'
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_PLACEHOLDER;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;

    location / {
        proxy_pass http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Performance tuning
        proxy_connect_timeout 60s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        proxy_buffering on;
        proxy_buffer_size 16k;
        proxy_buffers 4 32k;
        proxy_busy_buffers_size 64k;

        # Client limits
        client_max_body_size 10m;
        client_body_buffer_size 128k;
    }
}
NGINX_EOF

# Replace placeholders with actual values
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /etc/nginx/sites-available/$DOMAIN
sed -i "s/PORT_PLACEHOLDER/$APP_PORT/g" /etc/nginx/sites-available/$DOMAIN

# Enable site
ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and reload Nginx
nginx -t
systemctl reload nginx

echo "Nginx configured for $DOMAIN -> 127.0.0.1:$APP_PORT"

# === SSL Certificate ===
echo ""
echo "[6/6] Obtaining SSL certificate..."

certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect

echo "SSL certificate obtained and configured."

# === Verification ===
echo ""
echo "============================================"
echo "  Deployment Complete!"
echo "============================================"
echo ""
echo "  Domain:    https://$DOMAIN"
echo "  Container: $CONTAINER_NAME"
echo "  Port:      $APP_PORT (internal)"
echo ""
echo "  Useful commands:"
echo "    docker logs $CONTAINER_NAME          # View logs"
echo "    docker compose restart               # Restart"
echo "    docker compose down && docker compose up -d --build  # Rebuild"
echo "    certbot renew --dry-run              # Test SSL renewal"
echo ""
echo "============================================"
