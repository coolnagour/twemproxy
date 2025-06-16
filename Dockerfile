# Multi-stage Docker build for twemproxy with cloud zone detection
# Stage 1: Build container (x86 architecture)
FROM --platform=linux/amd64 ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libyaml-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build twemproxy
RUN autoreconf -fvi && \
    ./configure \
        --prefix=/usr/local \
        --enable-debug=no \
        --enable-stats \
        && \
    make -j$(nproc) && \
    make install DESTDIR=/tmp/install

# Verify the build
RUN /tmp/install/usr/local/sbin/nutcracker --version

# Stage 2: Runtime container (minimal)
FROM --platform=linux/amd64 ubuntu:22.04 AS runtime

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    libyaml-0-2 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create user for running twemproxy
RUN useradd -r -s /bin/false -d /var/lib/twemproxy twemproxy && \
    mkdir -p /var/lib/twemproxy /var/log/twemproxy /etc/twemproxy && \
    chown twemproxy:twemproxy /var/lib/twemproxy /var/log/twemproxy

# Copy binary and config from builder
COPY --from=builder /tmp/install/usr/local/sbin/nutcracker /usr/local/sbin/
COPY conf/*.yml /etc/twemproxy/

# Create entrypoint script for environment variable substitution
RUN cat > /usr/local/bin/entrypoint.sh << 'EOF'
#!/bin/bash
set -e

# Set default values if environment variables are not provided
READ_HOST=${READ_HOST:-"redis-read:6379"}
WRITE_HOST=${WRITE_HOST:-"redis-write:6379"}
ZONE_WEIGHT=${ZONE_WEIGHT:-"95"}
DNS_RESOLVE_INTERVAL=${DNS_RESOLVE_INTERVAL:-"30"}
DNS_EXPIRATION_MINUTES=${DNS_EXPIRATION_MINUTES:-"5"}
DNS_HEALTH_CHECK_INTERVAL=${DNS_HEALTH_CHECK_INTERVAL:-"30"}

# Create configuration from template
cat > /etc/twemproxy/nutcracker.yml << EOL
# Twemproxy configuration with zone-aware routing
# Generated from environment variables
global:
    worker_processes: auto
    max_openfiles: 102400
    user: twemproxy
    group: twemproxy
    worker_shutdown_timeout: 30

pools:
    # Write pool - single primary endpoint
    redis_write:
        listen: 0.0.0.0:6379
        auto_eject_hosts: true
        redis: true
        timeout: 2000
        server_retry_timeout: 1000
        server_failure_limit: 5
        server_connections: 1
        servers:
            - ${WRITE_HOST}:1

    # Read pool - zone-aware routing for cost optimization
    redis_read:
        listen: 0.0.0.0:6378
        distribution: ketama
        auto_eject_hosts: true
        redis: true
        timeout: 2000
        server_retry_timeout: 10000
        server_failure_limit: 1
        server_connections: 1

        # Zone-aware configuration
        zone_aware: true
        zone_weight: ${ZONE_WEIGHT}
        dns_resolve_interval: ${DNS_RESOLVE_INTERVAL}
        dns_expiration_minutes: ${DNS_EXPIRATION_MINUTES}
        dns_health_check_interval: ${DNS_HEALTH_CHECK_INTERVAL}

        # Connection pooling for efficiency
        connection_pooling: true
        connection_warming: 1

        servers:
            - ${READ_HOST}:1
EOL

echo "Generated configuration:"
cat /etc/twemproxy/nutcracker.yml
echo ""

# Execute the original command
exec "$@"
EOF

# Set permissions
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/sbin/nutcracker && \
    mkdir -p /etc/twemproxy

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:22222 || exit 1

# Expose ports
EXPOSE 6378 6379 22222

# Labels
LABEL maintainer="Twemproxy Enhanced" \
      version="1.0.0" \
      description="Twemproxy with cloud zone detection and latency-based routing" \
      org.opencontainers.image.title="twemproxy-enhanced" \
      org.opencontainers.image.description="Redis proxy with intelligent zone-aware routing" \
      org.opencontainers.image.source="https://github.com/your-repo/twemproxy"

# Switch to non-root user
USER twemproxy

# Set entrypoint and default command
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/sbin/nutcracker", \
     "--conf-file=/etc/twemproxy/nutcracker.yml", \
     "--verbose=6", \
     "--output=/var/log/twemproxy/nutcracker.log", \
     "--stats-port=22222"]