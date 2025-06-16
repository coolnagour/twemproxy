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
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create user for running twemproxy
RUN useradd -r -s /bin/false -d /var/lib/twemproxy twemproxy && \
    mkdir -p /var/lib/twemproxy /var/log/twemproxy /etc/twemproxy && \
    chown twemproxy:twemproxy /var/lib/twemproxy /var/log/twemproxy

# Copy binary and config from builder
COPY --from=builder /tmp/install/usr/local/sbin/nutcracker /usr/local/sbin/
COPY --from=builder /tmp/install/usr/local/bin/nutcracker /usr/local/bin/
COPY conf/*.yml /etc/twemproxy/

# Create default configuration
RUN cat > /etc/twemproxy/nutcracker.yml << 'EOF'
# Default twemproxy configuration with cloud zone detection
global:
    worker_processes: auto
    user: twemproxy
    group: twemproxy

pools:
    # Redis read pool with zone awareness
    redis_read:
        listen: 0.0.0.0:6378
        redis: true
        
        # Enable cloud zone detection
        latency_routing: true
        latency_weight: 60
        zone_aware: true
        zone_weight: 30
        zone_latency_threshold: 50000
        
        # Connection optimization
        connection_pooling: true
        connection_warming: 1
        dns_resolve_interval: 30
        
        # Default to localhost (override with environment)
        servers:
            - redis-server:6379:1
    
    # Redis write pool  
    redis_write:
        listen: 0.0.0.0:6379
        redis: true
        zone_aware: true
        connection_pooling: true
        
        servers:
            - redis-server:6379:1
EOF

# Set permissions
RUN chmod 644 /etc/twemproxy/nutcracker.yml && \
    chmod +x /usr/local/sbin/nutcracker /usr/local/bin/nutcracker

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD /usr/local/sbin/nutcracker --test-conf -c /etc/twemproxy/nutcracker.yml || exit 1

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

# Default command
CMD ["/usr/local/sbin/nutcracker", \
     "--conf-file=/etc/twemproxy/nutcracker.yml", \
     "--verbose=6", \
     "--output=/var/log/twemproxy/nutcracker.log", \
     "--stats-port=22222"]