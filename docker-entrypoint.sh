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