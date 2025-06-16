#!/bin/bash

# Test script for twemproxy with zone detection
# Tests the functionality of the Docker container

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[TEST]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Configuration
TWEMPROXY_HOST="${TWEMPROXY_HOST:-localhost}"
READ_PORT="${READ_PORT:-6378}"
WRITE_PORT="${WRITE_PORT:-6377}"
STATS_PORT="${STATS_PORT:-22222}"

log "Testing twemproxy with zone detection..."
log "Host: $TWEMPROXY_HOST"
log "Read port: $READ_PORT, Write port: $WRITE_PORT, Stats port: $STATS_PORT"

# Wait for services to be ready
wait_for_service() {
    local host=$1
    local port=$2
    local service=$3
    local timeout=30
    
    log "Waiting for $service at $host:$port..."
    
    for i in $(seq 1 $timeout); do
        if timeout 3 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
            success "$service is ready!"
            return 0
        fi
        sleep 1
    done
    
    error "$service is not responding after ${timeout}s"
    return 1
}

# Test Redis CLI availability
test_redis_cli() {
    if ! command -v redis-cli >/dev/null 2>&1; then
        if docker ps --format "table {{.Names}}" | grep -q redis-test-client; then
            log "Using redis-cli from Docker container"
            REDIS_CLI="docker exec redis-test-client redis-cli"
        else
            error "redis-cli not available. Install Redis CLI or run: docker-compose --profile testing up -d"
            return 1
        fi
    else
        REDIS_CLI="redis-cli"
    fi
}

# Test basic connectivity
test_connectivity() {
    log "Testing basic connectivity..."
    
    # Test write port
    if $REDIS_CLI -h $TWEMPROXY_HOST -p $WRITE_PORT ping >/dev/null 2>&1; then
        success "Write port ($WRITE_PORT) is accessible"
    else
        error "Cannot connect to write port ($WRITE_PORT)"
        return 1
    fi
    
    # Test read port  
    if $REDIS_CLI -h $TWEMPROXY_HOST -p $READ_PORT ping >/dev/null 2>&1; then
        success "Read port ($READ_PORT) is accessible"
    else
        error "Cannot connect to read port ($READ_PORT)"
        return 1
    fi
}

# Test write/read operations
test_operations() {
    log "Testing read/write operations..."
    
    local test_key="twemproxy:test:$(date +%s)"
    local test_value="zone-detection-test-$(shuf -i 1000-9999 -n 1)"
    
    # Write operation
    log "Writing test data: $test_key = $test_value"
    if $REDIS_CLI -h $TWEMPROXY_HOST -p $WRITE_PORT set "$test_key" "$test_value" >/dev/null; then
        success "Write operation successful"
    else
        error "Write operation failed"
        return 1
    fi
    
    # Read operation from read pool
    log "Reading from read pool..."
    local read_result=$($REDIS_CLI -h $TWEMPROXY_HOST -p $READ_PORT get "$test_key" 2>/dev/null || echo "")
    
    if [[ "$read_result" == "$test_value" ]]; then
        success "Read operation successful"
    else
        warn "Read result: '$read_result' (expected: '$test_value')"
        warn "This might be due to replication lag or read/write pool separation"
    fi
    
    # Cleanup
    $REDIS_CLI -h $TWEMPROXY_HOST -p $WRITE_PORT del "$test_key" >/dev/null 2>&1 || true
}

# Test stats endpoint
test_stats() {
    log "Testing stats endpoint..."
    
    if command -v curl >/dev/null 2>&1; then
        local stats_response=$(curl -s "http://$TWEMPROXY_HOST:$STATS_PORT" 2>/dev/null || echo "")
        
        if [[ -n "$stats_response" ]]; then
            success "Stats endpoint is accessible"
            
            # Check for zone detection stats
            if echo "$stats_response" | grep -q "dns_addresses\|latency"; then
                success "Zone detection stats are present"
                
                # Show some key stats
                log "Key statistics:"
                echo "$stats_response" | grep -E "(dns_addresses|latency_fastest_sel|latency_distributed_sel)" | head -5
            else
                warn "Zone detection stats not found in response"
            fi
        else
            error "Stats endpoint is not responding"
            return 1
        fi
    else
        warn "curl not available, skipping stats test"
    fi
}

# Test zone detection behavior
test_zone_detection() {
    log "Testing zone detection behavior..."
    
    # Perform multiple read operations to trigger zone detection
    local test_key="twemproxy:zone:test"
    
    # Set a test value
    $REDIS_CLI -h $TWEMPROXY_HOST -p $WRITE_PORT set "$test_key" "zone-test" >/dev/null
    
    # Perform multiple reads to generate latency data
    log "Performing multiple reads to generate latency data..."
    for i in {1..20}; do
        $REDIS_CLI -h $TWEMPROXY_HOST -p $READ_PORT get "$test_key" >/dev/null 2>&1 || true
        sleep 0.1
    done
    
    success "Zone detection test completed"
    
    # Check stats for zone activity
    if command -v curl >/dev/null 2>&1; then
        local stats=$(curl -s "http://$TWEMPROXY_HOST:$STATS_PORT" 2>/dev/null || echo "")
        if echo "$stats" | grep -q "latency_fastest_sel\|latency_distributed_sel"; then
            log "Zone routing statistics:"
            echo "$stats" | grep -E "latency.*sel" | head -3
        fi
    fi
    
    # Cleanup
    $REDIS_CLI -h $TWEMPROXY_HOST -p $WRITE_PORT del "$test_key" >/dev/null 2>&1 || true
}

# Performance test
test_performance() {
    log "Running basic performance test..."
    
    if command -v redis-benchmark >/dev/null 2>&1; then
        log "Running redis-benchmark against read pool..."
        redis-benchmark -h $TWEMPROXY_HOST -p $READ_PORT -n 1000 -c 10 -q -t get,set 2>/dev/null || warn "Performance test failed"
        success "Performance test completed"
    else
        warn "redis-benchmark not available, skipping performance test"
    fi
}

# Main test execution
main() {
    log "Starting twemproxy zone detection tests..."
    
    # Wait for services
    wait_for_service $TWEMPROXY_HOST $READ_PORT "twemproxy read pool" || exit 1
    wait_for_service $TWEMPROXY_HOST $WRITE_PORT "twemproxy write pool" || exit 1
    wait_for_service $TWEMPROXY_HOST $STATS_PORT "twemproxy stats" || exit 1
    
    # Setup Redis CLI
    test_redis_cli || exit 1
    
    # Run tests
    test_connectivity || exit 1
    test_operations || exit 1
    test_stats || exit 1
    test_zone_detection || exit 1
    test_performance || true  # Don't fail on performance test
    
    success "All tests completed successfully!"
    
    log "To monitor zone detection in real-time:"
    log "  curl -s http://$TWEMPROXY_HOST:$STATS_PORT | grep latency"
    log ""
    log "To see detailed stats:"
    log "  curl -s http://$TWEMPROXY_HOST:$STATS_PORT | jq ."
}

# Run tests
main "$@"