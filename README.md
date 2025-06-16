# twemproxy (nutcracker) - Enhanced with Dynamic DNS & Latency-Based Routing

## 🚀 What's Different from Original Twemproxy?

This fork adds **dynamic DNS resolution** and **latency-based server selection** for Redis read replicas, eliminating the need for external scripts and config file reloading.

### ✨ New Features:
- **🎯 Latency-Based Routing**: Automatically routes traffic to the lowest latency Redis servers
- **⚖️ Weighted Traffic Distribution**: Configure percentage split (e.g., 80% to fastest server, 20% to second-best)
- **🔄 Dynamic DNS Resolution**: Automatically discovers new/removed Redis servers without restarts
- **📊 Real-time Latency Measurement**: Measures actual connection latency during normal operations
- **⚙️ Configurable per Pool**: Enable/disable features independently for read vs write pools
- **🛡️ Automatic Failover**: Seamlessly handles server failures and DNS changes

### 🌍 Cloud Multi-Zone Optimizations:
- **🏢 Zone Awareness**: Automatically detects zones based on latency patterns (reduces costs & latency)
- **⚡ Managed Cache Integration**: Enhanced support for cloud cache service endpoints and scaling
- **🔒 TLS Support**: Built-in support for TLS encryption and certificate verification
- **🏥 Enhanced Health Checking**: Advanced health monitoring with failure threshold controls
- **🔗 Connection Pooling**: Intelligent connection management with warming and idle timeout
- **📈 Cost Optimization**: Minimizes cross-zone data transfer charges through smart routing

---

## Quick Start

### 1. Build from Source
```bash
git clone <this-repo>
cd twemproxy
autoreconf -fvi
./configure
make
sudo make install
```

### 2. Create Configuration
Create `nutcracker.yml` with dynamic DNS support:

```yaml
global:
    worker_processes: auto
    user: nobody
    group: nobody

pools:
    redis_read:
        listen: 127.0.0.1:6378
        redis: true
        auto_eject_hosts: true
        
        # Dynamic DNS and latency-based routing
        latency_routing: true           # Enable smart routing
        dns_resolve_interval: 30        # Re-check DNS every 30 seconds  
        latency_weight: 50              # 50% to fastest, 50% distributed among all others
        
        servers:
            - redis-cluster-ro.us-east-1.cache.amazonaws.com:6379:1

    redis_write:
        listen: 127.0.0.1:6379
        redis: true
        servers:
            - redis-cluster.us-east-1.cache.amazonaws.com:6379:1
```

### 3. Run
```bash
nutcracker -c nutcracker.yml -v 6
```

### 4. Test
```bash
# Read traffic (will route to lowest latency server)
redis-cli -h 127.0.0.1 -p 6378 GET mykey

# Write traffic (normal routing)
redis-cli -h 127.0.0.1 -p 6379 SET mykey value
```

---

## Cloud Configuration Examples

### 🔥 Managed Redis Cluster
```yaml
pools:
    redis_read:
        listen: 127.0.0.1:6378
        redis: true
        
        # Core latency routing
        latency_routing: true
        latency_weight: 60                    # 60% to fastest, 40% distributed
        dns_resolve_interval: 15              # Managed caches scale frequently
        
        # Cloud zone optimizations
        zone_aware: true                      # Enable zone-aware routing
        zone_weight: 30                       # +30% weight for same-zone servers
        zone_latency_threshold: 50000         # 50ms threshold for zone detection
        cache_mode: true                      # Managed cache optimizations
        
        # Connection pooling
        connection_pooling: true
        connection_warming: 1                 # Pre-warm connections
        connection_idle_timeout: 300
        
        # Enhanced health monitoring
        dns_failure_threshold: 2              # Faster failover
        
        servers:
            - redis-cluster-ro.cache.example.com:6379:1
```

### 🗄️ Managed Database Cluster
```yaml
pools:
    database_read:
        listen: 127.0.0.1:3306
        
        # Database-optimized settings
        latency_routing: true
        latency_weight: 70                    # Prefer fastest reader
        dns_resolve_interval: 30              # Managed databases change less frequently
        
        # Zone optimization (reduces cross-zone charges)
        zone_aware: true
        zone_weight: 25                       # Same-zone preference
        zone_latency_threshold: 30000         # 30ms threshold for DB zones
        
        # Database connection settings
        connection_pooling: true
        connection_warming: 2
        connection_idle_timeout: 600          # Longer for DB connections
        
        servers:
            - database-cluster-ro.example.com:3306:1
```

### 🔒 Secure Managed Cache with TLS
```yaml
pools:
    secure_redis:
        listen: 127.0.0.1:6380
        redis: true
        
        latency_routing: true
        zone_aware: true
        cache_mode: true
        
        # TLS configuration
        tls_enabled: true                     # Enable encryption in transit
        tls_verify_peer: true                 # Verify certificates
        
        servers:
            - secure-cache-ro.example.com:6380:1
```

See `conf/cloud-*.yml` for complete examples.

---

## Configuration Options

### Core Latency-Based Routing

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `latency_routing` | boolean | `false` | Enable latency-based server selection |
| `dns_resolve_interval` | integer | `30` | DNS re-resolution interval (seconds) |
| `latency_weight` | integer | `80` | Percentage of traffic to lowest latency server (0-100) |

### Cloud Multi-Zone Optimizations

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `zone_aware` | boolean | `false` | Enable zone aware routing (latency-based) |
| `zone_weight` | integer | `25` | Extra weight bonus for same-zone servers (0-100) |
| `zone_latency_threshold` | integer | `50000` | Latency threshold for zone detection (microseconds) |
| `cache_mode` | boolean | `false` | Enable managed cache service optimizations |

### Connection Management

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `connection_pooling` | boolean | `false` | Enable connection pooling |
| `connection_warming` | integer | `0` | Number of connections to pre-warm |
| `connection_idle_timeout` | integer | `300` | Close idle connections after N seconds |

### Enhanced Health Monitoring

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dns_failure_threshold` | integer | `3` | Failures before marking server unhealthy |
| `dns_cache_negative_ttl` | integer | `30` | Negative DNS cache TTL (seconds) |

### Security & Encryption

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tls_enabled` | boolean | `false` | Enable TLS encryption |
| `tls_verify_peer` | boolean | `true` | Verify TLS peer certificates |

### Traffic Distribution Examples

**Example 1: Pure Latency-Based (100% to fastest)**
```yaml
latency_routing: true
latency_weight: 100    # All traffic to fastest server
```
*With 6 servers: 100% → Server A (fastest), 0% → all others*

**Example 2: Balanced Load Distribution (50/50 split)**
```yaml
latency_routing: true  
latency_weight: 50     # 50% to fastest, 50% split among all others
```
*With 6 servers: 50% → Server A (fastest), 10% each → Servers B,C,D,E,F*

**Example 3: Zone-Aware Distribution**
```yaml
latency_routing: true
latency_weight: 60
zone_aware: true
zone_weight: 30              # Same-zone servers get +30% weight bonus
zone_latency_threshold: 50000 # 50ms threshold for zone detection
```
*Result: Same-zone servers are preferred, but all healthy servers are used*

**Example 4: Managed Cache Optimized**
```yaml
latency_routing: true
latency_weight: 70
zone_aware: true
cache_mode: true
dns_resolve_interval: 15    # Frequent updates for scaling
```
*Result: 70% → fastest server, 30% distributed, with managed cache optimizations*

**Example 5: Cost-Optimized (Minimize Cross-Zone Transfer)**
```yaml
latency_routing: true
latency_weight: 40     # More distributed traffic
zone_aware: true
zone_weight: 60        # Strong same-zone preference
```
*Result: Strongly favors same-zone to reduce data transfer costs*

---

## How It Works

### Core Engine
1. **DNS Discovery**: Automatically resolves hostnames with `-ro` suffix to discover read replicas
2. **Latency Measurement**: Measures connection latency during normal operations  
3. **Health Monitoring**: Tracks failures per server and excludes unhealthy ones
4. **Smart Routing**: Routes traffic based on configured weight distribution
5. **Automatic Updates**: Re-resolves DNS periodically to discover topology changes

### Cloud Zone Intelligence
6. **Zone Detection**: Analyzes latency patterns to automatically detect zones (no metadata required)
7. **Zone Clustering**: Groups servers with similar latency into the same zone
8. **Cost Optimization**: Calculates route costs considering same-zone vs cross-zone data transfer
9. **Cache Integration**: Recognizes managed cache endpoints and optimizes DNS resolution intervals
10. **Health Scoring**: Advanced health checks considering latency thresholds and failure patterns

### Server Selection Logic
- Servers with >3 recent failures are excluded from routing
- **`latency_weight%`** of traffic goes to the **lowest latency server**
- **Remaining `(100-latency_weight)%`** is **equally distributed** among **all other healthy servers**
- When new servers are discovered via DNS, they automatically join the routing pool
- Seamless failover when servers become unavailable

---

## Traditional Configuration

All original twemproxy features are still supported:

```yaml
pools:
    example:
        listen: 127.0.0.1:22121
        hash: fnv1a_64
        distribution: ketama
        auto_eject_hosts: true
        redis: true
        timeout: 400
        server_retry_timeout: 2000
        server_failure_limit: 1
        servers:
         - 127.0.0.1:6379:1
         - 127.0.0.1:6380:1
```

### Core Configuration Options

+ **listen**: The listening address and port (name:port or ip:port) for this server pool
+ **redis**: A boolean value that controls if a server pool speaks redis protocol. Defaults to false.
+ **hash**: The name of the hash function (one_at_a_time, md5, crc16, crc32, fnv1_64, fnv1a_64, etc.)
+ **distribution**: The key distribution mode (ketama, modula, random)
+ **timeout**: The timeout value in msec for server connections
+ **auto_eject_hosts**: Automatically eject failed servers temporarily
+ **server_retry_timeout**: Timeout before retrying ejected servers (msec)
+ **server_failure_limit**: Number of failures before ejecting a server
+ **servers**: List of server address, port and weight (name:port:weight or ip:port:weight)

---

## Command Line Usage

```
Usage: nutcracker [-?hVdDt] [-v verbosity level] [-o output file]
                  [-c conf file] [-s stats port] [-a stats addr]
                  [-i stats interval] [-p pid file] [-m mbuf size]

Options:
  -h, --help             : this help
  -V, --version          : show version and exit
  -t, --test-conf        : test configuration for syntax errors and exit
  -d, --daemonize        : run as a daemon
  -v, --verbose=N        : set logging level (default: 5, min: 0, max: 11)
  -c, --conf-file=S      : set configuration file (default: conf/nutcracker.yml)
  -s, --stats-port=N     : set stats monitoring port (default: 22222)
```

---

## Monitoring & Observability

### Stats Endpoint
Access runtime statistics on port 22222 (default):
```bash
curl http://localhost:22222
```

### Logging
Enable detailed logging to monitor latency-based routing:
```bash
nutcracker -c nutcracker.yml -v 6 -o /var/log/nutcracker.log
```

Look for log entries like:
```
[timestamp] selected best address 0 for 'server' (latency: 15000us, failures: 0, weight: 80%)
[timestamp] resolved 'redis-cluster-ro.amazonaws.com' to 3 addresses  
[timestamp] weighted routing: selected second-best address 1 for 'server' (latency: 18000us)
```

---

## License

Copyright 2012 Twitter, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0