# twemproxy (nutcracker) - Enhanced with Zone-Aware Routing

## 🚀 What's Different from Original Twemproxy?

This enhanced version adds **automatic zone-aware routing** for Redis caching, optimized specifically for cloud environments like AWS, GCP, and Azure. It automatically routes most traffic to same-availability-zone servers to reduce costs and latency.

### ✨ Key Features:
- **🌍 Automatic Zone Detection**: Intelligently groups servers by latency patterns (no manual configuration needed)
- **💰 Cost Optimization**: Routes most traffic to same-AZ servers to minimize cross-zone data transfer costs
- **🔄 Dynamic DNS Resolution**: Automatically discovers new/removed Redis servers without restarts
- **📊 Real-time Latency Measurement**: Continuously measures connection latency for intelligent routing
- **🛡️ Automatic Failover**: Seamlessly handles server failures and DNS changes
- **⚙️ Cache Optimized**: Built specifically for Redis/cache services (not databases)

---

## Quick Start

### Basic Same-AZ Configuration

```yaml
global:
    worker_processes: auto
    user: nobody
    group: nobody

pools:
    # Write pool (single primary)
    write:
        listen: 127.0.0.1:6379
        redis: true
        auto_eject_hosts: true
        timeout: 2000
        server_retry_timeout: 1000
        server_failure_limit: 5
        servers:
            - my-redis-primary.cache.amazonaws.com:6379:1

    # Read pool with zone-aware routing
    read:
        listen: 127.0.0.1:6378
        redis: true
        auto_eject_hosts: true
        timeout: 2000
        server_retry_timeout: 10000
        server_failure_limit: 1

        # Zone-aware routing - sends 99% traffic to same-AZ
        zone_aware: true
        zone_weight: 99             # 99% preference for same-AZ servers
        dns_resolve_interval: 30    # Re-check DNS every 30 seconds

        servers:
            - my-redis-ro.cache.amazonaws.com:6379:1
```

### Real-World AWS ElastiCache Example

```yaml
global:
    worker_processes: auto
    max_openfiles: 102400
    user: nobody
    group: nobody
    worker_shutdown_timeout: 30

pools:
    write:
        listen: 127.0.0.1:6379
        auto_eject_hosts: true
        redis: true
        timeout: 2000
        server_retry_timeout: 1000
        server_failure_limit: 5
        server_connections: 1
        servers:
            - staging-dispatch-api.qfjk8t.ng.0001.euw1.cache.amazonaws.com:6379:1

    read:
        listen: 127.0.0.1:6378
        distribution: ketama
        auto_eject_hosts: true
        redis: true
        timeout: 2000
        server_retry_timeout: 10000
        server_failure_limit: 1
        server_connections: 1

        # Zone-aware routing for cost optimization
        zone_aware: true
        zone_weight: 95             # 95% to same-AZ, 5% distributed
        dns_resolve_interval: 30

        servers:
            - staging-dispatch-api-ro.qfjk8t.ng.0001.euw1.cache.amazonaws.com:6379:1
```

---

## Configuration Reference

### Zone-Aware Routing

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `zone_aware` | boolean | `false` | Enable automatic zone detection and routing |
| `zone_weight` | integer | `25` | Percentage preference for same-zone servers (0-100) |
| `dns_resolve_interval` | integer | `30` | DNS re-resolution interval (seconds) |

### Connection Management

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `connection_pooling` | boolean | `false` | Enable connection pooling |
| `connection_warming` | integer | `0` | Number of connections to pre-warm |
| `connection_idle_timeout` | integer | `300` | Close idle connections after N seconds |

### Health & Monitoring

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dns_failure_threshold` | integer | `3` | Failures before marking server unhealthy |
| `dns_cache_negative_ttl` | integer | `30` | Negative DNS cache TTL (seconds) |

### Security & Encryption

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tls_enabled` | boolean | `false` | Enable TLS encryption |
| `tls_verify_peer` | boolean | `true` | Verify TLS peer certificates |

---

## Zone Weight Examples

### Cost-Optimized (Minimal Cross-AZ Traffic)
```yaml
zone_aware: true
zone_weight: 99    # 99% same-AZ, 1% cross-AZ
```
*Minimizes data transfer costs*

### Balanced Performance/Cost
```yaml
zone_aware: true
zone_weight: 70    # 70% same-AZ, 30% distributed
```
*Good balance of cost savings and load distribution*

### High Availability Focus
```yaml
zone_aware: true
zone_weight: 40    # 40% same-AZ, 60% distributed
```
*Ensures good cross-AZ utilization*

---

## How Zone Detection Works

1. **Automatic Discovery**: Resolves DNS to discover all server IPs
2. **Latency Measurement**: Measures actual connection latency to each server
3. **Statistical Analysis**: Groups servers using latency outlier detection
   - Servers with latency ≤ (min + 25% of range) = "same zone"
   - Other servers = "cross zone"
4. **Intelligent Routing**: Routes configured percentage to same-zone servers
5. **Continuous Monitoring**: Re-analyzes zones every 2 minutes

### No Manual Configuration Needed!
- No need to specify zone IDs or latency thresholds
- Automatically adapts to your infrastructure
- Works with AWS, GCP, Azure, and any cloud provider

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
Enable detailed logging to monitor zone-aware routing:
```bash
nutcracker -c nutcracker.yml -v 6 -o /var/log/nutcracker.log
```

Look for log entries like:
```
[timestamp] 🌍 auto-detected 2 zones for server 'redis-ro.example.com' (low-latency threshold: 15000us)
[timestamp] → selected SAME-ZONE address 0 for 'redis-ro.example.com' (latency: 12000us, zone: 1)
[timestamp] → selected DISTRIBUTED address 2 for 'redis-ro.example.com' (latency: 45000us, zone: 2)
```

### Zone Statistics
Monitor zone routing effectiveness:
- `same_zone_selections` - Times same-zone server was selected
- `cross_zone_selections` - Times cross-zone server was selected  
- `zones_detected` - Number of zones detected
- `current_latency_us` - Current connection latency

---

## Use Cases

### AWS ElastiCache
- **Primary use case**: Route traffic to read replicas in same AZ
- **Cost savings**: Eliminate cross-AZ data transfer charges
- **Performance**: Reduce latency with same-AZ routing

### Multi-Region Caching
- **Global distribution**: Intelligent routing across regions
- **Automatic failover**: Cross-region backup when local region fails
- **Cost optimization**: Prefer local region, fallback to others

### Container Orchestration
- **Kubernetes**: Automatic zone detection within clusters
- **Docker Swarm**: Cross-node intelligent routing
- **Auto-scaling**: Adapts as cache nodes are added/removed

---

## License

Copyright 2012 Twitter, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0