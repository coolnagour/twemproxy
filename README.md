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
        dns_expiration_minutes: 5   # Expire addresses after 5 minutes of not appearing in DNS (AWS DNS lookups to the readonly endpoint gives different responses, rotating each node on each response)

        servers:
            - my-redis-ro.cache.amazonaws.com:6379:1
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

To view DNS host details for a specific server:
```bash
curl -s http://localhost:22222 | jq .[0].pools.redis_read.servers[].dns_hosts
```

To monitor all resolved IPs and their health:
```bash
curl -s http://localhost:22222 | jq .[0].pools.redis_read.servers[].dns_hosts.address_details
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

### DNS and Zone Statistics

Monitor zone routing effectiveness and DNS resolution:
- `dns_addresses` - Number of resolved IP addresses
- `dns_resolves` - Total DNS resolution attempts
- `dns_failures` - Failed DNS resolution attempts
- `last_dns_resolved_at` - Timestamp of last DNS resolution
- `same_zone_selections` - Times same-zone server was selected
- `cross_zone_selections` - Times cross-zone server was selected  
- `zones_detected` - Number of zones detected
- `current_latency_us` - Current connection latency

### Detailed DNS Host Information

Each server now includes a `dns_hosts` field with comprehensive details:

```json
{
  "dns_hosts": {
    "type": "dynamic",
    "hostname": "staging-api-ro.cache.amazonaws.com",
    "dns_resolve_interval": 30,
    "last_resolved": 1750079179689290,
    "addresses": 4,
    "current_address": 0,
    "zone_aware": true,
    "zone_weight_percent": 95,
    "zones_detected": 2,
    "same_zone_servers": 1,
    "cross_zone_servers": 3,
    "address_details": [
      {
        "index": 0,
        "ip": "10.1.2.3",
        "latency_us": 12000,
        "failures": 0,
        "zone_id": 1,
        "zone_type": "same-az",
        "zone_weight": 95,
        "healthy": true,
        "current": true
      },
      {
        "index": 1,
        "ip": "10.1.3.4", 
        "latency_us": 45000,
        "failures": 0,
        "zone_id": 2,
        "zone_type": "cross-az",
        "zone_weight": 5,
        "healthy": true,
        "current": false
      }
    ]
  }
}
```

**DNS Host Fields Explained**:
- `type` - "dynamic" for DNS-resolved servers, "static" for fixed IPs
- `hostname` - The DNS name being resolved
- `dns_resolve_interval` - How often DNS is re-resolved (seconds)
- `last_resolved` - Unix timestamp of last DNS resolution
- `addresses` - Total number of resolved IP addresses
- `current_address` - Index of currently selected IP address
- `zone_aware` - Whether zone-aware routing is enabled
- `zone_weight_percent` - Percentage preference for same-zone servers
- `zones_detected` - Number of latency-based zones identified
- `same_zone_servers` - Count of servers in the local zone
- `cross_zone_servers` - Count of servers in remote zones

**Per-Address Details**:
- `index` - Array index of this IP address
- `ip` - The resolved IP address
- `latency_us` - Current measured latency in microseconds
- `failures` - Number of recent connection failures
- `zone_id` - Automatically assigned zone identifier
- `zone_type` - "same-az" or "cross-az" classification
- `zone_weight` - Routing weight percentage for this address
- `healthy` - Whether this address is considered healthy
- `current` - Whether this is the currently selected address

---

## Health Checks & Automatic Recovery

### How Health Monitoring Works

Twemproxy uses **passive health monitoring** - it doesn't send active PING commands or connection probes to Redis servers. Instead, health is determined by monitoring actual client request failures and successes.

**Health Check Process:**
- ✅ **Successful requests** → `server_ok()` → Reset failure count to 0
- ❌ **Failed requests** → `server_failure()` → Increment failure count
- 🚫 **Server ejection** → When failures exceed `server_failure_limit`
- 🔄 **Automatic retry** → After `server_retry_timeout` period

### Automatic Recovery Example

When a Redis server gets rebooted or temporarily fails:

1. **Failure Detection** (immediate)
   - Client requests start failing against the server
   - Failure count increments with each failed request
   - Server gets ejected when failures exceed `server_failure_limit`

2. **Ejection Period** (configurable)
   - Server is removed from active rotation
   - No client traffic sent to failed server
   - Duration controlled by `server_retry_timeout`

3. **Automatic Recovery** (seamless)
   - After timeout expires, twemproxy automatically retries the server
   - First successful request resets failure count to 0
   - Server immediately returns to active rotation

### Configuration Example

```yaml
pools:
    read:
        server_retry_timeout: 10000    # Retry failed servers after 10 seconds
        server_failure_limit: 1        # Eject server after 1 failure
        auto_eject_hosts: true         # Enable automatic ejection/recovery
```

**Result**: A server that gets rebooted will be out of rotation for only 10 seconds, then automatically rejoin once healthy.

### Enhanced Recovery for Dynamic DNS

With accumulative DNS resolution (`dns_expiration_minutes`), recovery is even more resilient:

- 📍 **IP addresses persist** in the address list even during outages
- 🏥 **Health tracking** per individual IP address
- ⏰ **Smart expiration** - only remove IPs that are both unhealthy AND not seen in DNS
- 🔄 **Instant recovery** - healthy servers immediately resume receiving traffic

### Health Check Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `auto_eject_hosts` | `false` | Enable automatic server ejection and recovery |
| `server_failure_limit` | `2` | Number of failures before ejecting server |
| `server_retry_timeout` | `30000` | Milliseconds before retrying ejected server |
| `dns_expiration_minutes` | `5` | Minutes to keep IPs not seen in DNS (if healthy) |
| `dns_health_check_interval` | `30` | Seconds between health analysis cycles |

**💡 Pro Tip**: Set `server_failure_limit: 1` and `server_retry_timeout: 10000` for fast failover and recovery in high-availability setups.

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
Copyright 2024-2025 coolnagour

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0