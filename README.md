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

## Docker Quick Start

### Using Docker Compose (Recommended)

1. **Clone and build**:
```bash
git clone https://github.com/coolnagour/twemproxy.git
cd twemproxy
```

2. **Copy example configuration**:
```bash
cp docker-compose.example.yml docker-compose.yml
```

3. **Configure your Redis endpoints**:
```yaml
# docker-compose.yml
services:
  twemproxy:
    environment:
      READ_HOST: "your-redis-ro.cache.amazonaws.com:6379"
      WRITE_HOST: "your-redis-primary.cache.amazonaws.com:6379"
      ZONE_WEIGHT: "95"  # 95% same-AZ traffic
```

4. **Start the services**:
```bash
docker-compose up -d
```

5. **Check status and stats**:
```bash
# View logs
docker-compose logs twemproxy

# Check stats endpoint
curl http://localhost:22222

# Test Redis connections
redis-cli -p 6378 ping  # Read pool
redis-cli -p 6379 ping  # Write pool
```

### Docker Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `READ_HOST` | `redis-read:6379` | Redis read replica endpoint |
| `WRITE_HOST` | `redis-write:6379` | Redis primary write endpoint |
| `ZONE_WEIGHT` | `95` | Percentage preference for same-zone servers |
| `DNS_RESOLVE_INTERVAL` | `30` | DNS re-resolution interval (seconds) |
| `DNS_EXPIRATION_MINUTES` | `5` | Minutes to keep addresses not seen in DNS |
| `DNS_HEALTH_CHECK_INTERVAL` | `30` | Health check interval (seconds) |
| `CONNECTION_POOLING` | `true` | Enable connection pooling (`true`/`false`) |
| `CONNECTION_WARMING` | `1` | Number of connections to pre-warm |
| `SERVER_CONNECTIONS` | `1` | Maximum connections per server |
| `CONNECTION_MAX_LIFETIME` | `900` | Force close connections after N seconds (triggers re-selection) |
| `DYNAMIC_SERVER_CONNECTIONS` | `false` | Auto-scale connections based on DNS addresses |
| `MAX_SERVER_CONNECTIONS` | `10` | Maximum limit for dynamic connection scaling |

### Docker Build and Run

```bash
# Build the image
docker build -t twemproxy-enhanced .

# Run with custom configuration
docker run -d \
  --name twemproxy \
  -p 6378:6378 \
  -p 6379:6379 \
  -p 22222:22222 \
  -e READ_HOST="my-redis-ro.amazonaws.com:6379" \
  -e WRITE_HOST="my-redis-primary.amazonaws.com:6379" \
  -e ZONE_WEIGHT="99" \
  twemproxy-enhanced
```

### AWS ElastiCache Example

```yaml
# docker-compose.yml for AWS ElastiCache
version: '3.8'
services:
  twemproxy:
    build: .
    ports:
      - "6378:6378"
      - "6379:6379" 
      - "22222:22222"
    environment:
      READ_HOST: "my-cluster-ro.abc123.ng.0001.use1.cache.amazonaws.com:6379"
      WRITE_HOST: "my-cluster.abc123.ng.0001.use1.cache.amazonaws.com:6379"
      ZONE_WEIGHT: "100"  # Prefer same-AZ, failover to cross-AZ when needed
      DNS_RESOLVE_INTERVAL: "15"  # More frequent DNS checks for ElastiCache
    restart: unless-stopped
```

**Result**: Automatic cost-optimized routing with seamless failover!

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
=======
# changes on top of original twempproxy

Config can be reloaded by running `sudo pkill -1 nutcracker` to send a SIGHUP


If you are using AWS with read only endpoints (url contains `-ro`) then you can use configUpdater.php in a cron job to keep the config file up to date with all the DNS records behind this reader endpoint. 

Normally the read only endpoint is behind round robin DNS with a TTL of about 15 seconds, meaning if you added the read only endpoint many times in the config file hoping to use all reader endpoints, you will end up connecting to the same reader endpoint multiple times and the load will not distribute.


# twemproxy (nutcracker) [![Build Status](https://secure.travis-ci.org/twitter/twemproxy.png)](http://travis-ci.org/twitter/twemproxy)

twemproxy is a multi-process, fast and lightweight proxy for [memcached](http://www.memcached.org/) and [redis](http://redis.io/) protocol.
It was built primarily to reduce the number of connections to the caching servers on the backend.
This, together with protocol pipelining and sharding enables you to horizontally scale your distributed caching architecture.

This is a fork of `twitter/twemproxy` to support *multi-process* and *hot-reload* features. All the developments happen
on the `develop` branch, so we could use the master to track the upstream changes and backporting.

The `develop` branch is quite stable, it's been used on the production servers at *Meitu Inc.* and reliably weathers the storm for over a year.

## Build

To build twemproxy from [distribution tarball](https://drive.google.com/open?id=0B6pVMMV5F5dfMUdJV25abllhUWM&authuser=0):

    $ ./configure
    $ make
    $ sudo make install

To build twemproxy from [distribution tarball](https://drive.google.com/open?id=0B6pVMMV5F5dfMUdJV25abllhUWM&authuser=0) in _debug mode_:

    $ CFLAGS="-ggdb3 -O0" ./configure --enable-debug=full
    $ make
    $ sudo make install

To build twemproxy from source with _debug logs enabled_ and _assertions enabled_:

    $ git clone git@github.com:twitter/twemproxy.git
    $ cd twemproxy
    $ autoreconf -fvi
    $ ./configure --enable-debug=full
    $ make
    $ src/nutcracker -h

A quick checklist:

+ Use newer version of gcc (older version of gcc has problems)
+ Use CFLAGS="-O1" ./configure && make
+ Use CFLAGS="-O3 -fno-strict-aliasing" ./configure && make
+ `autoreconf -fvi && ./configure` needs `automake` and `libtool` to be installed

## Features

* Supports master-worker's process mode(NEW)
* Supports reload config in runtime(NEW)
* Supports split read/write in redis master-slave(NEW)

+ Fast.
+ Lightweight.
+ Maintains persistent server connections.
+ Keeps connection count on the backend caching servers low.
+ Enables pipelining of requests and responses.
+ Supports proxying to multiple servers.
+ Supports multiple server pools simultaneously.
+ Shard data automatically across multiple servers.
+ Implements the complete [memcached ascii](notes/memcache.md) and [redis](notes/redis.md) protocol.
+ Easy configuration of server pools through a YAML file.
+ Supports multiple hashing modes including consistent hashing and distribution.
+ Can be configured to disable nodes on failures.
+ Observability via stats exposed on the stats monitoring port.
+ Works with Linux, \*BSD, OS X and SmartOS (Solaris)

## Help

    Usage: nutcracker [-?hVdDt] [-v verbosity level] [-o output file]
                      [-c conf file] [-s stats port] [-a stats addr]
                      [-i stats interval] [-p pid file] [-m mbuf size]

    Options:
      -h, --help             : this help
      -V, --version          : show version and exit
      -t, --test-conf        : test configuration for syntax errors and exit
      -d, --daemonize        : run as a daemon
      -D, --describe-stats   : print stats description and exit
      -v, --verbose=N        : set logging level (default: 5, min: 0, max: 11)
      -o, --output=S         : set logging file (default: stderr)
      -c, --conf-file=S      : set configuration file (default: conf/nutcracker.yml)
      -s, --stats-port=N     : set stats monitoring port (default: 22222)
      -a, --stats-addr=S     : set stats monitoring ip (default: 0.0.0.0)
      -i, --stats-interval=N : set stats aggregation interval in msec (default: 30000 msec)
      -p, --pid-file=S       : set pid file (default: off)
      -m, --mbuf-size=N      : set size of mbuf chunk in bytes (default: 16384 bytes)

## Zero Copy

In twemproxy, all the memory for incoming requests and outgoing responses is allocated in mbuf. Mbuf enables zero-copy because the same buffer on which a request was received from the client is used for forwarding it to the server. Similarly the same mbuf on which a response was received from the server is used for forwarding it to the client.

Furthermore, memory for mbufs is managed using a reuse pool. This means that once mbuf is allocated, it is not deallocated, but just put back into the reuse pool. By default each mbuf chunk is set to 16K bytes in size. There is a trade-off between the mbuf size and number of concurrent connections twemproxy can support. A large mbuf size reduces the number of read syscalls made by twemproxy when reading requests or responses. However, with a large mbuf size, every active connection would use up 16K bytes of buffer which might be an issue when twemproxy is handling large number of concurrent connections from clients. When twemproxy is meant to handle a large number of concurrent client connections, you should set chunk size to a small value like 512 bytes using the -m or --mbuf-size=N argument.

## Configuration

Twemproxy can be configured through a YAML file specified by the -c or --conf-file command-line argument on process start. The configuration file is used to specify the server pools and the servers within each pool that twemproxy manages. The configuration files parses and understands the following keys:

+ **listen**: The listening address and port (name:port or ip:port) or an absolute path to sock file (e.g. /var/run/nutcracker.sock) for this server pool.
+ **client_connections**: The maximum number of connections allowed from redis clients. Unlimited by default, though OS-imposed limitations will still apply.
+ **hash**: The name of the hash function. Possible values are:
 + one_at_a_time
 + md5
 + crc16
 + crc32 (crc32 implementation compatible with [libmemcached](http://libmemcached.org/))
 + crc32a (correct crc32 implementation as per the spec)
 + fnv1_64
 + fnv1a_64
 + fnv1_32
 + fnv1a_32
 + hsieh
 + murmur
 + jenkins
+ **hash_tag**: A two character string that specifies the part of the key used for hashing. Eg "{}" or "$$". [Hash tag](notes/recommendation.md#hash-tags) enable mapping different keys to the same server as long as the part of the key within the tag is the same.
+ **distribution**: The key distribution mode. Possible values are:
 + ketama
 + modula
 + random
+ **timeout**: The timeout value in msec that we wait for to establish a connection to the server or receive a response from a server. By default, we wait indefinitely.
+ **backlog**: The TCP backlog argument. Defaults to 512.
+ **preconnect**: A boolean value that controls if twemproxy should preconnect to all the servers in this pool on process start. Defaults to false.
+ **redis**: A boolean value that controls if a server pool speaks redis or memcached protocol. Defaults to false.
+ **redis_auth**: Authenticate to the Redis server on connect.
+ **redis_db**: The DB number to use on the pool servers. Defaults to 0. Note: Twemproxy will always present itself to clients as DB 0.
+ **server_connections**: The maximum number of connections that can be opened to each server. By default, we open at most 1 server connection.
+ **auto_eject_hosts**: A boolean value that controls if server should be ejected temporarily when it fails consecutively server_failure_limit times. See [liveness recommendations](notes/recommendation.md#liveness) for information. Defaults to false.
+ **server_retry_timeout**: The timeout value in msec to wait for before retrying on a temporarily ejected server, when auto_eject_host is set to true. Defaults to 30000 msec.
+ **server_failure_limit**: The number of consecutive failures on a server that would lead to it being temporarily ejected when auto_eject_host is set to true. Defaults to 2.
+ **servers**: A list of server address, port and weight (name:port:weight or ip:port:weight) for this server pool.


For example, the configuration file in [conf/nutcracker.yml](conf/nutcracker.yml), also shown below, configures 5 server pools with names - _alpha_, _beta_, _gamma_, _delta_ and omega. Clients that intend to send requests to one of the 10 servers in pool delta connect to port 22124 on 127.0.0.1. Clients that intend to send request to one of 2 servers in pool omega connect to unix path /tmp/gamma. Requests sent to pool alpha and omega have no timeout and might require timeout functionality to be implemented on the client side. On the other hand, requests sent to pool beta, gamma and delta timeout after 400 msec, 400 msec and 100 msec respectively when no response is received from the server. Of the 5 server pools, only pools alpha, gamma and delta are configured to use server ejection and hence are resilient to server failures. All the 5 server pools use ketama consistent hashing for key distribution with the key hasher for pools alpha, beta, gamma and delta set to fnv1a_64 while that for pool omega set to hsieh. Also only pool beta uses [nodes names](notes/recommendation.md#node-names-for-consistent-hashing) for consistent hashing, while pool alpha, gamma, delta and omega use 'host:port:weight' for consistent hashing. Finally, only pool alpha and beta can speak the redis protocol, while pool gamma, delta and omega speak memcached protocol.

    global:
        worker_processes: auto      # num of workers, fallback to single process model while worker_processes is 0
        max_openfiles: 102400       # max num of open files in every worker process
        user: nobody                # user of worker's process, master process should be setup with root
        group: nobody               # group of worker's process
        worker_shutdown_timeout: 30 # terminate the old worker after worker_shutdown_timeout, unit is second


    pools:
        alpha:
          listen: 127.0.0.1:22121
          hash: fnv1a_64
          distribution: ketama
          auto_eject_hosts: true
          redis: true
          server_retry_timeout: 2000
          server_failure_limit: 1
          servers:
           - 127.0.0.1:6379:1

        beta:
          listen: 127.0.0.1:22122
          hash: fnv1a_64
          hash_tag: "{}"
          distribution: ketama
          auto_eject_hosts: false
          timeout: 400
          redis: true
          servers:
           - 127.0.0.1:6380:1 server1
           - 127.0.0.1:6381:1 server2
           - 127.0.0.1:6382:1 server3
           - 127.0.0.1:6383:1 server4

        gamma:
          listen: 127.0.0.1:22123
          hash: fnv1a_64
          distribution: ketama
          timeout: 400
          backlog: 1024
          preconnect: true
          auto_eject_hosts: true
          server_retry_timeout: 2000
          server_failure_limit: 3
          servers:
           - 127.0.0.1:11212:1
           - 127.0.0.1:11213:1

        delta:
          listen: 127.0.0.1:22124
          hash: fnv1a_64
          distribution: ketama
          timeout: 100
          auto_eject_hosts: true
          server_retry_timeout: 2000
          server_failure_limit: 1
          servers:
           - 127.0.0.1:11214:1
           - 127.0.0.1:11215:1
           - 127.0.0.1:11216:1
           - 127.0.0.1:11217:1
           - 127.0.0.1:11218:1
           - 127.0.0.1:11219:1
           - 127.0.0.1:11220:1
           - 127.0.0.1:11221:1
           - 127.0.0.1:11222:1
           - 127.0.0.1:11223:1

        omega:
          listen: /tmp/gamma 0666
          hash: hsieh
          distribution: ketama
          auto_eject_hosts: false
          servers:
           - 127.0.0.1:11214:100000
           - 127.0.0.1:11215:1

Finally, to make writing a syntactically correct configuration file easier, twemproxy provides a command-line argument -t or --test-conf that can be used to test the YAML configuration file for any syntax error.

## Observability

Observability in twemproxy is through logs and stats.

Twemproxy exposes stats at the granularity of server pool and servers per pool through the stats monitoring port. The stats are essentially JSON formatted key-value pairs, with the keys corresponding to counter names. By default stats are exposed on port 22222 and aggregated every 30 seconds. Both these values can be configured on program start using the -c or --conf-file and -i or --stats-interval command-line arguments respectively. You can print the description of all stats exported by  using the -D or --describe-stats command-line argument.

    $ nutcracker --describe-stats

    pool stats:
      client_eof          "# eof on client connections"
      client_err          "# errors on client connections"
      client_connections  "# active client connections"
      server_ejects       "# times backend server was ejected"
      forward_error       "# times we encountered a forwarding error"
      fragments           "# fragments created from a multi-vector request"

    server stats:
      server_eof          "# eof on server connections"
      server_err          "# errors on server connections"
      server_timedout     "# timeouts on server connections"
      server_connections  "# active server connections"
      requests            "# requests"
      request_bytes       "total request bytes"
      responses           "# responses"
      response_bytes      "total response bytes"
      in_queue            "# requests in incoming queue"
      in_queue_bytes      "current request bytes in incoming queue"
      out_queue           "# requests in outgoing queue"
      out_queue_bytes     "current request bytes in outgoing queue"

Logging in twemproxy is only available when twemproxy is built with logging enabled. By default logs are written to stderr. Twemproxy can also be configured to write logs to a specific file through the -o or --output command-line argument. On a running twemproxy, we can turn log levels up and down by sending it SIGTTIN and SIGTTOU signals respectively and reopen log files by sending it SIGHUP signal.

## Pipelining

Twemproxy enables proxying multiple client connections onto one or few server connections. This architectural setup makes it ideal for pipelining requests and responses and hence saving on the round trip time.

For example, if twemproxy is proxying three client connections onto a single server and we get requests - 'get key\r\n', 'set key 0 0 3\r\nval\r\n' and 'delete key\r\n' on these three connections respectively, twemproxy would try to batch these requests and send them as a single message onto the server connection as 'get key\r\nset key 0 0 3\r\nval\r\ndelete key\r\n'.

Pipelining is the reason why twemproxy ends up doing better in terms of throughput even though it introduces an extra hop between the client and server.

## Deployment

If you are deploying twemproxy in production, you might consider reading through the [recommendation document](notes/recommendation.md) to understand the parameters you could tune in twemproxy to run it efficiently in the production environment.


## docker hub deployment
```
TAG=2.0.46
docker build -t twemproxy-enhanced .
docker tag twemproxy-enhanced:latest bobbymaher/twemproxy:$TAG
docker push bobbymaher/twemproxy:$TAG
docker push bobbymaher/twemproxy:latest
```

## License

Copyright 2012 Twitter, Inc.
Copyright 2024-2025 coolnagour

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0