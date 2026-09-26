# NetCache client image

Build from the `netcache` directory:

```sh
docker build -f Dockerfile.client -t docker.io/kacpercwiertnia/netcache-client:dev .
```

On Apple Silicon, publish an amd64 image for AWS nodes:

```sh
docker buildx build --platform linux/amd64 -f Dockerfile.client \
  -t docker.io/kacpercwiertnia/netcache-client:dev --push .
```

Example run:

```sh
docker run --rm \
  -e NETCACHE_SERVER_IPS=10.200.0.5 \
  -e NETCACHE_CLIENT_OP=read \
  -e NETCACHE_CLIENT_KEYS=one,two,three \
  docker.io/kacpercwiertnia/netcache-client:dev
```

Useful environment variables:

- `NETCACHE_SERVER_IPS`: comma-separated backend server IPs.
- `NETCACHE_CLIENT_OP`: `read`, `put`, `delete`, or `put-read`.
- `NETCACHE_CLIENT_KEYS`: comma-separated keys.
- `NETCACHE_CLIENT_VALUE`: value used by `put` and `put-read`.
- `NETCACHE_CLIENT_REPEAT`: number of workload repetitions.
- `NETCACHE_CLIENT_DISABLE_CACHE`: set to `true` to use the no-cache port.
- `NETCACHE_CLIENT_METRICS`: set to `true` to request server metrics after the workload.
- `NETCACHE_CLIENT_BACKEND`: `netcache` or `redis`.
- `REDIS_HOST`: Redis server IP when `NETCACHE_CLIENT_BACKEND=redis`.
- `REDIS_PORT`: Redis server port when `NETCACHE_CLIENT_BACKEND=redis`.
