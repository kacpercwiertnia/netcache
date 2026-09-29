#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.request

from client_api import NetCacheClient


def bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def csv_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def workload_entries(args: argparse.Namespace) -> list[dict[str, str]]:
    raw = json.loads(args.entries) if args.entries else None
    if raw is None:
        return [{"key": key, "value": args.value} for key in args.keys]
    if not isinstance(raw, list) or not raw:
        raise ValueError("Client entries must be a non-empty list")
    return [{"key": str(entry["key"]), "value": str(entry["value"])} for entry in raw]


def value_for_key(args, key):
    if not hasattr(args, "entry_values"):
        args.entry_values = {entry["key"]: entry["value"] for entry in workload_entries(args)}
    return args.entry_values[key]


def control_entries(args: argparse.Namespace) -> list[dict[str, str]]:
    if args.control_entries:
        raw = json.loads(args.control_entries)
        if isinstance(raw, dict):
            raw = raw.get("entries", [])
        return [
            {"key": str(item["key"]), "value": str(item["value"])}
            for item in raw
        ]
    return workload_entries(args)


def install_control_entries(args: argparse.Namespace) -> None:
    if not args.switch_control_url:
        return
    payload = {"entries": control_entries(args)}
    url = args.switch_control_url.rstrip("/") + "/cache/entries"
    data = json.dumps(payload).encode("utf-8")
    last_error: BaseException | None = None
    for attempt in range(1, args.switch_control_retries + 1):
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=args.switch_control_timeout_seconds) as response:
                body = response.read().decode("utf-8")
            print(f"[netcache-client] control insert response: {body}")
            return
        except Exception as exc:
            last_error = exc
            if attempt >= args.switch_control_retries:
                break
            delay = min(2.0 * attempt, 10.0)
            print(
                f"[netcache-client] control insert attempt {attempt}/{args.switch_control_retries} failed: "
                f"{type(exc).__name__}: {exc}; retrying in {delay:.1f}s",
                flush=True,
            )
            time.sleep(delay)
    assert last_error is not None
    raise last_error


def prime_backend_entries(args: argparse.Namespace, client: NetCacheClient) -> int:
    if not args.prime_backend or args.op != "read":
        return 0
    failures = 0
    for key in args.keys:
        print(f"[netcache-client] prime backend key={key}")
        if not client.put(key, value_for_key(args, key)):
            failures += 1
    return failures


class RedisClient:
    def __init__(self, host: str, port: int = 6379, timeout: float = 5.0, retries: int = 12) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries

    def _encode(self, *parts: str) -> bytes:
        encoded = [f"*{len(parts)}\r\n".encode()]
        for part in parts:
            data = str(part).encode()
            encoded.append(f"${len(data)}\r\n".encode())
            encoded.append(data + b"\r\n")
        return b"".join(encoded)

    def _read_line(self, sock: socket.socket) -> bytes:
        chunks: list[bytes] = []
        while True:
            byte = sock.recv(1)
            if not byte:
                raise ConnectionError("Redis connection closed")
            chunks.append(byte)
            if len(chunks) >= 2 and chunks[-2:] == [b"\r", b"\n"]:
                return b"".join(chunks[:-2])

    def _read_response(self, sock: socket.socket):
        prefix = sock.recv(1)
        if prefix == b"+":
            return self._read_line(sock).decode()
        if prefix == b"-":
            raise RuntimeError(self._read_line(sock).decode())
        if prefix == b":":
            return int(self._read_line(sock))
        if prefix == b"$":
            length = int(self._read_line(sock))
            if length == -1:
                return None
            data = b""
            while len(data) < length:
                data += sock.recv(length - len(data))
            sock.recv(2)
            return data.decode()
        raise RuntimeError(f"Unsupported Redis response prefix: {prefix!r}")

    def command(self, *parts: str):
        last_error: OSError | None = None
        for attempt in range(1, self.retries + 1):
            try:
                with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                    sock.sendall(self._encode(*parts))
                    return self._read_response(sock)
            except OSError as exc:
                last_error = exc
                print(
                    f"[redis-client] connection attempt {attempt}/{self.retries} failed: {exc}",
                    file=sys.stderr,
                )
                time.sleep(1)
        raise TimeoutError(f"Could not connect to Redis at {self.host}:{self.port}") from last_error

    def read(self, key: str):
        value = self.command("GET", key)
        print("(nil)" if value is None else value)
        return value

    def put(self, key: str, value: str):
        result = self.command("SET", key, value)
        print(result)
        return result

    def delete(self, key: str):
        result = self.command("DEL", key)
        print(result)
        return result


def run_redis_client(args: argparse.Namespace) -> int:
    client = RedisClient(args.redis_host, args.redis_port, retries=args.redis_retries)
    if args.op == "read":
        for entry in workload_entries(args):
            client.put(entry["key"], entry["value"])

    for iteration in range(args.repeat):
        for key in args.keys:
            if args.op == "read":
                print(f"[redis-client] read key={key} iteration={iteration + 1}")
                client.read(key)
            elif args.op == "put":
                print(f"[redis-client] put key={key} iteration={iteration + 1}")
                client.put(key, value_for_key(args, key))
            elif args.op == "delete":
                print(f"[redis-client] delete key={key} iteration={iteration + 1}")
                client.delete(key)
            elif args.op == "put-read":
                print(f"[redis-client] put-read key={key} iteration={iteration + 1}")
                client.put(key, value_for_key(args, key))
                client.read(key)
            else:
                print(f"Unsupported Redis operation: {args.op}", file=sys.stderr)
                return 2

        if args.sleep_seconds > 0 and iteration + 1 < args.repeat:
            time.sleep(args.sleep_seconds)

    return 0


def run_client(args: argparse.Namespace) -> int:
    client = NetCacheClient(n_servers=args.servers, no_cache=args.disable_cache)
    failures = prime_backend_entries(args, client)
    install_control_entries(args)

    for iteration in range(args.repeat):
        for key in args.keys:
            if args.op == "read":
                print(f"[netcache-client] read key={key} iteration={iteration + 1}")
                if not client.read(key):
                    failures += 1
            elif args.op == "put":
                print(f"[netcache-client] put key={key} iteration={iteration + 1}")
                if not client.put(key, value_for_key(args, key)):
                    failures += 1
            elif args.op == "delete":
                print(f"[netcache-client] delete key={key} iteration={iteration + 1}")
                client.delete(key)
            elif args.op == "put-read":
                print(f"[netcache-client] put-read key={key} iteration={iteration + 1}")
                if not client.put(key, value_for_key(args, key)):
                    failures += 1
                if not client.read(key):
                    failures += 1
            else:
                print(f"Unsupported operation: {args.op}", file=sys.stderr)
                return 2

        if args.sleep_seconds > 0 and iteration + 1 < args.repeat:
            time.sleep(args.sleep_seconds)

    if args.metrics:
        client.request_metrics_report()

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a small NetCache client workload.")
    parser.add_argument(
        "--backend",
        choices=["netcache", "redis"],
        default=os.environ.get("NETCACHE_CLIENT_BACKEND", "netcache"),
    )
    parser.add_argument(
        "--op",
        choices=["read", "put", "delete", "put-read"],
        default=os.environ.get("NETCACHE_CLIENT_OP", "read"),
    )
    parser.add_argument(
        "--keys",
        nargs="+",
        default=csv_values(os.environ.get("NETCACHE_CLIENT_KEYS", "one,two,three")),
    )
    parser.add_argument(
        "--value",
        default=os.environ.get("NETCACHE_CLIENT_VALUE", "netcache-client-value"),
    )
    parser.add_argument(
        "--servers",
        type=int,
        default=int(os.environ.get("NETCACHE_CLIENT_SERVERS", "1")),
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=int(os.environ.get("NETCACHE_CLIENT_REPEAT", "1")),
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=float(os.environ.get("NETCACHE_CLIENT_SLEEP_SECONDS", "0")),
    )
    parser.add_argument(
        "--disable-cache",
        action="store_true",
        default=bool_env("NETCACHE_CLIENT_DISABLE_CACHE", False),
    )
    parser.add_argument(
        "--metrics",
        action="store_true",
        default=bool_env("NETCACHE_CLIENT_METRICS", False),
    )
    parser.add_argument(
        "--prime-backend",
        action="store_true",
        default=bool_env("NETCACHE_PRIME_BACKEND", False),
    )
    parser.add_argument(
        "--switch-control-url",
        default=os.environ.get("NETCACHE_SWITCH_CONTROL_URL", ""),
    )
    parser.add_argument(
        "--switch-control-timeout-seconds",
        type=float,
        default=float(os.environ.get("NETCACHE_SWITCH_CONTROL_TIMEOUT_SECONDS", "10")),
    )
    parser.add_argument(
        "--switch-control-retries",
        type=int,
        default=int(os.environ.get("NETCACHE_SWITCH_CONTROL_RETRIES", "3")),
    )
    parser.add_argument(
        "--control-entries",
        default=os.environ.get("NETCACHE_CONTROL_ENTRIES", ""),
    )
    parser.add_argument(
        "--redis-host",
        default=os.environ.get("REDIS_HOST", "127.0.0.1"),
    )
    parser.add_argument(
        "--redis-port",
        type=int,
        default=int(os.environ.get("REDIS_PORT", "6379")),
    )
    parser.add_argument(
        "--redis-retries",
        type=int,
        default=int(os.environ.get("REDIS_RETRIES", "12")),
    )
    parser.add_argument("--entries", default=os.environ.get("NETCACHE_CLIENT_ENTRIES", ""))
    args = parser.parse_args()
    args.keys = [entry["key"] for entry in workload_entries(args)]
    if args.backend == "redis":
        return run_redis_client(args)
    return run_client(args)


if __name__ == "__main__":
    raise SystemExit(main())
