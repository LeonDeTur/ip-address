
#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

import dns.resolver
import dns.exception


DNS_SERVERS = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "77.88.8.8",
]

DNS_TIMEOUT = 3.0
MAX_WORKERS = 20
MAX_LINES = 1024

DEFAULT_PREFIX = 24
DEFAULT_GATEWAY = "0.0.0.0"

ROUTE_PATTERN = re.compile(
    r"route\s+add\s+(\S+)\s+mask\s+(\S+)\s+(\S+)",
    re.IGNORECASE,
)


class IPv4ListLimitExceeded(Exception):
    pass


class DNSResolutionError(Exception):
    pass


# ============================================================
# PATHS
# ============================================================

def get_content_root(value):
    if value is None:
        return None

    return (Path.cwd() / value).expanduser().resolve()


def get_output_path(root, value):
    path = Path(value).expanduser()

    if root is None:
        if not path.is_absolute():
            raise ValueError(
                f"Without --content-root, an absolute "
                f"output path is required: {value}"
            )
        return path.resolve()

    if path.is_absolute():
        raise ValueError(
            f"Output path must be relative to content-root: {value}"
        )

    target = (root / path).resolve()

    if not target.is_relative_to(root) or target == root:
        raise ValueError(f"Invalid output path: {value}")

    return target


# ============================================================
# INPUT
# ============================================================

def normalize_host(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Invalid domain: {value!r}")

    value = value.strip()

    if "://" in value:
        value = urlsplit(value).hostname or ""

    value = value.rstrip(".").lower()

    try:
        interface = ipaddress.ip_interface(value)
    except ValueError:
        interface = None

    if interface is not None:
        if (
            interface.version != 4
            or interface.network.prefixlen != 32
        ):
            raise ValueError(f"Expected IPv4 or IPv4/32: {value}")

        return str(interface.ip)

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid domain: {value}") from exc

    pattern = re.compile(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    )

    if (
        len(value) > 253
        or not all(
            pattern.fullmatch(label)
            for label in value.split(".")
        )
    ):
        raise ValueError(f"Invalid domain: {value}")

    return value


def normalize_domains(domains):
    if isinstance(domains, str):
        domains = [domains]

    if not isinstance(domains, list) or not domains:
        raise ValueError("domains must be a string or non-empty array")

    return sorted({
        normalize_host(domain)
        for domain in domains
    })


def load_jobs(args, root):
    if args.config:
        if args.output or args.domains:
            raise ValueError(
                "--config cannot be combined with "
                "--output or positional domains"
            )

        raw = (
            sys.stdin.read()
            if args.config == "-"
            else Path(args.config).expanduser().read_text(
                encoding="utf-8-sig"
            )
        )

        config = json.loads(raw)

        if isinstance(config, dict) and "files" in config:
            entries = config["files"]
        elif isinstance(config, dict):
            entries = [
                {"path": path, "domains": domains}
                for path, domains in config.items()
            ]
        elif isinstance(config, list):
            entries = config
        else:
            raise ValueError("Invalid JSON configuration")

    else:
        if not args.output or not args.domains:
            raise ValueError(
                "Specify --output and domains, or --config"
            )

        entries = [{
            "path": args.output,
            "domains": args.domains,
        }]

    if not isinstance(entries, list) or not entries:
        raise ValueError("No output files configured")

    jobs = []
    seen = set()

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid file entry")

        path = entry.get("path")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Output path is required")

        target = get_output_path(root, path)

        if target in seen:
            raise ValueError(f"Duplicate output file: {target}")

        seen.add(target)

        mode = entry.get("mode", args.mode)
        cidr = entry.get("cidr", args.cidr)

        # .bat automatically generates route add commands.
        default_format = (
            "route"
            if target.suffix.lower() == ".bat"
            else "cidr" if cidr else "ip"
        )

        output_format = entry.get(
            "format",
            default_format,
        )

        prefix = entry.get("prefix", args.prefix)
        gateway = entry.get("gateway", args.gateway)

        if mode not in ("append", "replace"):
            raise ValueError(f"Invalid mode: {mode}")

        if output_format not in ("ip", "cidr", "route"):
            raise ValueError(f"Invalid format: {output_format}")

        if type(prefix) is not int or not 0 <= prefix <= 32:
            raise ValueError(f"Invalid network prefix: {prefix}")

        gateway = str(ipaddress.IPv4Address(gateway))

        jobs.append({
            "path": target,
            "domains": normalize_domains(entry.get("domains")),
            "mode": mode,
            "format": output_format,
            "prefix": prefix,
            "gateway": gateway,
        })

    return jobs


# ============================================================
# DNS
# ============================================================

def resolve_ipv4(host, server):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    answers = resolver.resolve(
        host, "A", search=False
    )

    return {
        str(address)
        for record in answers
        if (
            address := ipaddress.IPv4Address(record.address)
        ).is_global
    }


def collect_ipv4(hosts):
    results = {host: set() for host in hosts}
    queries = []

    for host in hosts:
        try:
            results[host].add(
                str(ipaddress.IPv4Address(host))
            )
        except ipaddress.AddressValueError:
            queries.extend(
                (host, server)
                for server in DNS_SERVERS
            )

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(resolve_ipv4, host, server): (
                host, server
            )
            for host, server in queries
        }

        for future in as_completed(futures):
            host, server = futures[future]

            try:
                results[host].update(future.result())
            except (dns.exception.DNSException, OSError) as exc:
                print(f"[WARN] {host} via {server}: {exc}")

    return results


# ============================================================
# EXISTING FILES
# ============================================================

def read_existing(path):
    if not path.exists():
        return ""

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return file.read()


def is_metadata_line(value):
    lower = value.strip().lower()

    return (
        not lower
        or lower in ("@echo off", "echo off", "rem")
        or lower.startswith(("rem ", "::", "#"))
    )


def read_route_networks(content, job):
    """
    Supports:
      route add X.X.X.0 mask 255.255.255.0 0.0.0.0

    Also migrates legacy:
      X.X.X.X
      X.X.X.X/32
    """
    networks = set()
    metadata = []

    prefix = job["prefix"]
    gateway = job["gateway"]

    for line_number, line in enumerate(
        content.splitlines(), start=1
    ):
        value = line.strip()

        if is_metadata_line(value):
            metadata.append(line)
            continue

        match = ROUTE_PATTERN.fullmatch(value)

        if match:
            address, mask, old_gateway = match.groups()

            try:
                old_network = ipaddress.IPv4Network(
                    f"{address}/{mask}",
                    strict=False,
                )
                old_gateway = str(
                    ipaddress.IPv4Address(old_gateway)
                )
            except ValueError as exc:
                raise ValueError(
                    f"{job['path']}:{line_number}: "
                    "Invalid route command"
                ) from exc

            if old_gateway != gateway:
                raise ValueError(
                    f"{job['path']}:{line_number}: "
                    f"Gateway mismatch: {old_gateway} != {gateway}"
                )

            if old_network.prefixlen not in (prefix, 32):
                raise ValueError(
                    f"{job['path']}:{line_number}: "
                    f"Unexpected network mask: {mask}"
                )

            ip = old_network.network_address

        else:
            # Migrate old plain IP or CIDR entries.
            try:
                interface = ipaddress.ip_interface(value)

                if (
                    interface.version != 4
                    or interface.network.prefixlen != 32
                ):
                    raise ValueError("Expected IPv4/32")

                ip = interface.ip

            except ValueError as exc:
                raise ValueError(
                    f"{job['path']}:{line_number}: "
                    f"Unsupported entry: {value!r}"
                ) from exc

        networks.add(
            ipaddress.IPv4Network(
                f"{ip}/{prefix}",
                strict=False,
            )
        )

    return networks, metadata


def read_plain_ips(content, path):
    addresses = set()

    for number, line in enumerate(
        content.splitlines(), start=1
    ):
        value = line.split("#", 1)[0].strip()

        if not value:
            continue

        try:
            interface = ipaddress.ip_interface(value)

            if (
                interface.version != 4
                or interface.network.prefixlen != 32
            ):
                raise ValueError("Expected IPv4/32")

            addresses.add(str(interface.ip))

        except ValueError as exc:
            raise ValueError(
                f"{path}:{number}: Invalid IPv4 entry: {value}"
            ) from exc

    return addresses


# ============================================================
# GENERATION
# ============================================================

def sorted_ipv4(addresses):
    return sorted(
        addresses,
        key=lambda ip: int(ipaddress.IPv4Address(ip)),
    )


def generate_routes(addresses, job, existing):
    prefix = job["prefix"]
    gateway = job["gateway"]

    networks = {
        ipaddress.IPv4Network(
            f"{address}/{prefix}",
            strict=False,
        )
        for address in addresses
    }

    metadata = []

    if job["mode"] == "append":
        old_networks, metadata = read_route_networks(
            existing, job
        )
        networks.update(old_networks)

    ordered = sorted(
        networks,
        key=lambda network: int(network.network_address),
    )

    commands = [
        (
            f"route add {network.network_address} "
            f"mask {network.netmask} {gateway}"
        )
        for network in ordered
    ]

    # Use Windows CRLF line endings for batch files.
    lines = metadata + commands

    return "\r\n".join(lines) + ("\r\n" if lines else "")


def generate_plain(addresses, job, existing):
    output_format = job["format"]
    suffix = "/32" if output_format == "cidr" else ""

    if job["mode"] == "replace":
        return "".join(
            f"{ip}{suffix}\n"
            for ip in sorted_ipv4(addresses)
        )

    existing_ips = read_plain_ips(existing, job["path"])
    new_ips = sorted_ipv4(addresses - existing_ips)

    if not new_ips:
        return existing

    newline = "\r\n" if "\r\n" in existing else "\n"

    separator = (
        newline
        if existing and not existing.endswith(("\r", "\n"))
        else ""
    )

    additions = "".join(
        f"{ip}{suffix}{newline}"
        for ip in new_ips
    )

    return existing + separator + additions


def prepare_content(job, addresses):
    target = job["path"]
    existing = read_existing(target)

    if job["format"] == "route":
        content = generate_routes(
            addresses, job, existing
        )
    else:
        content = generate_plain(
            addresses, job, existing
        )

    line_count = len(content.splitlines())

    if line_count > MAX_LINES:
        raise IPv4ListLimitExceeded(
            f"\nIPv4 list limit exceeded: {target}\n"
            f"Lines: {line_count}\n"
            f"Maximum: {MAX_LINES}\n"
            f"Overflow: {line_count - MAX_LINES}\n"
            "Write new routes into another file.\n"
            "No files have been modified."
        )

    return content


# ============================================================
# WRITING
# ============================================================

def atomic_write(path, content):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            newline="",
        ) as file:
            file.write(content)

        os.replace(temporary, path)

    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate IPv4 routes from DNS records"
    )

    parser.add_argument("domains", nargs="*")

    parser.add_argument(
        "--content-root",
        type=Path,
        default=None,
    )

    parser.add_argument("--config")
    parser.add_argument("--output")

    parser.add_argument(
        "--mode",
        choices=["append", "replace"],
        default="append",
    )

    parser.add_argument(
        "--prefix",
        type=int,
        default=DEFAULT_PREFIX,
    )

    parser.add_argument(
        "--gateway",
        default=DEFAULT_GATEWAY,
    )

    parser.add_argument(
        "--cidr",
        action="store_true",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
    )

    args = parser.parse_args()

    root = get_content_root(args.content_root)

    if root is not None and not root.is_dir():
        parser.error(f"Content root does not exist: {root}")

    try:
        jobs = load_jobs(args, root)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    hosts = sorted({
        host
        for job in jobs
        for host in job["domains"]
    })

    print(f"Content root: {root or 'Not specified'}")
    print(f"Hosts: {len(hosts)}")
    print(f"Output files: {len(jobs)}")

    results = collect_ipv4(hosts)

    for host in hosts:
        print(f"[DNS] {host}: {len(results[host])} IPv4")

    unresolved = [
        host for host in hosts
        if not results[host]
    ]

    if unresolved:
        raise DNSResolutionError(
            "Could not resolve: "
            + ", ".join(unresolved)
            + ". No files have been modified."
        )

    # Validate all files before writing any of them.
    planned = []

    for job in jobs:
        addresses = set()

        for host in job["domains"]:
            addresses.update(results[host])

        content = prepare_content(job, addresses)
        target = job["path"]

        planned.append((target, content))

        print(
            f"[CHECK] {target}: "
            f"{len(content.splitlines())}/{MAX_LINES} lines"
        )

    for target, content in planned:
        if target.exists() and read_existing(target) == content:
            print(f"[UNCHANGED] {target}")
            continue

        if args.dry_run:
            print(f"[DRY-RUN] {target}")
            continue

        atomic_write(target, content)
        print(f"[UPDATED] {target}")

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
