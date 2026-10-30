"""Command-line interface for managing TransIP DNS records.

Usage:
    transip-dns --username USER --key-file KEYFILE list DOMAIN
    transip-dns --username USER --key-file KEYFILE add DOMAIN NAME TYPE CONTENT [--ttl SECONDS]
    transip-dns --username USER --key-file KEYFILE update DOMAIN NAME TYPE CONTENT [--ttl SECONDS]
    transip-dns --username USER --key-file KEYFILE delete DOMAIN NAME TYPE CONTENT [--ttl SECONDS]

    # Or, instead of --username/--key-file, point at a credentials file
    # (same dns_transip_username/dns_transip_key_file keys the
    # certbot-dns-transip plugin's own credentials ini uses):
    transip-dns --credentials-ini /etc/letsencrypt/transip/accounts.d/transip.ini list DOMAIN
"""
from __future__ import annotations

import argparse
import sys

from .client import TransipClient
from .exceptions import TransipApiError

RECORD_TYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "SSHFP", "TLSA", "CAA", "NAPTR",
]


def _read_credentials_ini(path: str) -> tuple[str, str]:
    """Read dns_transip_username/dns_transip_key_file from a flat key=value
    credentials file - the same format and keys certbot-dns-transip's own
    credentials ini uses (no [section] header, so plain line parsing
    rather than configparser, which would require one)."""
    values: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    except OSError as exc:
        raise SystemExit(f"Could not read credentials file {path!r}: {exc}") from exc

    missing = [k for k in ("dns_transip_username", "dns_transip_key_file") if k not in values]
    if missing:
        raise SystemExit(
            f"{path}: missing required key(s) {', '.join(missing)} "
            "(expected dns_transip_username and dns_transip_key_file)"
        )
    return values["dns_transip_username"], values["dns_transip_key_file"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage TransIP DNS records")
    parser.add_argument(
        "--username",
        help="TransIP account login (or use --credentials-ini instead)",
    )
    parser.add_argument(
        "--key-file",
        help="Path to the RSA private key, PEM (or use --credentials-ini instead)",
    )
    parser.add_argument(
        "--credentials-ini",
        help=(
            "Path to a credentials file with dns_transip_username and "
            "dns_transip_key_file keys (same format/keys certbot-dns-transip "
            "uses) - an alternative to passing --username/--key-file separately"
        ),
    )
    parser.add_argument(
        "--global-key",
        action="store_true",
        help="Request a token that works from any IP (default: limited to whitelisted IPs)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", help="List DNS entries for a domain")
    list_p.add_argument("domain")

    add_p = sub.add_parser("add", help="Add a DNS entry")
    add_p.add_argument("domain")
    add_p.add_argument("name")
    add_p.add_argument("type", choices=RECORD_TYPES)
    add_p.add_argument("content")
    add_p.add_argument("--ttl", type=int, default=86400, help="TTL in seconds (default: 86400, matching TransIP's own API example)")

    update_p = sub.add_parser(
        "update",
        help=(
            "Change an existing DNS entry's content in place (name, type AND "
            "ttl must match the live record exactly - only content changes; "
            "use delete+add instead to change the ttl or type itself)"
        ),
    )
    update_p.add_argument("domain")
    update_p.add_argument("name")
    update_p.add_argument("type", choices=RECORD_TYPES)
    update_p.add_argument("content", help="The new content to set")
    update_p.add_argument("--ttl", type=int, default=86400, help="Must match the TTL the record currently has")

    del_p = sub.add_parser(
        "delete",
        help="Delete a DNS entry (name, type, content AND ttl must match the live record exactly)",
    )
    del_p.add_argument("domain")
    del_p.add_argument("name")
    del_p.add_argument("type", choices=RECORD_TYPES)
    del_p.add_argument("content")
    del_p.add_argument("--ttl", type=int, default=86400, help="Must match the TTL the record was created with")

    return parser


def _resolve_credentials(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[str, str]:
    """Return (username, key_file_path) from either --credentials-ini or
    --username/--key-file - exactly one of the two forms, never a mix,
    never neither. Calls parser.error() (exits with status 2, argparse's
    own usual way of reporting a bad invocation) on a bad combination."""
    if args.credentials_ini:
        if args.username or args.key_file:
            parser.error("--credentials-ini cannot be combined with --username/--key-file")
        return _read_credentials_ini(args.credentials_ini)
    if not args.username or not args.key_file:
        parser.error("either --credentials-ini, or both --username and --key-file, is required")
    return args.username, args.key_file


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    username, key_file_path = _resolve_credentials(args, parser)

    with open(key_file_path, "rb") as fh:
        private_key_pem = fh.read()

    client = TransipClient(
        username=username, private_key_pem=private_key_pem, global_key=args.global_key
    )

    try:
        if args.command == "list":
            for entry in client.list_dns_entries(args.domain):
                print(f"{entry['name']}\t{entry['expire']}\t{entry['type']}\t{entry['content']}")
        elif args.command == "add":
            client.create_dns_entry(args.domain, args.name, args.type, args.content, args.ttl)
            print("OK")
        elif args.command == "update":
            client.update_dns_entry(args.domain, args.name, args.type, args.content, args.ttl)
            print("OK")
        elif args.command == "delete":
            client.delete_dns_entry(args.domain, args.name, args.type, args.content, args.ttl)
            print("OK")
    except TransipApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
