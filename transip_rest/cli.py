"""Command-line interface for managing TransIP DNS records.

Usage:
    transip-dns --username USER --key-file KEYFILE list DOMAIN
    transip-dns --username USER --key-file KEYFILE add DOMAIN NAME TYPE CONTENT [--ttl SECONDS]
    transip-dns --username USER --key-file KEYFILE delete DOMAIN NAME TYPE CONTENT [--ttl SECONDS]
"""
from __future__ import annotations

import argparse
import sys

from .client import TransipClient
from .exceptions import TransipApiError

RECORD_TYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "SSHFP", "TLSA", "CAA", "NAPTR",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage TransIP DNS records")
    parser.add_argument("--username", required=True, help="TransIP account login")
    parser.add_argument("--key-file", required=True, help="Path to the RSA private key (PEM)")
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    with open(args.key_file, "rb") as fh:
        private_key_pem = fh.read()

    client = TransipClient(
        username=args.username, private_key_pem=private_key_pem, global_key=args.global_key
    )

    try:
        if args.command == "list":
            for entry in client.list_dns_entries(args.domain):
                print(f"{entry['name']}\t{entry['expire']}\t{entry['type']}\t{entry['content']}")
        elif args.command == "add":
            client.create_dns_entry(args.domain, args.name, args.type, args.content, args.ttl)
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
