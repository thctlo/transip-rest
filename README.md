# transip-rest

A minimal REST client and CLI for the [TransIP API v6](https://api.transip.nl/rest/docs.html).

Implements only authentication and generic DNS entry management
(list/create/delete) - not a full wrapper of TransIP's API. Written for
use by `certbot-dns-transip` and for ad-hoc DNS management (CAA, DKIM,
and any other record type TransIP supports: A, AAAA, CNAME, MX, NS,
TXT, SRV, SSHFP, TLSA, CAA, NAPTR).

## Platform

Built and packaged for Debian 13 (trixie); not tested on other
distributions or Debian releases.

## CLI usage

```
transip-dns --username USER --key-file KEYFILE list example.com
transip-dns --username USER --key-file KEYFILE add example.com www A 127.0.0.1
transip-dns --username USER --key-file KEYFILE update example.com www A 127.0.0.2
transip-dns --username USER --key-file KEYFILE delete example.com www A 127.0.0.2
```

`update` changes an existing entry's content in place, via TransIP's
PATCH endpoint, instead of a separate delete-then-add - but TransIP
identifies which entry to update by `name`+`type`+`ttl` (not content),
so those three must match the live record exactly; only `content`
changes.

Instead of passing `--username`/`--key-file` on every call, point at a
credentials file instead - the same file format and key names
(`dns_transip_username`, `dns_transip_key_file`) the
`certbot-dns-transip` plugin's own credentials file already uses, so
one file can serve both tools:

```
transip-dns --credentials-ini /etc/letsencrypt/transip/accounts.d/transip.ini list example.com
```

## Provenance

The authentication signing scheme (RSA PKCS#1 v1.5 padding, SHA-512,
base64-encoded signature in the `Signature` header, POST to `/v6/auth`)
and the DNS entry endpoint shapes come from TransIP's own API
documentation. They were cross-checked for correctness against two
independently licensed open source clients (no code copied from
either): [roaldnefs/python-transip](https://github.com/roaldnefs/python-transip)
(LGPL-3.0) and [Jerrythafast/transip-dyndns](https://github.com/Jerrythafast/transip-dyndns)
(GPL-3.0).

## Token lifecycle

`TransipClient` requests one access token per process and reuses it
for every call until it is close to expiring, instead of requesting a
new one for every request. Each token request uses a unique label
(the `label` constructor argument is a *prefix* - a random suffix is
appended per request) so that two requests - even seconds apart - can
never collide with "the label ... is already used in another active
access token", which is what happens if a fixed label is reused while
the previous token under that label hasn't expired yet.

Pass `token_cache_path` to also persist the current token to a small
JSON file (written with mode `600`), so a *separate* process (e.g. a
second CLI invocation, or a certbot renewal shortly after another one)
reuses it too instead of requesting its own. This is optional and
purely a performance/collision-avoidance optimization - without it,
each process simply gets its own uniquely-labelled token as described
above.

## Known limitation

TransIP's own API documentation does not specify how `content` values
longer than the DNS 255-byte single-string limit (e.g. an RSA DKIM
public key) should be submitted. This has not been tested against the
live API yet - short values (such as ACME dns-01 challenge tokens)
are well under this limit and unaffected.
