import pytest

from transip_rest.cli import _read_credentials_ini, _resolve_credentials, build_parser


def test_read_credentials_ini_parses_flat_keyfile(tmp_path):
    ini = tmp_path / "transip.ini"
    ini.write_text(
        "# a comment\n"
        "\n"
        "dns_transip_username = someone\n"
        "dns_transip_key_file = /etc/letsencrypt/transip/keys/transip.key\n"
    )
    username, key_file = _read_credentials_ini(str(ini))
    assert username == "someone"
    assert key_file == "/etc/letsencrypt/transip/keys/transip.key"


def test_read_credentials_ini_missing_key_raises(tmp_path):
    ini = tmp_path / "transip.ini"
    ini.write_text("dns_transip_username = someone\n")
    with pytest.raises(SystemExit, match="dns_transip_key_file"):
        _read_credentials_ini(str(ini))


def test_read_credentials_ini_missing_file_raises(tmp_path):
    with pytest.raises(SystemExit, match="Could not read"):
        _read_credentials_ini(str(tmp_path / "does-not-exist.ini"))


def test_resolve_credentials_from_ini(tmp_path):
    ini = tmp_path / "transip.ini"
    ini.write_text(
        "dns_transip_username = someone\n"
        "dns_transip_key_file = key.pem\n"
    )
    parser = build_parser()
    args = parser.parse_args(["--credentials-ini", str(ini), "list", "example.com"])
    assert _resolve_credentials(args, parser) == ("someone", "key.pem")


def test_resolve_credentials_from_flags():
    parser = build_parser()
    args = parser.parse_args(["--username", "u", "--key-file", "k", "list", "example.com"])
    assert _resolve_credentials(args, parser) == ("u", "k")


def test_resolve_credentials_ini_and_username_together_is_rejected(tmp_path):
    ini = tmp_path / "transip.ini"
    ini.write_text(
        "dns_transip_username = someone\n"
        "dns_transip_key_file = key.pem\n"
    )
    parser = build_parser()
    args = parser.parse_args(
        ["--credentials-ini", str(ini), "--username", "u", "list", "example.com"]
    )
    with pytest.raises(SystemExit):
        _resolve_credentials(args, parser)


def test_resolve_credentials_neither_form_is_rejected():
    parser = build_parser()
    args = parser.parse_args(["list", "example.com"])
    with pytest.raises(SystemExit):
        _resolve_credentials(args, parser)


def test_resolve_credentials_only_username_without_key_file_is_rejected():
    parser = build_parser()
    args = parser.parse_args(["--username", "u", "list", "example.com"])
    with pytest.raises(SystemExit):
        _resolve_credentials(args, parser)


def test_update_subcommand_parses(tmp_path):
    parser = build_parser()
    args = parser.parse_args(
        [
            "--username", "u", "--key-file", "k",
            "update", "example.com", "_acme-challenge", "TXT", "new-value", "--ttl", "60",
        ]
    )
    assert args.command == "update"
    assert args.domain == "example.com"
    assert args.name == "_acme-challenge"
    assert args.type == "TXT"
    assert args.content == "new-value"
    assert args.ttl == 60
