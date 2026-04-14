import io
import json
import sys
import zipfile

import pytest

import valhallaAPI.valhalla as valhalla_module
import valhallaAPI.valhalla_cli as valhalla_cli
from valhallaAPI.filters import ApiError
from valhallaAPI.valhalla import ValhallaAPI


class MockResponse(object):
    def __init__(self, payload):
        self.text = json.dumps(payload)


def test_cli_check_mentions_sigma_feed_flag(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["valhalla-cli", "--check"])
    monkeypatch.setattr(valhalla_cli.os.path, "exists", lambda path: False)
    monkeypatch.setattr(
        valhalla_cli.ValhallaAPI,
        "get_subscription",
        lambda self: {"active": True},
    )

    with pytest.raises(SystemExit) as exc:
        valhalla_cli.main()

    captured = capsys.readouterr()

    assert exc.value.code == 0
    assert "Account is active" in captured.err
    assert "YARA is the default rule feed" in captured.err
    assert "--feed sigma or --sigma/-s" in captured.err


def test_cli_feed_sigma_retrieves_sigma_rules(monkeypatch, capsys, tmp_path):
    output_file = tmp_path / "sigma-rules.zip"

    monkeypatch.setattr(sys, "argv", [
        "valhalla-cli",
        "--feed",
        "sigma",
        "-o",
        str(output_file),
    ])
    monkeypatch.setattr(valhalla_cli.os.path, "exists", lambda path: False)

    def fake_get_sigma_rules_zip(self, search="", private_only=False):
        self.last_retrieved_rules_count = 2
        return b"zip-bytes"

    def unexpected_yara_fetch(self, **kwargs):
        raise AssertionError("YARA retrieval should not be used for --feed sigma")

    monkeypatch.setattr(
        valhalla_cli.ValhallaAPI,
        "get_sigma_rules_zip",
        fake_get_sigma_rules_zip,
    )
    monkeypatch.setattr(
        valhalla_cli.ValhallaAPI,
        "get_rules_text",
        unexpected_yara_fetch,
    )

    valhalla_cli.main()

    captured = capsys.readouterr()

    assert output_file.read_bytes() == b"zip-bytes"
    assert "Selected rule feed: SIGMA" in captured.err
    assert "Retrieving Sigma rules with params" in captured.err


def test_cli_yara_feed_access_error_suggests_sigma(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["valhalla-cli"])
    monkeypatch.setattr(valhalla_cli.os.path, "exists", lambda path: False)

    def fake_get_rules_text(self, **kwargs):
        raise ApiError("user has no rule feed access")

    monkeypatch.setattr(valhalla_cli.ValhallaAPI, "get_rules_text", fake_get_rules_text)

    with pytest.raises(SystemExit) as exc:
        valhalla_cli.main()

    captured = capsys.readouterr()

    assert exc.value.code == 1
    assert "user has no rule feed access" in captured.err
    assert "This request targets the YARA feed" in captured.err
    assert "--feed sigma or --sigma/-s" in captured.err


def test_cli_sigma_warns_about_ignored_yara_flags(monkeypatch, capsys, tmp_path):
    output_file = tmp_path / "sigma-rules.zip"

    monkeypatch.setattr(sys, "argv", [
        "valhalla-cli",
        "--sigma",
        "-fp",
        "CarbonBlack",
        "-fs",
        "75",
        "-o",
        str(output_file),
    ])
    monkeypatch.setattr(valhalla_cli.os.path, "exists", lambda path: False)
    monkeypatch.setattr(
        valhalla_cli.ValhallaAPI,
        "get_sigma_rules_zip",
        lambda self, search="", private_only=False: b"zip-bytes",
    )

    valhalla_cli.main()

    captured = capsys.readouterr()

    assert output_file.read_bytes() == b"zip-bytes"
    assert "Ignoring YARA-only flags for Sigma retrieval: -fp, -fs" in captured.err


def test_sigma_zip_updates_retrieved_rule_count(monkeypatch):
    def fake_post(url, data=None, proxies=None, headers=None):
        assert url.endswith("/getsigma")
        return MockResponse(
            {
                "rules": [
                    {
                        "signature_type": "sigma",
                        "type": "Process Creation",
                        "filename": "first.yml",
                        "content": "title: first",
                    },
                    {
                        "signature_type": "sigma",
                        "type": "Network Connection",
                        "filename": "second.yml",
                        "content": "title: second",
                    },
                ]
            }
        )

    monkeypatch.setattr(valhalla_module.requests, "post", fake_post)

    v = ValhallaAPI(api_key=ValhallaAPI.DEMO_KEY)
    archive = v.get_sigma_rules_zip()

    assert v.last_retrieved_rules_count == 2

    with zipfile.ZipFile(io.BytesIO(archive), "r") as zip_file:
        names = sorted(zip_file.namelist())

    assert names == [
        "sigma/NetworkConnection/second.yml",
        "sigma/ProcessCreation/first.yml",
    ]


def test_sigma_zip_raises_api_error(monkeypatch):
    def fake_post(url, data=None, proxies=None, headers=None):
        assert url.endswith("/getsigma")
        return MockResponse(
            {
                "status": "error",
                "message": "user has no sigma rule feed access",
            }
        )

    monkeypatch.setattr(valhalla_module.requests, "post", fake_post)

    v = ValhallaAPI(api_key="invalid")

    with pytest.raises(ApiError) as exc:
        v.get_sigma_rules_zip()

    assert exc.value.message == "user has no sigma rule feed access"
