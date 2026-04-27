import io
import json
import sys
import zipfile

import pytest

import valhallaAPI.valhalla as valhalla_module
import valhallaAPI.valhalla_cli as valhalla_cli
from valhallaAPI.valhalla import ValhallaAPI, ApiError
from valhallaAPI.version import __version__

DEMO_KEY = ValhallaAPI.DEMO_KEY


class MockResponse(object):
    def __init__(self, payload):
        self.text = json.dumps(payload)


def test_cli_banner_uses_package_version(monkeypatch, capsys):
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
    assert "Ver. %s" % __version__ in captured.out
    assert "No config file found; using the API key passed on the command line (-k)" in captured.err
    assert "Use '-k APIKEY' with your private API key to retrieve the rule sets you are subscribed to" in captured.err


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
    v = ValhallaAPI(api_key=DEMO_KEY)
    archive = v.get_sigma_rules_zip()

    assert v.last_retrieved_rules_count == 2

    with zipfile.ZipFile(io.BytesIO(archive), "r") as zip_file:
        names = sorted(zip_file.namelist())

    assert names == [
        "sigma/NetworkConnection/second.yml",
        "sigma/ProcessCreation/first.yml",
    ]


def test_sigma_json_error_response_does_not_keyerror(monkeypatch):
    def fake_post(url, data=None, proxies=None, headers=None):
        assert url.endswith("/getsigma")
        return MockResponse(
            {
                "status": "error",
                "message": "demo failure",
            }
        )

    monkeypatch.setattr(valhalla_module.requests, "post", fake_post)
    v = ValhallaAPI(api_key=DEMO_KEY)

    response = v.get_sigma_rules_json(search="suspicious", private_only=True)

    assert response["status"] == "error"
    assert v.last_retrieved_rules_count == 0


def test_sigma_zip_raises_api_error_on_error_response(monkeypatch):
    def fake_post(url, data=None, proxies=None, headers=None):
        assert url.endswith("/getsigma")
        return MockResponse(
            {
                "status": "error",
                "message": "demo failure",
            }
        )

    monkeypatch.setattr(valhalla_module.requests, "post", fake_post)
    v = ValhallaAPI(api_key=DEMO_KEY)

    with pytest.raises(ApiError) as exc:
        v.get_sigma_rules_zip(search="suspicious", private_only=True)

    assert exc.value.message == "demo failure"


@pytest.mark.integration
def test_sigma_zip_updates_retrieved_rule_count_live_demo():
    v = ValhallaAPI(api_key=DEMO_KEY)

    archive = v.get_sigma_rules_zip()

    assert len(archive) > 0
    assert v.last_retrieved_rules_count > 0

    with zipfile.ZipFile(io.BytesIO(archive), "r") as zip_file:
        names = zip_file.namelist()

    assert len(names) == v.last_retrieved_rules_count
