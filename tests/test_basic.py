from os import sys, path
import pytest
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from valhallaAPI.valhalla import ValhallaAPI

DEMO_KEY = "1111111111111111111111111111111111111111111111111111111111111111"
INVALID_KEY = "invalid"
RULES_TEXT = "VALHALLA YARA RULE SET"
RULE_INFO_DISALLOWED = "SUSP_Office_Dropper_Strings"
SIGMA_RULE_UUID = "06d71506-7beb-4f22-8888-e2e5e2ca7fd8"


def test_quote():
    """
    Tests the quote page to check if the service can be access
    :return:
    """
    v = ValhallaAPI(api_key="")
    assert "brave shall live forever" in v.get_quote()


def test_status():
    """
    Retrieves the API status
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    status = v.get_status()
    assert status["status"] == "green"


def test_subscription():
    """
    Retrieves the subscription status of the current user
    :return:
    """
    v = ValhallaAPI()
    response = v.get_subscription()
    assert len(response) == 5
    assert response["subscription"] == "limited"
    assert response["tags"] == ['DEMO']


def test_demo_rules_json():
    """
    Retrieves the demo rules from the rule feed
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    rules_response = v.get_rules_json()
    assert len(rules_response['rules']) > 0


def test_no_rule_info():
    """
    Retrieves no rule info since demo key is limited
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    rules_response1 = v.get_rule_info(RULE_INFO_DISALLOWED)
    assert 'rule_matches' not in rules_response1


def test_demo_rules_product_limited():
    """
    Retrieves the demo rules from the rule feed with a product set
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    rules_response = v.get_rules_json()
    rules_response_limited = v.get_rules_json(product="DummyTest")
    assert len(rules_response['rules']) > 0
    assert len(rules_response['rules']) > len(rules_response_limited['rules'])
    rules_response_limited2 = v.get_rules_json(product="CarbonBlack")
    assert len(rules_response_limited2['rules']) > 0


def test_demo_rules_custom_limited():
    """
    Retrieves the demo rules from the rule feed with custom expressions
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    rules_response1 = v.get_rules_json(modules=['pe'])
    rules_response2 = v.get_rules_json(modules=['pe'], with_crypto=False)
    assert len(rules_response1['rules']) > 0
    assert len(rules_response2['rules']) > 0
    assert len(rules_response2['rules']) < len(rules_response1['rules'])


def test_demo_rules_tag_limited():
    """
    Retrieves the demo rules from the rule feed with custom expressions
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    rules_response1 = v.get_rules_json()
    rules_response2 = v.get_rules_json(tags=['APT'])
    assert len(rules_response1['rules']) > 0
    assert len(rules_response2['rules']) > 0
    assert len(rules_response1['rules']) > len(rules_response2['rules'])


def test_demo_rules_score_limited():
    """
    Retrieves the demo rules from the rule feed with custom expressions
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    rules_response1 = v.get_rules_json()
    rules_response2 = v.get_rules_json(score=80)
    assert len(rules_response1['rules']) > 0
    assert len(rules_response2['rules']) > 0
    assert len(rules_response1['rules']) > len(rules_response2['rules'])


def test_demo_rules_search_limited():
    """
    Retrieves the demo rules from the rule feed with custom expressions
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    rules_response1 = v.get_rules_json()
    rules_response2 = v.get_rules_json(search="Mimikatz")
    assert len(rules_response1['rules']) > 1
    assert len(rules_response2['rules']) > 1
    assert len(rules_response1['rules']) > len(rules_response2['rules'])


def test_demo_rules_combo_limited():
    """
    Retrieves the demo rules from the rule feed with custom expressions
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    rules_response1 = v.get_rules_json()
    rules_response2 = v.get_rules_json(score=60)
    rules_response3 = v.get_rules_json(tags=['SUSP'], score=60)
    assert len(rules_response1['rules']) > 1
    assert len(rules_response2['rules']) > 1
    assert len(rules_response3['rules']) > 1
    assert len(rules_response1['rules']) > len(rules_response2['rules'])
    assert len(rules_response2['rules']) > len(rules_response3['rules'])


def test_demo_rules_text():
    """
    Retrieves the demo rules from the rule feed
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    response = v.get_rules_text()
    assert RULES_TEXT in response
    assert len(response) > 500


def test_invalid_key():
    """
    Trying to retrieve rules with an invalid key
    :return:
    """
    v = ValhallaAPI(api_key=INVALID_KEY)
    with pytest.raises(Exception):
        v.get_rules_text()


def test_demo_sigma_rules_json():
    """
    Retrieves the demo rules from the sigma rule feed
    :return:
    """
    v = ValhallaAPI(api_key=DEMO_KEY)
    response = v.get_sigma_rules_json()
    assert len(response['rules']) > 0

def test_get_rule_info_invalid():
    """
    Retrieves no rules since key is invalid
    :return:
    """
    v = ValhallaAPI(api_key=INVALID_KEY)
    response = v.get_rules_json()
    assert response['status'] == 'error'
    response2 = v.get_rules_json(score=75)
    assert response2['status'] == 'error'