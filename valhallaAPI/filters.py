import re
from packaging import version

# Product Requirements
PRODUCT_REQUIREMENTS = {
    "FireEyeAX": {
        "maximum_version": "3.4.0",
        "supported_modules": [],  # assumption
        "with_crypto": True,  # assumption
    },
    "FireEyeNX": {
        "maximum_version": "3.4.0",
        "supported_modules": [],  # assumption
        "with_crypto": True,  # assumption
    },
    "FireEyeEX": {
        "maximum_version": "1.7.0",
        "supported_modules": [],  # assumption
        "with_crypto": False,  # assumption
    },
    "CarbonBlack": {
        "maximum_version": "",
        "supported_modules": ["pe", "math", "hash"],
        "reference": "https://github.com/carbonblack/cb-yara-connector",
        "with_crypto": True,  # depends
    },
    "Tanium": {
        "maximum_version": "3.7.0",
        "supported_modules": [],
        "with_crypto": True,  # assumption
    },
    "Tenable": {
        "maximum_version": "3.7.0",  # assumption
        "supported_modules": ['pe', 'elf'],
        "reference": "https://community.tenable.com/s/article/Supported-Yara-Checks",
        "with_crypto": False,
    },
    "SymantecMAA": {
        "maximum_version": "2.1.0",
        "supported_modules": [],  # assumption
        "reference": "https://twitter.com/RedSecSecurity/status/1103599203459129344",
        "with_crypto": False,   # assumption
    },
    "GRR": {
        "maximum_version": "3.6.3",
        "supported_modules": [],  # assumption
        "reference": "Open Source DFIR Slack",
        "with_crypto": False,  # assumption
    },
    "osquery": {
        "maximum_version": "3.7.1",
        "supported_modules": ["pe", "elf", "math"],  # assumption
        "reference": "https://github.com/osql/osql/issues/11",
        "with_crypto": True,  # https://github.com/facebook/osquery/blob/experimental/tools/provision/formula/yara.rb
    },
    "McAfeeATD3": {
        "maximum_version": "3.0",
        "supported_modules": ["pe", "elf", "math"],  # assumption
        "reference": "https://docs.mcafee.com/exports/pdf/jobs/download/pdf/238025",
        "with_crypto": True,
    },
    "McAfeeATD4": {
        "maximum_version": "3.0",  # until we know exactly which version is supported
        "supported_modules": ["pe", "elf", "math"],  # assumption
        "reference": "https://docs.mcafee.com/exports/pdf/jobs/download/pdf/238025",
        "with_crypto": True,
    },
    "DummyTest": {
        "maximum_version": "1.7.0",
        "supported_modules": [],
        "with_crypto": True,
    },
}

REGEX_CRYPTO_FEATURES = r'( pe\.imphash| pe\.signatures| hash\.)'


class UnknownProductError(Exception):
    """
    Unknown product exception
    """
    def __init__(self, message):
        Exception.__init__(self)
        self.message = message


class ApiError(Exception):
    """
    API error exception
    """
    def __init__(self, message):
        Exception.__init__(self)
        self.message = message


def get_product_requirements(product):
    """
    Get the version and modules that are supported by the product
    :param product: product for which the rule output should be prepared
    :return sup_version: supported version as string
    :return sup_modules: supported modules as list of strings
    :return with_crypto: indicates if YARA has been compiled with OpenSSL
    """
    # Product requirements
    if product not in PRODUCT_REQUIREMENTS:
        raise UnknownProductError("product name '%s' is not in the predefined list: %s" %
                                  (product, ", ".join(PRODUCT_REQUIREMENTS)))
    # Get the values from the dict
    sup_version = PRODUCT_REQUIREMENTS[product]['maximum_version']
    sup_modules = PRODUCT_REQUIREMENTS[product]['supported_modules']
    with_crypto = PRODUCT_REQUIREMENTS[product]['with_crypto']
    return sup_version, sup_modules, with_crypto


def filter_requirements(rules, sup_ver_string, sup_modules=[], with_crypto=True):
    """
    Filter the rules object for rules that comply with the given criteria
    :param rules: YARA rules JSON object
    :param sup_ver_string: the maximum YARA version that is supportted by the product
    :param sup_modules: the supported modules
    :param with_crypto: indicates if the product's YARA has been compiled with OpenSSL
    :return: list of filtered rules
    """
    filtered_rules = []
    version_check = True
    if sup_ver_string == "":
        version_check = False
    else:
        sup_version = version.parse(sup_ver_string)
    re_crypto = re.compile(REGEX_CRYPTO_FEATURES)
    # Process the rules
    for rule in rules:
        # YARA version filter
        if version_check:
            # Filter rules that need versions that are not supported
            if 'minimum_yara' in rule:
                req_version = version.parse(rule['minimum_yara'])
                # If required version is higher than supported version, skip the rule
                if req_version > sup_version:
                    continue
        # Crypto / OpenSSL filter
        if not with_crypto:
            if re_crypto.search(rule['content'], re.MULTILINE):
                continue
        # Module filter
        if 'required_modules' in rule:
            one_unsupported = False
            for m in rule['required_modules']:
                if m not in sup_modules:
                    one_unsupported = True
            # If a single required module is unsupported, then skip the rule
            if one_unsupported:
                continue
        filtered_rules.append(rule)

    return filtered_rules


def filter_tags(rules, tags=[]):
    """
    Filter the rules object for rules that have a certain tag
    :param rules: YARA rules JSON object
    :param tags: the selected tags
    :return: list of filtered rules
    """
    filtered_rules = []
    # Process the rules
    for rule in rules:
        for tag in tags:
            if tag.upper() in rule['tags']:
                filtered_rules.append(rule)
                break

    return filtered_rules


def filter_score(rules, minimum_score=0):
    """
    Filter the rules object for rules that have a certain score or higher
    :param rules: YARA rules JSON object
    :param minimum_score: minimum score
    :return: list of filtered rules
    """
    filtered_rules = []
    # Process the rules
    for rule in rules:
        if int(rule['score']) >= minimum_score:
            filtered_rules.append(rule)
    return filtered_rules


def filter_search(rules, query):
    """
    Filter the rules object for rules that have a certain string in them
    :param rules: YARA rules JSON object
    :param query: string to search in rule name and description
    :return: list of filtered rules
    """
    filtered_rules = []
    # Process the rules
    for rule in rules:
        if re.search(r'%s' % query, rule['description'], re.IGNORECASE) or \
                re.search(r'%s' % query, rule['name'], re.IGNORECASE):
            filtered_rules.append(rule)
    return filtered_rules


def get_product_templates():
    """
    Get the predefined product templates as list
    :return:
    """
    products = []
    for product in PRODUCT_REQUIREMENTS:
        products.append(product)
    return products
