
from datetime import datetime

YARA_SET_HEADER = """/*
    VALHALLA YARA RULE SET
    Retrieved: {{ date }}
    Generated for User: {{ user }}
    Number of Rules: {{ len_rules }}
    
    ANY REPRODUCTION OR DISTRIBUTION IS STRICTLY PROHIBITED WITHOUT THE PRIOR WRITTEN CONSENT OF NEXTRON SYSTEMS AND MAY RESULT IN LEGAL ACTION AS WELL AS THE TERMINATION OF THE CONTRACTUAL RELATIONSHIP
*/
"""


def generate_header(rules_response):
    """
    Generates a header for the text format YARA rule set and uses the meta data section to fill the placeholders
    :param rules_response: the retrieved rule set as python object
    :return:
    """
    header_elements = list()

    # Header comment
    yara_set_header = YARA_SET_HEADER
    yara_set_header = yara_set_header.replace('{{ date }}', datetime.utcnow().strftime("%Y-%m-%d %H:%M"))
    yara_set_header = yara_set_header.replace('{{ user }}', rules_response['customer'])
    yara_set_header = yara_set_header.replace('{{ len_rules }}', str(len(rules_response['rules'])))
    header_elements.append(yara_set_header)

    # Required modules
    required_modules = set()
    for rule in rules_response['rules']:
        for module in rule['required_modules']:
            required_modules.add(module)
    for module in required_modules:
        header_elements.append('import "{0}"'.format(module))
    return "\n".join(header_elements)
