#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Valhalla API Client
# Florian Roth
#
# Designed to work with API version 1

__version__ = "0.6.1"

import io
import json
import requests
import platform
import zipfile
from urllib.parse import urlparse
from .filters import *
from .helper import generate_header
# from requests.auth import HTTPProxyAuth  # not yet used


class ValhallaAPI(object):
    """
    Valhalla API Client Class
    """
    base_url = "https://valhalla.nextron-systems.com"
    api_key = ""
    api_version = "v1"
    verify_ssl = True

    proxies = {}

    # Product Identifier
    FIREEYEAX_912_915 = "FireEyeAX_912_915"
    FIREEYEAX_900_911 = "FireEyeAX_900_911"
    FIREEYEAX_83x_84x = "FireEyeAX_83x_84x"
    FIREEYENX_912_915 = "FireEyeNX_912_915"
    FIREEYENX_900_911 = "FireEyeNX_900_911"
    FIREEYENX_83x = "FireEyeNX_83x"
    FIREEYEEX_912_915 = "FireEyeEX_912_915"
    FIREEYEEX_900_911 = "FireEyeEX_900_911"
    FIREEYEEX_82x_84x = "FireEyeEX_82x_84x"
    CARBONBLACK = "CarbonBlack"
    TANIUM = "Tanium"
    TENABLE = "Tenable"
    GRR = "GRR"
    OSQUERY = "osquery"

    PRODUCT_IDENTIFIER = ['FireEyeAX_912_915', 'FireEyeAX_900_911', 'FireEyeAX_83x_84x', 
                          'FireEyeNX_912_915', 'FireEyeNX_900_911', 'FireEyeNX_83x' 
                          'FireEyeEX_912_915', 'FireEyeEX_900_911', 'FireEyeEX_82x_84x', 
                          'CarbonBlack', 'Tanium', 'Tenable', 'GRR', 'osquery']
    DEMO_KEY = "1111111111111111111111111111111111111111111111111111111111111111"
    DEFAULT_OUTPUT_FILE = 'valhalla-rules.yar'

    # Cached info
    last_retrieved_rules_count = 0

    def __init__(self, api_key=""):
        """
        Initializes the API client object
        :param api_key:
        """
        # Demo API key if no API key was given
        if api_key == "":
            api_key = self.DEMO_KEY

        # API Key
        self.api_key = api_key
        # Adjust user agent (add system info)
        user_agent = "{0} {1}".format(requests.utils.default_headers()['User-Agent'], platform.system())
        self.headers = {'User-Agent': user_agent}

    def set_proxy(self, proxy, user="", pwd=""):
        """
        Set a proxy URL, user and password
        :param proxy: Proxy URL (e.g. https://proxy.local:8080)
        :param user: user name
        :param pwd: password
        :return:
        """
        u = urlparse(proxy)
        # Auth
        auth_string = ""
        if user:
            auth_string = "{1}:{2}@".format(user, pwd)
        # Set the proxy
        self.proxies = {u.scheme: '{0}://{1}{2}/'.format(
            u.scheme,
            auth_string,
            u.netloc
        )}

    def set_url(self, url):
        """
        Set the URL to a different value for testing purposes
        :param url: alternative API URL
        :return:
        """
        self.base_url = url

    def get_quote(self):
        """
        Returns a poem to see if Valhalla is up and running
        :return:
        """
        r = requests.get("%s/quote" % self.base_url, verify=self.verify_ssl, proxies=self.proxies, headers=self.headers)
        return r.text

    def get_status(self):
        """
        Retrieve the service status
        :return:
        """
        r = requests.post("%s/api/%s/status" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        return json.loads(r.text)

    def get_subscription(self):
        """
        Retrieve the subscribed tags
        :return:
        """
        r = requests.post("%s/api/%s/subscription" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        return json.loads(r.text)

    def get_rule_info(self, rulename):
        """
        Retrieve info for a given rule
        :param rulename: name of the rule
        :return:
        """
        r = requests.post("%s/api/%s/ruleinfo" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                              "rulename": rulename,
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        return json.loads(r.text)

    def get_sigma_rule_info(self, ruleid):
        """
        Retrieve info for a given sigma rule
        :param ruleid: UUID of the rule
        :return:
        """
        r = requests.post("%s/api/%s/sigmaruleinfo" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                              "ruleid": ruleid,
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        return json.loads(r.text)

    def get_hash_info(self, hash):
        """
        Retrieve rule matches for a given hash
        :param hash: a sha256 hash of a sample
        :return:
        """
        r = requests.post("%s/api/%s/hashinfo" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                              "sha256": hash,
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        return json.loads(r.text)

    def get_keyword_rules(self, keyword):
        """
        Retrieve rule matches for a given keyword (tag, string)
        :param keyword: a keyword for a certain malware or group
        :return:
        """
        r = requests.post("%s/api/%s/keyword" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                              "keyword": keyword,
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        return json.loads(r.text)

    def get_keyword_rule_matches(self, keyword):
        """
        Retrieve hash matches of rules on which a given keyword (tag, string) has matched
        :param keyword: a keyword for a certain malware or group
        :return:
        """
        r = requests.post("%s/api/%s/keyword-matches" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                              "keyword": keyword,
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        return json.loads(r.text)

    def get_rules_json(self, product="", max_version="", modules=[], with_crypto=True, tags=[], score=0, search="", private_only=False):
        """
        Retrieve the rules as JSON object
        :param product: set a certain product that all rules must support
        :param max_version: set a maximum YARA version that your product supports
        :param modules: set a list of modules that your product supports
        :param with_crypto: set False if a product's YARA has not been built with OpenSSL (--without-crypto)
        :param tags: set a list of tags that you want to retrieve
        :param score: minimum score for rules to include in the output
        :return:
        """
        # API Request
        r = requests.post("%s/api/%s/get" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                              "format": "json",
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        # Load JSON
        rules_response = json.loads(r.text)

        # Filter ------------------------------------------------------
        if 'rules' in rules_response:
            # Product filtering
            if product:
                (max_version, modules, with_crypto) = get_product_requirements(product=product)
            # Tag filtering
            if len(tags) > 0:
                rules_response['rules'] = filter_tags(rules_response['rules'], tags=tags)
            # Score
            if score > 0:
                rules_response['rules'] = filter_score(rules_response['rules'], minimum_score=score)
            # Search string
            if search:
                rules_response['rules'] = filter_search(rules_response['rules'], query=search)
            # Custom filtering
            if max_version or len(modules) > 0 or with_crypto is not True:
                rules_response['rules'] = filter_requirements(rules_response['rules'],
                                                            sup_ver_string=max_version,
                                                            sup_modules=modules,
                                                            with_crypto=with_crypto)
            # Public rules filter
            if private_only:
                rules_response['rules'] = filter_privateonly(rules_response['rules'])

        # Return filtered set
        return rules_response

    def get_rules_text(self, product="", max_version="", modules=[], with_crypto=True, tags=[], score=0, search="", private_only=False):
        """
        Retrieve the rules as JSON object, but converts them to text before returning them
        :param product: set a certain product that all rules must support
        :param max_version: set a maximum YARA version that your product supports
        :param modules: set a list of modules that your product supports
        :param with_crypto: set False if a product's YARA has not been built with OpenSSL (--without-crypto)
        :param tags: set a list of tags that you want to retrieve
        :param score: minimum score for rules to include in the output
        :return:
        """
        rules_response = self.get_rules_json(product=product,
                                             max_version=max_version,
                                             modules=modules,
                                             with_crypto=with_crypto,
                                             tags=tags,
                                             score=score,
                                             search=search,
                                             private_only=private_only)

        # Error
        if 'status' in rules_response:
            if rules_response['status'] == "error":
                raise ApiError(rules_response['message'])

        response_elements = list()

        # Generate header
        response_elements.append(generate_header(rules_response))

        # Save the number of retrieved rules
        self.last_retrieved_rules_count = len(rules_response['rules'])

        # Rules
        for rule in rules_response['rules']:
            response_elements.append(rule['content'])

        return "\n\n".join(response_elements)

    def get_sigma_rules_json(self, search="", private_only=False):
        """
        Retrieve the sigma rules as JSON object
        :return:
        """
        # API Request
        r = requests.post("%s/api/%s/getsigma" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                              "format": "json",
                          },
                          proxies=self.proxies,
                          headers=self.headers)
        # Load JSON
        rules_response = json.loads(r.text)

        if search:
            rules_response['rules'] = filter_search(rules_response['rules'], query=search)
        if private_only:
            rules_response['rules'] = filter_privateonly(rules_response['rules'])
        # Return filtered set
        return rules_response

    def get_sigma_rules_zip(self, search="", private_only=False):
        """
        Retrieve the sigma rules as ZIP object
        :return:
        """
        rules_response = self.get_sigma_rules_json(search, private_only)
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(file=zip_buffer, mode='w') as zip_file:

            for rule in rules_response['rules']:
                zip_file.writestr("%s/%s/%s" % (rule["signature_type"], rule["type"].replace(" ", ""), rule["filename"]), rule["content"])

        return zip_buffer.getbuffer().tobytes()
