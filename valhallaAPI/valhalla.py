#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Valhalla API Client
# Florian Roth
#
# Designed to work with API version 1

__version__ = "0.2.2"

import json
import requests
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
    FIREEYEAX = "FireEyeAX"
    FIREEYENX = "FireEyeNX"
    FIREEYEEX = "FireEyeEX"
    CARBONBLACK = "CarbonBlack"
    TANIUM = "Tanium"
    TENABLE = "Tenable"
    SYMANTECMAA = "SymantecMAA"

    PRODUCT_IDENTIFIER = ['FireEyeAX', 'FireEyeNX', 'FireEyeEX', 'CarbonBlack', 'Tanium', 'Tenable', 'SymantecMAA']
    DEMO_KEY = "1111111111111111111111111111111111111111111111111111111111111111"

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
        r = requests.get("%s/quote" % self.base_url, verify=self.verify_ssl)
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
                          proxies=self.proxies)
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
                          proxies=self.proxies)
        return json.loads(r.text)

    def get_rule_info(self, rulename):
        """
        Retrieve info for a given rule
        :return:
        """
        r = requests.post("%s/api/%s/ruleinfo" % (self.base_url, self.api_version),
                          data={
                              "apikey": self.api_key,
                              "rulename": rulename,
                          },
                          proxies=self.proxies)
        return json.loads(r.text)

    def get_rules_json(self, product="", max_version="", modules=[], with_crypto=True, tags=[], score=0, search=""):
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
                          proxies=self.proxies)
        # Load JSON
        rules_response = json.loads(r.text)

        # Filter ------------------------------------------------------
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
        # Return filtered set
        return rules_response

    def get_rules_text(self, product="", max_version="", modules=[], with_crypto=True, tags=[], score=0, search=""):
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
                                             search=search)

        response_elements = list()
        # Generate header
        response_elements.append(generate_header(rules_response))

        # Save the number of retrieved rules
        self.last_retrieved_rules_count = len(rules_response['rules'])

        # Rules
        for rule in rules_response['rules']:
            response_elements.append(rule['content'])

        return "\n\n".join(response_elements)
