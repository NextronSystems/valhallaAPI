#!/usr/bin/env python3
# Valhalla API command line client
# Florian Roth, 2020

__version__ = "0.6.0"

import sys
import os
import argparse
import logging
import platform
import json
import configparser
from pathlib import Path
from valhallaAPI.valhalla import ValhallaAPI, UnknownProductError, ApiError


def main():
    """
    Main Function (used as entry point)
    :return:
    """
    # Parse Arguments
    parser = argparse.ArgumentParser(description='Valhalla-CLI')
    parser.add_argument('-k', help='API KEY', metavar='apikey', default=ValhallaAPI.DEMO_KEY)
    parser.add_argument('-c', help='Config file (see README for details)', metavar='config-file',
                        default=os.path.join(str(Path.home()), ".valhalla"))
    parser.add_argument('-o', help='output file', metavar='output-file', default=ValhallaAPI.DEFAULT_OUTPUT_FILE)
    parser.add_argument('--check', action='store_true', default=False,
                        help='Check subscription info and total rule count')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
    parser.add_argument('-s', action='store_true', default=False, help='Load Sigma rules')

    group_proxy = parser.add_argument_group(
        '=======================================================================\nProxy')
    group_proxy.add_argument('-p', help='proxy URL (e.g. https://my.proxy.net:8080)', metavar='proxy-url', default='')
    group_proxy.add_argument('-pu', help='proxy user', metavar='proxy-user', default='')
    group_proxy.add_argument('-pp', help='proxy password', metavar='proxy-pass', default='')

    group_filter = parser.add_argument_group(
        '=======================================================================\nFilter')
    group_filter.add_argument('-fp', help='filter product (valid products are: %s)' %
                                          ", ".join(ValhallaAPI.PRODUCT_IDENTIFIER),
                              metavar='product', default='')
    group_filter.add_argument('-fv', help='get rules that support the given YARA version and lower',
                              metavar='yara-version', default='')
    group_filter.add_argument('-fm', help='set a list of modules that your product supports (e.g. "-fm pe hash") '
                                          '(setting no modules means that all modules are supported by your product)',
                              action='append', nargs='+', metavar='modules')
    group_filter.add_argument('-ft', help='set a list of tags to receive (e.g. "-ft APT MAL")',
                              action='append', nargs='+', metavar='tags')
    group_filter.add_argument('-fs', help='minimum score of rules to retrieve (e.g. "-fs 75")',
                              metavar='score', default=0)
    group_filter.add_argument('-fq', help='get only rules that match a certain keyword in name or description '
                                          '(e.g. "-fq Mimikatz")', metavar='query', default='')
    group_filter.add_argument('--nocrypto', help='filter all rules that require YARA to be compiled with crypto '
                                                 'support (OpenSSL)', action='store_false', default=True)

    group_proxy = parser.add_argument_group(
        '=======================================================================\nLookups')
    group_proxy.add_argument('-lr', help='Lookup a certain rule (returns matching samples)', metavar='lookup-rule',
                             default='')
    group_proxy.add_argument('-lh', help='Lookup a certain sample hash (sha256) (returns matching rules)',
                             metavar='lookup-hash', default='')
    group_proxy.add_argument('-lk', help='Lookup rules with a certain keyword (returns matching rules)',
                             metavar='lookup-keyword', default='')
    group_proxy.add_argument('-lkm', help='Lookup hashes of samples on which rules have matches that contain a certain '
                                          'keyword (returns matching sample hashes)',
                             metavar='lookup-keyword', default='')
    group_proxy.add_argument('-lo', help='Output file for the lookup output', metavar='lookup-output', default='')

    args = parser.parse_args()

    print(" ")
    print("===========================================================")
    print("   _   __     ____        ____         _______   ____ ")
    print("  | | / /__ _/ / /  ___ _/ / /__ _____/ ___/ /  /  _/ ")
    print("  | |/ / _ `/ / _ \\/ _ `/ / / _ `/___/ /__/ /___/ /   ")
    print("  |___/\\_,_/_/_//_/\\_,_/_/_/\\_,_/    \\___/____/___/   ")
    print("   Ver. %s, Florian Roth, 2021                        " % __version__)
    print(" ")
    print("===========================================================")
    print(" ")

    # Logging
    logFormatter = logging.Formatter("[%(levelname)-5.5s] %(message)s")
    logFormatterRemote = logging.Formatter("{0} [%(levelname)-5.5s] %(message)s".format(platform.uname()[1]))
    Log = logging.getLogger(__name__)
    Log.setLevel(logging.INFO)
    # Console Handler
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    Log.addHandler(consoleHandler)

    # API Key
    apikey = args.k
    Log.info("Trying to read Valhalla config file at '%s' (set manually with -c)" % args.c)
    if os.path.exists(args.c):
        Log.debug("Config file found at '%s'" % args.c)
        config = configparser.ConfigParser()
        config.read(args.c)
        if 'DEFAULT' not in config:
            Log.error("section [DEFAULT] missing in config file - skipping this config")
        else:
            apikey = config['DEFAULT']['APIKEY']
            Log.info("Successfully read config file")
    else:
        Log.info("No config file found, will rely on API KEY passed via cmd line arguments (-k)")

    # Check key
    if apikey == ValhallaAPI.DEMO_KEY:
        Log.warning("You are using the DEMO API key and will only retrieve the reduced open source signature set")
        Log.warning("Set your private API key with '-k APIKEY' to get the rule sets that your have subscribed")

    # Create the ValhallaAPI object
    v = ValhallaAPI(api_key=apikey)

    # Subscription check
    if args.check:
        status = v.get_subscription()
        if 'active' in status:
            if status['active']:
                Log.info("Account is active: %s" % status)
                sys.exit(0)
            else:
                Log.error("Account is inactive: %s" % status)
                sys.exit(1)
        else:
            Log.error("Error: %s" % status['message'])
            sys.exit(1)

    # Proxy
    if args.p:
        Log.info("Setting proxy URL: %s USER: %s PASS: (hidden)" % (args.p, args.pu))
        if args.p.startswith("http:"):
            Log.warning("URL starts with http instead of https - you should use a TLS encrypted connection")
        v.set_proxy(args.p, args.pu, args.pp)

    # Default: Get all rules that the set API key is subscribed to
    # prepare some variables
    modules = []
    if args.fm:
        modules = args.fm[0]
    tags = []
    if args.ft:
        tags = args.ft[0]

    # Lookups
    if args.lr or args.lh or args.lk or args.lkm:
        # Rule Lookup
        if args.lr != "":
            if args.s:
                r = v.get_sigma_rule_info(args.lr)
            else:
                r = v.get_rule_info(args.lr)
        # Hash Lookup
        if args.lh != "":
            r = v.get_hash_info(args.lh)
        # Keyword to Rules Lookup
        if args.lk != "":
            r = v.get_keyword_rules(args.lk)
        # Keyword to Rule Matches Lookup
        if args.lkm != "":
            r = v.get_keyword_rule_matches(args.lkm)

        # Write them to an output file
        if args.lo:
            with open(args.lo, 'w') as fh:
                fh.write(json.dumps(r, indent=4, sort_keys=True))
        else:
            # Show results
            print(json.dumps(r, indent=4, sort_keys=True))
        sys.exit(0)

    # Score warning
    if args.fs == 0:
        Log.warning("Note that an unfiltered set (-fs 0) contains low scoring rules used for threat hunting purposes")

    # Info output
    Log.info("Retrieving rules with params PRODUCT: %s MAX_VERSION: %s MODULES: %s WITH_CRYPTO: %s TAGS: %s "
             "SCORE: %s QUERY: %s" % (
                 args.fp,
                 args.fv,
                 ", ".join(modules),
                 str(args.nocrypto),
                 ", ".join(tags),
                 str(args.fs),
                 args.fq
             ))

    # Retrieve rules
    try:
        if args.s:
            response = v.get_sigma_rules_zip(
                search=args.fq,
            )
        else:
            response = v.get_rules_text(
                product=args.fp,
                max_version=args.fv,
                modules=modules,
                with_crypto=args.nocrypto,
                tags=tags,
                score=int(args.fs),
                search=args.fq,
            )
    except UnknownProductError as e:
        Log.error("Unknown product identifier - please use one of these: %s", ", ".join(ValhallaAPI.PRODUCT_IDENTIFIER))
        sys.exit(1)
    except ApiError as e:
        Log.error(e.message)
        sys.exit(1)

    # Response information
    Log.info("Number of retrieved rules: %d" % v.last_retrieved_rules_count)

    # Output
    output_file = args.o
    # Tanium accepts only the ".yara" extension for imports
    if args.fp == "Tanium" and output_file == ValhallaAPI.DEFAULT_OUTPUT_FILE:
        output_file = "valhalla-rules.yara"
    if args.s and output_file == ValhallaAPI.DEFAULT_OUTPUT_FILE:
        output_file = "valhalla-rules.zip"
    # Write to the output file
    Log.info("Writing retrieved rules into: %s" % output_file)
    if args.s:
        with open(output_file, 'wb') as fh:
            fh.write(response)
    else:
        with open(output_file, 'w') as fh:
            fh.write(response)



if __name__ == "__main__":
    main()
