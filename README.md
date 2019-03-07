# valhallaAPI
Valhalla API Client

This module allows you to interact with the Valhalla API, retrieve rules in different formats, filter them and write them to disk.

The module provides functions to filter the retrieved YARA rules by 
- tags
- score
- required YARA version and required YARA modules
- search queries
- date

## Usage

Get a service status (does not require a valid API key)
```python
from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key="")
status = v.test_status()
```

### Text Rules

Get all subscribed rules as text and save them to a file
```python
from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key="Your API Key")
response = v.get_rules_text()

with open('valhalla-rules.yar') as fh:
    fh.write(response)
```

Get all subscribed rules with a minimum score of 75 and save it to a file
```python
response = v.get_rules_text(score=75)
```

Get all subscribed rules that contain the keyword `Mimikatz` and save them to a file
```python
response = v.get_rules_text(search="Mimikatz")
```

Get all subscribed rules for your scan engine, which suppports YARA up to version `3.2.0` and the `pe` module, and save them to a file
```python
response = v.get_rules_text(max_version="3.2.0", modules=['pe'])
```

Get all subscribed rules for your `FireEyeNX` and save them to a file
```python
response = v.get_rules_text(product="FireEyeEX")
```

An example response will look like
```
/*
    VALHALLA YARA RULE SET
    Retrieved: 2019-02-25 14:54
    Generated for User: a67
    Number of Rules: 8127
    ANY REPRODUCTION OR DISTRIBUTION IS STRICTLY PROHIBITED WITHOUT THE PRIOR WRITTEN CONSENT OF NEXTRON SYSTEMS AND MAY RESULT IN LEGAL ACTION AS WELL AS THE TERMINATION OF THE CONTRACTUAL RELATIONSHIP
*/

import "pe"

rule SUSP_Katz_PDB_RID664 : EXE SUSP DEMO FILE {
   meta:
      description = "Detects suspicious PDB in file"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-02-04 10:32:31"
      score = 70
      customer = "demo"
      copyright = "Distribution to third parties is not permitted and will be pursued with legal measurements" 
      minimum_yara = "1.7"
      
   strings:
      $s1 = /\\Release\\[a-z]{0,8}katz.pdb/ 
      $s2 = /\\Debug\\[a-z]{0,8}katz.pdb/ 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and all of them
} 
...
```

### JSON Output

Get all subscribed rules with the `APT` tag as `JSON` and save them to a file
```python
from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key="Your API Key")
response = v.get_rules_json(tags=['APT'])

with open('valhalla-rules.json') as fh:
    fh.write(response)
```

An example response will look like
```json
{
  "api_version": "1.0", 
  "copyright": "Nextron Systems GmbH", 
  "customer": "demo", 
  "date": "2019-03-07 10:55", 
  "legal_note": "Any reproduction or distribution is strictly prohibited without the prior written consent of Nextron Systems and may result in legal action as well as the termination of the contractual relationship", 
  "rules": [
    {
      "author": "Florian Roth", 
      "content": "rule EXP_Libre_Office_CVE_2018_16858_RIDBA9 : EXPLOIT OFFICE DEMO FILE {\n   meta:\n      description = \"Detects exploits addressing CVE-2018-16858 in LibreOffice - modified version\"\n      author = \"Florian Roth\"\n      reference = \"https://insert-script.blogspot.com/2019/02/libreoffice-cve-2018-16858-remote-code.html\"\n      date = \"2019-02-05 14:17:21\"\n      score = 70\n      customer = \"demo\"\n      copyright = \"Distribution to third parties is not permitted and will be pursued with legal measurements\" \n      minimum_yara = \"1.7\"\n      \n   strings:\n      $x1 = \"&#x74;&#x65;&#x6d;&#x70;&#x66;&#x69;&#x6c;&#x65;&#x70;&#x61;&#x67;&#x65;&#x72\" \n      $x2 = \"&#116;&#101;&#109;&#112;&#102;&#105;&#108;&#101;&#112;&#97;&#103;&#101;&#114;\" \n      $s1 = \"xlink:href=\\\"vnd.sun.star.script:\" ascii nocase\n      $s2 = \".py$tempfilepager\" ascii nocase\n      $s3 = \"language=Python\" ascii nocase\n   condition: \n      uint32be ( 0 ) == 0x3c3f786d and all of them or 1 of ( $x* )\n}", 
      "date": "2019-02-05 12:54:31", 
      "description": "Detects exploits addressing CVE-2018-16858 in LibreOffice - modified version", 
      "minimum_yara": "1.7", 
      "name": "EXP_Libre_Office_CVE_2018_16858_RID9B8", 
      "reference": "https://insert-script.blogspot.com/2019/02/libreoffice-cve-2018-16858-remote-code.html", 
      "required_modules": [], 
      "score": 70, 
      "tags": [
        "EXPLOIT", 
        "OFFICE", 
        "DEMO", 
        "FILE"
      ]
    }, 
  ...
```

### Rule Info

Get all subscribed rules with the `APT` tag as `JSON` and save them to a file
```python
from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key="Your API Key")
response = v.get_rule_info(rulename="Casing_Anomaly_ByPass")

with open('valhalla-rules.json') as fh:
    fh.write(response)
```

An example output of a rule info request will look like
```json
{
  "author": "Florian Roth", 
  "av_ratio": 16.52, 
  "av_verdicts": {
    "clean": 1, 
    "malicious": 21, 
    "suspicious": 27
  }, 
  "date": "2019-01-17 11:50:21", 
  "description": "Detects suspicious casing of bypass statement", 
  "minimum_yara": "1.7", 
  "name": "Casing_Anomaly_ByPass_RID837", 
  "reference": "Internal Research", 
  "required_modules": [], 
  "rule_matches": [
    {
      "hash": "bdde03b5b4f94ec7dbf947f3099f2009efac43b69659f788f513d3e615b98353", 
      "positives": 24, 
      "size": 319485, 
      "timestamp": "Thu, 07 Mar 2019 06:29:06 GMT", 
      "total": 56
    }, 
    {
      "hash": "646d446fb11eae76ca8b6e54306bb022431a4f20cc8cef5daa40dd6ec3537aff", 
      "positives": 3, 
      "size": 573, 
      "timestamp": "Thu, 07 Mar 2019 00:15:07 GMT", 
      "total": 57
    }
  ], 
  "score": 60, 
  "tags": [
    "SUSP", 
    "CASING"
  ] 
}
```

## Scores

The following list explains the scores used in the rule sets. 

|Score|Type|Description|
|-----|----|-----------|
|1-39|Info|Low scoring rules used in our scanners (excluded from Valhalla)|
|40-59|Noteworthy|Anomaly and threat hunting rules|
|60-74|Suspicious|Rules for suspicious objects|
|75-100|Alert|Hard malicious matches|

## Important Notices

- Old rules are constantly improved and may have changed the next time you fetch the rule set.
- The rule date is the creation time of the rule, not the timestamp when it was inserted into the database. It takes 1-3 days until a rule gets inserted into the database after the QA. Running a scheduled job once a week that does only extract the the rules created in the last 7 days, will therefore inevitably miss new rules. 
- The full rule set contains YARA rules with scores lower than 60, which are meant for threat hunting and anomaly detection use cases. 
