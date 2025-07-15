import re

RE_URL = re.compile(r"((?:<.*?>\.)?(?:(?:\*\.?)?[A-Za-z0-9\-]+\.)+(?!md[#)])[a-z]{2,})(?:/.*?(?:\s|$))?")
RE_IPV6 = re.compile(r"(\b(?:[0-9a-f]+:){2,}(?::|[0-9a-fA-F]{1,4})/\d{1,3})")
RE_IPV4 = re.compile(r"(\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b)")
RE_MDTABLE = re.compile(r"(^\|.*\|$\r?\n\|(?:\s|:)?-+.*\|(?:\r?\n\|.*\|)+)", re.MULTILINE)
