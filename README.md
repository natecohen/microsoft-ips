This repository provides text-file lists of Microsoft owned IP address ranges and service endpoint domain names in various formats, for use with software such as firewalls or DNS categorization.

For some categories, results are split by endpoint including Worldwide, US Gov DoD, US Gov GCC High, and China (21Vianet).

Some may be split further by service, and include an "All" subfolder with combined values.

## Formats

-  FQDNs including wildcards
-  FQDNs excluding wildcards
-  Mixed IPv4/IPv6 networks in CIDR notation
-  IPv6 networks in CIDR notation
-  IPv4 networks in CIDR notation

## Sources

- microsoft-365 - https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-endpoints?view=o365-worldwide
  - Microsoft provides JSON and CSV

## Todo

- Automation using Github Actions
- Addition of more services

## Will not implement

- IPv4 flattened lists
  - Microsoft owns too many IPs to make this practical, and I have not found any modern software which would benefit from this that doesn't already understand CIDR notation input