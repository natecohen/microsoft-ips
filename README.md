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

### Dynamic Sources
- microsoft-365 - https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-endpoints
- azure - https://azureipranges.azurewebsites.net/Home/About
- office-mac - https://learn.microsoft.com/en-us/microsoft-365/enterprise/network-requests-in-office-2016-for-mac
- windows-11 - https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints
- entra-connect - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-connectivity
  - China's 21Vianet endpoints are not included due to lack of Markdown source - https://docs.azure.cn/zh-cn/entra/identity/hybrid/connect/tshoot-connect-connectivity
- entra-connect-health - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-agent-install 

### Static Sources
- wsus - https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus#21-configure-network-connections
- microsoft-365-additional - https://learn.microsoft.com/en-us/microsoft-365/enterprise/additional-office365-ip-addresses-and-urls
  - skype-business-hybrid-and-meetings
    - https://learn.microsoft.com/en-us/microsoftteams/troubleshoot/teams-sign-in/sign-in-loop
    - https://learn.microsoft.com/en-us/skypeforbusiness/plan-your-deployment/clients-and-devices/minimum-network-requirements
  - azure-mfa-server - https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfaserver-deploy

You may find Windows attempt direct IP connections for updates. Those that are a part of [Microsoft Connected Cache for ISPs](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/microsoft-connected-cache-for-isps-microsoft-s-distributed-cdn/ba-p/3891604) are not published.

## Related Projects

- https://github.com/blrchen/azure-ip-lookup