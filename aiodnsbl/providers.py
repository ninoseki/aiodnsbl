from dataclasses import dataclass
from typing import List


@dataclass
class Provider:
    host: str
    support_type: str = "ip"


_BASE_PROVIDERS = [
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "ips.backscatterer.org",
    "psbl.surriel.com",
    "sbl.spamhaus.org",
    "spam.dnsbl.sorbs.net",
    "ubl.unsubscore.com",
    "xbl.spamhaus.org",
    "zen.spamhaus.org",
]

# list of domain providers
_DOMAIN_PROVIDERS = [
    "uribl.spameatingmonkey.net",
    "multi.surbl.org",
    "rhsbl.sorbs.net ",
    "dbl.spamhaus.org",
]

BASE_PROVIDERS: List[Provider] = [Provider(host=host) for host in _BASE_PROVIDERS]
BASE_DOMAIN_PROVIDERS: List[Provider] = [
    Provider(host=host, support_type="domain") for host in _DOMAIN_PROVIDERS
]
PROVIDERS: List[Provider] = BASE_PROVIDERS + BASE_DOMAIN_PROVIDERS
