# aiodnsbl

[![PyPI version](https://badge.fury.io/py/aiodnsbl.svg)](https://badge.fury.io/py/aiodnsbl)
[![Python CI](https://github.com/ninoseki/aiodnsbl/actions/workflows/test.yml/badge.svg)](https://github.com/ninoseki/aiodnsbl/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/ninoseki/aiodnsbl/badge.svg?branch=main)](https://coveralls.io/github/ninoseki/aiodnsbl?branch=main)

[DNSBL](https://en.wikipedia.org/wiki/DNSBL) lists checker based on [aiodns](https://github.com/saghul/aiodns). Checks if an IP or a domain is listed on anti-spam DNS blacklists.

## Notes

This is a fork of [pydnsbl](https://github.com/dmippolitov/pydnsbl).

Key differences:

- Fully type annotated
- No sync wrapper (async only)
- No category classification

## Installation

```bash
pip install aiodnsbl
```

## Usage

```python
import asyncio

from aiodnsbl import DNSBLChecker


loop = asyncio.get_event_loop()

checker = DNSBLChecker()

# Check IP
loop.run_until_complete(checker.check("8.8.8.8"))
# <DNSBLResult: 8.8.8.8  (0/10)>
loop.run_until_complete(checker.check("68.128.212.240"))
# <DNSBLResult: 68.128.212.240 [BLACKLISTED] (4/10)>

# Check domain
loop.run_until_complete(checker.check("example.com"))
# <DNSBLResult: example.com  (0/4)>

# Bulk check
loop.run_until_complete(
    checker.bulk_check(["example.com", "8.8.8.8", "68.128.212.240"])
)
# [<DNSBLResult: example.com  (0/4)>, <DNSBLResult: 8.8.8.8  (0/10)>, <DNSBLResult: 68.128.212.240 [BLACKLISTED] (4/10)>]
```

```python
import asyncio

from aiodnsbl import DNSBLChecker


async def main():
    checker = DNSBLChecker()
    res = await checker.check("68.128.212.240")
    print(res)
    # <DNSBLResult: 68.128.212.240 [BLACKLISTED] (4/10)>
    print(res.blacklisted)
    # True
    print([provider.host for provider in res.providers])
    # ['b.barracudacentral.org', 'bl.spamcop.net', 'dnsbl.sorbs.net', 'ips.backscatterer.org', ...]
    print([provider.host for provider in res.detected_by])
    # ['b.barracudacentral.org', 'dnsbl.sorbs.net', 'spam.dnsbl.sorbs.net', 'zen.spamhaus.org']


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```
