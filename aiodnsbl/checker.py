import abc
import asyncio
import functools
import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional

import aiodns
import idna
import pycares

from .providers import PROVIDERS, Provider


@functools.lru_cache(maxsize=256)
def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@functools.lru_cache(maxsize=256)
def normalize_domain(value: str) -> str:
    value = value.lower()
    return idna.encode(value).decode()


# https://regex101.com/r/vdrgm7/1
DOMAIN_REGEX = re.compile(
    r"^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--[a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$"
)


@functools.lru_cache(maxsize=256)
def is_domain(value: str) -> bool:
    value = normalize_domain(value)
    return DOMAIN_REGEX.match(value) is not None


def detect_request_type(request: str) -> str:
    if is_ip_address(request):
        return "ip"

    if is_domain(request):
        return "domain"

    raise ValueError(f"Should be a valid domain or an IP address, got {request}")


@dataclass
class DNSBLResponse:
    address: str
    provider: Provider
    results: Optional[List[pycares.ares_query_a_result]] = None
    error: Optional[aiodns.error.DNSError] = None


@dataclass
class DNSBLResult:
    address: str
    responses: List[DNSBLResponse]
    blacklisted: bool = False
    providers: List[Provider] = field(default_factory=list)
    failed_providers: List[Provider] = field(default_factory=list)
    detected_by: List[Provider] = field(default_factory=list)

    def __post_init__(self) -> None:
        for response in self.responses:
            provider = response.provider
            self.providers.append(provider)

            if response.error:
                self.failed_providers.append(provider)
                continue

            if not response.results:
                continue

            self.detected_by.append(provider)

            # set blacklisted to True if ip is detected with at least one dnsbl
            self.blacklisted = True

    def __repr__(self):
        blacklisted = "[BLACKLISTED]" if self.blacklisted else ""
        return f"<DNSBLResult: {self.address} {blacklisted} ({len(self.detected_by)}/{len(self.providers)})>"


class BaseDNSBLChecker(abc.ABC):
    def __init__(
        self,
        providers: List[Provider] = PROVIDERS,
        timeout: int = 5,
        tries: int = 2,
        concurrency: int = 200,
    ):
        self.providers = providers
        self._resolver = aiodns.DNSResolver(timeout=timeout, tries=tries)
        self._semaphore = asyncio.Semaphore(concurrency)

    async def dnsbl_request(self, request: str, provider: Provider) -> DNSBLResponse:
        results: Optional[List[pycares.ares_query_a_result]] = None
        error: Optional[aiodns.error.DNSError] = None
        query = self.prepare_query(request)
        dnsbl_query = f"{query}.{provider.host}"

        try:
            async with self._semaphore:
                results = await self._resolver.query(dnsbl_query, "A")
        except aiodns.error.DNSError as exc:
            if exc.args[0] != 4:  # 4: domain name not found:
                error = exc

        return DNSBLResponse(
            address=request, provider=provider, results=results, error=error
        )

    @abc.abstractmethod
    def prepare_query(self, request: str) -> str:
        """
        Prepare query to dnsbl
        """
        return NotImplemented

    async def check_async(self, request: str) -> DNSBLResult:
        # select providers
        selected_providers: List[Provider] = []
        request_type = detect_request_type(request)
        for provider in self.providers:
            if provider.support_type == request_type:
                selected_providers.append(provider)

        tasks = [
            self.dnsbl_request(request, provider) for provider in selected_providers
        ]
        responses = await asyncio.gather(*tasks)
        return DNSBLResult(address=request, responses=responses)

    async def check(self, request: str) -> DNSBLResult:
        return await self.check_async(request)

    async def bulk_check(self, requests: List[str]) -> List[DNSBLResult]:
        tasks = [self.check_async(request) for request in requests]
        return await asyncio.gather(*tasks)


class DNSBLChecker(BaseDNSBLChecker):
    def prepare_query(self, request: str) -> str:
        # check a request as an IP address
        if is_ip_address(request):
            address = ipaddress.ip_address(request)
            if address.version == 4:
                return ".".join(reversed(request.split(".")))

            if address.version == 6:
                # according to RFC: https://tools.ietf.org/html/rfc5782#section-2.4
                request_stripped = request.replace(":", "")
                return ".".join(reversed(list(request_stripped)))

            raise ValueError("Unknown ip version")

        domain = normalize_domain(request)
        if not is_domain(domain):
            raise ValueError(f"Should be a valid domain, got {domain}")

        return domain
