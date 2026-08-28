"""Domain parsing and basic validation helpers."""
import re
from urllib.parse import urlparse

# Fairly permissive but practical domain validation: labels of letters/digits/hyphens,
# separated by dots, ending in a TLD of at least 2 alphabetic characters.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


class InvalidDomainError(ValueError):
    """Raised when the supplied input cannot be parsed into a usable domain."""


def parse_domain(user_input: str) -> str:
    """Normalize arbitrary user input (bare domain or full URL) into a bare domain.

    Accepts things like "example.com", "http://example.com/path", or
    "https://Example.COM:8080/" and returns "example.com".
    """
    if not user_input or not user_input.strip():
        raise InvalidDomainError("No domain provided.")

    candidate = user_input.strip()

    # urlparse only treats input as having a netloc if a scheme is present,
    # so add one if the user gave a bare domain.
    if "//" not in candidate:
        candidate = "//" + candidate

    parsed = urlparse(candidate)
    netloc = parsed.netloc or parsed.path
    # Strip credentials, port, and trailing slashes/whitespace.
    netloc = netloc.split("@")[-1].split(":")[0].strip().strip("/")
    domain = netloc.lower()

    if not domain:
        raise InvalidDomainError(f"Could not extract a domain from '{user_input}'.")

    return domain


def validate_domain(domain: str) -> bool:
    """Return True if `domain` looks like a syntactically valid domain name."""
    return bool(_DOMAIN_RE.match(domain))
