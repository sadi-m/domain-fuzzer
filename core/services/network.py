"""HTTP availability and DNS resolution checks for candidate domains.

These were previously duplicated (with a stray, unused `self` parameter) inside
fuzzer.py. They're now plain functions that fuzzer.py's scanner composes with.
"""
import requests
import dns.resolver

# Reuse a single session so repeated requests benefit from connection pooling
# instead of opening a fresh TCP/TLS handshake for every one of the (often
# hundreds of) generated domain variations.
_session = requests.Session()
_session.headers.update({"User-Agent": "domain-fuzzer/1.1 (+phishing-detection scan)"})


def check_availability(domain: str, timeout: float = 5.0):
    """Check whether an HTTP server responds on `domain`.

    Returns (status, final_url). status is an int HTTP status code on success,
    or one of "ERR" / "TIMEOUT" on failure.
    """
    try:
        response = _session.get(f"http://{domain}", timeout=timeout, allow_redirects=True)
        return response.status_code, response.url
    except requests.Timeout:
        return "TIMEOUT", None
    except requests.RequestException:
        return "ERR", None


def get_ip_address(domain: str, timeout: float = 5.0):
    """Resolve the A record for `domain`. Returns the IP string, or a status string."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "A")
        for answer in answers:
            return answer.address
        return "N/A"
    except dns.resolver.NXDOMAIN:
        return "N/A"
    except dns.resolver.NoAnswer:
        return "N/A"
    except dns.exception.Timeout:
        return "TIMEOUT"
    except Exception:
        return "N/A"
