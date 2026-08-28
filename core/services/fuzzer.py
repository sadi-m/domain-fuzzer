"""Generates typosquatting/impersonation domain variations and scans them."""
import string
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from fuzzywuzzy import fuzz
from tabulate import tabulate
from tqdm import tqdm

from core.services import network, whois_query

log = logging.getLogger("domain-fuzzer")

HEADERS = ["#", "SC", "BASE DOMAIN", "IMPERSONATING DOMAIN", "SIMILARITY",
           "HTTP STATUS", "IP ADDRESS", "ABUSE E-MAIL"]


class Fuzzer:
    """Generates permutations of a domain name (typos, homoglyphs, hyphenation)
    and, optionally, scans each one for live HTTP/DNS presence and an abuse
    contact so the results can be triaged for phishing takedown.
    """

    def __init__(self, homoglyphs: dict):
        self.homoglyphs = homoglyphs or {}
        self.characters = string.ascii_lowercase + string.digits

    # ---- permutation algorithms -------------------------------------------------

    def add_character(self, domain):
        return [domain[:i] + c + domain[i:] for i in range(len(domain) + 1) for c in self.characters]

    def remove_character(self, domain):
        return [domain[:i] + domain[i + 1:] for i in range(len(domain))]

    def replace_character(self, domain):
        return [domain[:i] + c + domain[i + 1:] for i in range(len(domain)) for c in self.characters]

    def homoglyph_variations(self, domain):
        variations = []
        for i, char in enumerate(domain):
            for variant in self.homoglyphs.get(char, ()):
                variations.append(domain[:i] + variant + domain[i + 1:])
        return variations

    def hyphenation(self, domain):
        return [domain[:i] + "-" + domain[i:] for i in range(1, len(domain))]

    # ---- orchestration ------------------------------------------------------

    def generate_variations(self, domain: str):
        """Return a de-duplicated list of [technique, base_domain, variation] rows."""
        domain_parts = domain.split(".")
        domain_name = domain_parts[0]
        tld = ".".join(domain_parts[1:])

        techniques = (
            ("CA", self.add_character),
            ("CD", self.remove_character),
            ("CR", self.replace_character),
            ("HM", self.homoglyph_variations),
            ("HP", self.hyphenation),
        )

        seen = {domain}
        rows = []
        for code, fn in techniques:
            for variant_name in fn(domain_name):
                full = f"{variant_name}.{tld}" if tld else variant_name
                if full in seen:
                    continue
                seen.add(full)
                rows.append([code, domain, full])
        return rows

    def _scan_one(self, row, timeout, do_whois):
        _, base, variation = row
        status, _url = network.check_availability(variation, timeout=timeout)
        ip_address = network.get_ip_address(variation, timeout=timeout)
        abuse_email = whois_query.get_abuse_contact(variation) if do_whois else "SKIPPED"
        similarity = fuzz.ratio(base, variation)
        return row, similarity, status, ip_address, abuse_email

    def scan(self, domain: str, threads: int = 20, timeout: float = 5.0,
              do_whois: bool = True, show_progress: bool = True):
        """Generate variations of `domain` and concurrently check each one.

        Returns a list of result rows: [idx, technique, base, variation,
        similarity, http_status, ip_address, abuse_email].
        """
        rows = self.generate_variations(domain)
        results = []

        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            futures = [pool.submit(self._scan_one, row, timeout, do_whois) for row in rows]
            iterator = as_completed(futures)
            if show_progress:
                iterator = tqdm(iterator, total=len(futures), unit=" domains",
                                 desc="Scanning", ncols=100)
            for future in iterator:
                try:
                    (technique, base, variation), similarity, status, ip, abuse = future.result()
                except Exception as exc:  # keep scanning even if one worker blows up
                    log.debug("Worker failed: %s", exc)
                    continue
                results.append([technique, base, variation, similarity, status, ip, abuse])

        # Stable, readable ordering: most similar (most dangerous) variations first.
        results.sort(key=lambda r: r[3], reverse=True)
        for idx, row in enumerate(results, start=1):
            row.insert(0, idx)

        return results

    @staticmethod
    def render_table(results) -> str:
        return tabulate(results, HEADERS, tablefmt="simple")

    # Kept for backwards compatibility with the original CLI flow: generates,
    # scans, and prints in one call.
    def generate_domain_variations(self, domain: str, **scan_kwargs):
        results = self.scan(domain, **scan_kwargs)
        print("\n")
        print(self.render_table(results))
        return results
