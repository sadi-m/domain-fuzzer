"""WHOIS lookups used to find an abuse-reporting contact for a domain."""
import whois


def get_abuse_contact(domain: str) -> str:
    """Best-effort lookup of an abuse contact email for `domain`.

    Returns "N/A" if the domain is unregistered/unreachable or no usable
    email address is found.
    """
    try:
        domain_info = whois.whois(domain)
    except Exception:
        return "N/A"

    if domain_info is None:
        return "N/A"

    status = domain_info.status
    if status is None:
        return "N/A"
    # Some registries return the literal string "No match for <domain>" as status.
    if isinstance(status, str) and "no match for" in status.lower():
        return "N/A"

    emails = domain_info.emails

    if isinstance(emails, list):
        valid_emails = [e.lower() for e in emails if isinstance(e, str) and "@" in e]
        if not valid_emails:
            return "N/A"
        abuse_emails = [e for e in valid_emails if "abuse" in e]
        if abuse_emails:
            return abuse_emails[0]
        return min(valid_emails, key=len)

    if isinstance(emails, str):
        email = emails.lower()
        return email if "abuse" in email and "@" in email else "N/A"

    return "N/A"
