#!/usr/bin/env python3
import argparse
import json
import logging
import os
import sys

from core.services.fuzzer import Fuzzer
from core.services.input import get_user_input
from core.services.parser import parse_domain, validate_domain, InvalidDomainError
from core.services import export as export_service

BANNER = r"""
██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗███████╗ █████╗ ██████╗ ██╗
██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██║
███████║██║   ██║██║   ██║█████╔╝ ███████╗███████║██║  ██║██║
██╔══██║██║   ██║██║   ██║██╔═██╗ ╚════██║██╔══██║██║  ██║██║
██║  ██║╚██████╔╝╚██████╔╝██║  ██╗███████║██║  ██║██████╔╝██║
╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝

        Advanced Domain Based Phishing & Impersonating
                     Domain Detection Tool

                         HookSadi
"""
DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(__file__), "data", "homoglyph", "model.json")


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="domain-fuzzer",
        description="Generate typosquatting/homoglyph variations of a domain and "
                    "check which ones are live, so phishing/impersonation domains "
                    "can be spotted and reported.",
    )
    p.add_argument("domain", nargs="?", help="Domain to analyze, e.g. example.com. "
                                              "If omitted, you'll be prompted interactively.")
    p.add_argument("-o", "--output", metavar="FILE",
                    help="Write results to FILE. Format is inferred from extension "
                         "(.json or .csv); defaults to CSV.")
    p.add_argument("-t", "--threads", type=int, default=20,
                    help="Number of concurrent worker threads for HTTP/DNS/WHOIS checks "
                         "(default: 20).")
    p.add_argument("--timeout", type=float, default=5.0,
                    help="Per-request network timeout in seconds (default: 5).")
    p.add_argument("--no-whois", action="store_true",
                    help="Skip WHOIS abuse-contact lookups (much faster; WHOIS "
                         "servers are often rate-limited).")
    p.add_argument("--no-progress", action="store_true", help="Disable the progress bar.")
    p.add_argument("--model", default=DEFAULT_MODEL_PATH,
                    help=f"Path to the homoglyph model JSON (default: {DEFAULT_MODEL_PATH}).")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress the banner.")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    return p


def load_homoglyphs(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Homoglyph model not found at '{path}'.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Homoglyph model at '{path}' is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    args = build_arg_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    if not args.quiet:
        print(BANNER)

    homoglyphs = load_homoglyphs(args.model)

    raw_input_domain = args.domain or get_user_input()

    try:
        domain = parse_domain(raw_input_domain)
    except InvalidDomainError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    if not validate_domain(domain):
        print(f"[ERROR] '{domain}' doesn't look like a valid domain name.", file=sys.stderr)
        sys.exit(1)

    fuzzer = Fuzzer(homoglyphs)

    try:
        results = fuzzer.scan(
            domain,
            threads=args.threads,
            timeout=args.timeout,
            do_whois=not args.no_whois,
            show_progress=not args.no_progress,
        )
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted, exiting.", file=sys.stderr)
        sys.exit(130)

    print("\n")
    print(Fuzzer.render_table(results))

    if args.output:
        export_service.export(results, args.output)
        print(f"\n[INFO] Results written to {args.output}")


if __name__ == "__main__":
    main()
