"""Interactive prompt used when no domain is supplied on the command line."""


def get_user_input() -> str:
    while True:
        try:
            user_input = input("[INFO] Please enter domain: ")
        except EOFError:
            # No interactive stdin available (e.g. piped/non-tty input exhausted).
            raise SystemExit("\n[ERROR] No domain provided and no interactive input available.")
        print(" ")
        if user_input.strip():
            return user_input.strip()
