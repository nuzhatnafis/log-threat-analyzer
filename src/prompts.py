"""
Shared interactive prompt helpers.
"""
import os
import sys
import getpass
from urllib.parse import urlparse


def _read(prompt):
    """input() wrapper that exits cleanly on Ctrl-D / Ctrl-C."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\n\n  Cancelled.")
        sys.exit(1)


def banner(title):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


def ask_text(label, default=None, validator=None):
    """Ask for text. Re-asks until validator (if any) passes."""
    suffix = f" [{default}]" if default else ""
    while True:
        value = _read(f"  {label}{suffix}: ").strip() or (default or "")
        if not value:
            print("  ! A value is required.")
            continue
        if validator:
            error = validator(value)
            if error:
                print(f"  ! {error}")
                continue
        return value


def ask_yes_no(label, default=True):
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        answer = _read(f"  {label} {hint}: ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  ! Please answer y or n.")


def ask_int(label, default, min_v, max_v):
    while True:
        raw = _read(f"  {label} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("  ! Enter a whole number.")
            continue
        if not (min_v <= value <= max_v):
            print(f"  ! Must be between {min_v} and {max_v}.")
            continue
        return value


def ask_choice(label, choices, default):
    """choices: list of strings. Returns the chosen string."""
    shown = "/".join(choices)
    while True:
        answer = _read(f"  {label} ({shown}) [{default}]: ").strip().lower()
        if not answer:
            return default
        if answer in choices:
            return answer
        print(f"  ! Choose one of: {shown}")


def validate_url(value):
    candidate = value if value.startswith(("http://", "https://")) else "http://" + value
    parsed = urlparse(candidate)
    if not parsed.netloc or "." not in parsed.netloc and parsed.netloc != "localhost":
        return "That doesn't look like a valid URL (example: http://testphp.vulnweb.com)"
    return None


def validate_port_range(value):
    try:
        start, end = map(int, value.split("-"))
    except ValueError:
        return "Use the format START-END (example: 1-1024)"
    if not (1 <= start <= end <= 65535):
        return "Ports must satisfy 1 <= START <= END <= 65535"
    return None


def confirm_authorization(target):
    """Make the user explicitly confirm they may test the target."""
    print(f"\n  Target: {target}")
    print("  Only scan systems you own or have written permission to test.")
    return ask_yes_no("Do you have authorization to test this target?", default=False)


def ask_save_path(default_filename, default_dir="reports", ext=".pdf"):
    """Ask where to save a file. Handles ~, directories, creation, overwrite."""
    default_path = os.path.join(default_dir, default_filename)
    print(f"\n  {'-'*58}\n  Save report\n  {'-'*58}")
    while True:
        raw = _read(
            f"  Enter path to save report\n"
            f"  [Press Enter for default: {default_path}]\n  > "
        ).strip()
        chosen = os.path.expanduser(os.path.expandvars(raw or default_path))

        if chosen.endswith(os.sep) or os.path.isdir(chosen):
            chosen = os.path.join(chosen, default_filename)
        if not chosen.lower().endswith(ext):
            chosen += ext

        parent = os.path.dirname(chosen) or "."
        if not os.path.isdir(parent):
            if ask_yes_no(f"Directory '{parent}' doesn't exist. Create it?", True):
                os.makedirs(parent, exist_ok=True)
            else:
                print("  Please choose a different path.\n")
                continue

        if os.path.exists(chosen):
            if not ask_yes_no(f"'{chosen}' already exists. Overwrite?", False):
                print("  Please choose a different path.\n")
                continue
        return chosen


def ask_secret(label):
    try:
        return getpass.getpass(f"  {label}: ")
    except (EOFError, KeyboardInterrupt):
        print("\n\n  Cancelled.")
        sys.exit(1)
