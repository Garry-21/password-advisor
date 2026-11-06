"""
vault/clipboard.py
------------------
Clipboard integration with automatic timed clearing:
- Copies password/secret using pyperclip
- Spawns background daemon thread to overwrite clipboard after N seconds (default 20s)
- Only clears if clipboard still holds the exact copied value
"""

import threading
import pyperclip
from typing import Optional

_ACTIVE_TIMER: Optional[threading.Timer] = None


def _clear_clipboard_if_matches(original_text: str):
    try:
        current = pyperclip.paste()
        if current == original_text:
            pyperclip.copy("")
    except Exception:
        pass


def copy_with_auto_clear(text: str, auto_clear_seconds: int = 20) -> bool:
    """
    Copies text to OS clipboard and schedules automatic clearing after auto_clear_seconds.
    Returns True if successfully copied.
    """
    global _ACTIVE_TIMER
    try:
        pyperclip.copy(text)
    except Exception:
        return False

    # Cancel previous timer if still pending
    if _ACTIVE_TIMER and _ACTIVE_TIMER.is_alive():
        _ACTIVE_TIMER.cancel()

    if auto_clear_seconds > 0:
        _ACTIVE_TIMER = threading.Timer(auto_clear_seconds, _clear_clipboard_if_matches, args=(text,))
        _ACTIVE_TIMER.daemon = True
        _ACTIVE_TIMER.start()

    return True


def copy_to_clipboard(text: str, timeout_seconds: int = 20) -> bool:
    """Convenience alias for copy_with_auto_clear."""
    return copy_with_auto_clear(text, auto_clear_seconds=timeout_seconds)

