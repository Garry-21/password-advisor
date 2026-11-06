"""
tests/test_clipboard.py
-----------------------
Unit tests for clipboard integration and timed auto-clearing.
"""

import time
import pyperclip
from vault.clipboard import copy_with_auto_clear

def test_copy_with_auto_clear():
    secret = "TestClipboardSecret9988!"
    
    # Copy with short 0.5s auto-clear timeout
    success = copy_with_auto_clear(secret, auto_clear_seconds=0.5)
    assert success is True
    assert pyperclip.paste() == secret

    # Wait for background timer to trigger
    time.sleep(0.7)
    assert pyperclip.paste() == ""


def test_no_clear_if_user_copied_something_else():
    secret = "InitialSecret123!"
    copy_with_auto_clear(secret, auto_clear_seconds=0.5)
    
    # User immediately copies a different string
    pyperclip.copy("UserCopiedNewThing")

    # Wait for the initial timer to trigger
    time.sleep(0.7)
    # Clipboard should NOT be cleared because current content is different from original secret
    assert pyperclip.paste() == "UserCopiedNewThing"
    pyperclip.copy("")  # cleanup
