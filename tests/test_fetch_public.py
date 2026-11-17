import json
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from rofi_rbw.argument_parsing import parse_arguments
from rofi_rbw.models.entry import Entry
from rofi_rbw.models.targets import Target, Targets, TypeTarget, TypeTargets, needs_no_secret
from rofi_rbw.rbw import Rbw


@pytest.mark.parametrize(
    ("targets", "expected"),
    [
        ([Targets.USERNAME], True),
        ([Targets.USERNAME, TypeTargets.TAB], True),
        ([Target("uri")], True),
        ([Target("uri 2"), TypeTargets.ENTER], True),
        ([Targets.USERNAME, TypeTargets.TAB, Targets.PASSWORD], False),
        ([Targets.PASSWORD], False),
        ([Targets.TOTP], False),
        ([Targets.NOTES], False),
        ([Targets.MENU], False),
        ([Targets.USERNAME, Targets.MENU], False),
        ([], False),
        (None, False),
    ],
    ids=["username", "username+tab", "uri", "uri2+enter", "username+tab+password", "password", "totp", "notes", "menu",
         "username+menu", "empty", "none"],
)
def test_needs_no_secret(targets, expected):
    assert needs_no_secret(targets) is expected


LOGIN = {
    "id": "x", "folder": None, "name": "site",
    "data": {"username": "me", "password": None, "totp": None, "uris": []},
    "fields": [], "notes": None, "history": [],
}


def fetch(entry_type, public):
    with patch("rofi_rbw.rbw.run", return_value=CompletedProcess([], 0, stdout=json.dumps(LOGIN))) as run:
        Rbw().fetch_credentials(Entry("site", "work", "me", entry_type, []), public=public)
    return run.call_args.args[0]


def test_public_adds_flag_for_logins():
    assert fetch("Login", True) == ["rbw", "get", "--raw", "site", "me", "--folder", "work", "--public"]


def test_no_flag_by_default():
    assert "--public" not in fetch("Login", False)


def test_public_entry_has_empty_password_and_no_totp():
    with patch("rofi_rbw.rbw.run", return_value=CompletedProcess([], 0, stdout=json.dumps(LOGIN))):
        c = Rbw().fetch_credentials(Entry("site", "", "me", "Login", []), public=True)
    assert (c.username, c.password, c.has_totp) == ("me", "", False)

# bw-autotype's keybindings line (config/rofi-rbw.rc). rofi-rbw builds EVERY target of a keybinding as a TypeTarget, so this is the
# shape the real program passes to needs_no_secret; testing with plain Targets.* alone hid a bug that treated every keybinding as secret-free.
BW_AUTOTYPE_KEYBINDINGS = ("Alt+1:type:username:tab:password,Alt+2:type:username,Alt+3:type:password,Alt+4:type:totp,"
                           "Alt+u:copy:username,Alt+t:copy:totp,Alt+h:copy:cardholder,Alt+m::menu,Alt+s:sync")


@pytest.mark.parametrize(
    ("shortcut", "expected"),
    [
        ("Alt+1", False),   # username, tab, password
        ("Alt+2", True),    # username only
        ("Alt+3", False),   # password only
        ("Alt+4", False),   # totp
        ("Alt+u", True),    # copy the username
        ("Alt+t", False),   # copy the totp
        ("Alt+h", False),   # copy the cardholder
        ("Alt+m", False),   # menu
        ("Alt+s", False),   # sync (no targets)
    ],
)
def test_real_keybindings_only_username_only_operations_need_no_secret(shortcut, expected):
    args = parse_arguments(["--keybindings", BW_AUTOTYPE_KEYBINDINGS])
    kb = next(k for k in args.parsed_keybindings if k.shortcut == shortcut)
    assert needs_no_secret(kb.targets) is expected


def test_every_keybinding_target_is_a_typetarget():
    """The reason the check must use the target's value: the class is the same for secrets and non-secrets."""
    args = parse_arguments(["--keybindings", BW_AUTOTYPE_KEYBINDINGS])
    kb = next(k for k in args.parsed_keybindings if k.shortcut == "Alt+3")
    assert all(isinstance(t, TypeTarget) for t in kb.targets)
    assert needs_no_secret(kb.targets) is False
