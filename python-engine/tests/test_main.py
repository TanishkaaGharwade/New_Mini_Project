"""Command-line options of main.py."""

import pytest

import main
from config import DETECT_ONLY


@pytest.mark.parametrize("argv,detect_only", [
    ([], DETECT_ONLY),               # no option: config.py decides
    (["--block"], False),
    (["--detect-only"], True),
])
def test_mode_options(argv, detect_only):
    assert main.parse_args(argv).detect_only is detect_only


def test_block_and_detect_only_cannot_be_combined():
    with pytest.raises(SystemExit):
        main.parse_args(["--block", "--detect-only"])
