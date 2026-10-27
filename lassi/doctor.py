"""Backward-compatible alias for LassiVet (`lassi.vet`).

The command was introduced as `lassi.doctor`; `python -m lassi.doctor` keeps
working, but the friendly name is now **LassiVet**:

    python -m lassi.vet
"""

from lassi.vet import (Check, _add, _report_text, _summary,  # noqa: F401
                       check_environment, main)

if __name__ == "__main__":
    raise SystemExit(main())
