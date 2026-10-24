"""Every annotation must resolve, also on an interpreter that evaluates them.

Python 3.14 (PEP 649) defers annotations, so a missing import used only inside
an annotation raises nothing locally. Python 3.12 — what CI uses — evaluates
them at import time and the whole test session dies at collection with
`NameError: name 'Any' is not defined`.

That exact bug shipped in 0.5.0 (lassi/devices.py used `Any` without importing
it, CI run 62/63 red, invisible on the 3.15 laptop). Resolving the hints
explicitly reproduces the strict behaviour on any interpreter.
"""

import importlib
import inspect
import typing

import pytest

MODULES = (
    "app",
    "lassi.devices",
    "lassi.discovery",
    "lassi.firewall",
    "lassi.live",
    "lassi.ml",
    "lassi.simulator",
    "lassi.state",
)


def _callables(module):
    for name, obj in vars(module).items():
        if name.startswith("__"):
            continue
        if inspect.isfunction(obj) and obj.__module__ == module.__name__:
            yield f"{module.__name__}.{name}", obj
        elif inspect.isclass(obj) and obj.__module__ == module.__name__:
            for attr, value in vars(obj).items():
                if inspect.isfunction(value):
                    yield f"{module.__name__}.{obj.__name__}.{attr}", value


@pytest.mark.parametrize("module_name", MODULES)
def test_all_annotations_can_be_resolved(module_name: str) -> None:
    module = importlib.import_module(module_name)
    broken = []
    for label, func in _callables(module):
        try:
            typing.get_type_hints(func)
        except NameError as exc:
            broken.append(f"{label}: {exc}")
    assert not broken, "annotations reference undefined names:\n" + "\n".join(broken)
