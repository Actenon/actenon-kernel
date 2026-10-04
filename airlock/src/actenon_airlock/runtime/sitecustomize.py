"""Loaded by every Python process ``airlock run`` starts (PYTHONPATH). Installs the Airlock audit hook,
then runs the project's own ``sitecustomize`` if there is one further down ``sys.path``."""

import importlib.machinery
import importlib.util
import os
import sys

if os.environ.get("AIRLOCK_EDGE"):
    import _airlock_hook

    _airlock_hook.install()

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.machinery.PathFinder.find_spec("sitecustomize", [p for p in sys.path if os.path.abspath(p or ".") != _here])
if _spec is not None and _spec.loader is not None and _spec.origin and os.path.dirname(_spec.origin) != _here:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
