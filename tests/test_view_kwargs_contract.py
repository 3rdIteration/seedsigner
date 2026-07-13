"""
Static contract test for the View layer.

Every ``self.run_screen(SomeScreen, **kwargs)`` call instantiates
``SomeScreen(**kwargs)``, and every ``Destination(SomeView, view_args={...})``
is later instantiated by the Controller as ``SomeView(**view_args)``. If a call
passes a keyword the target's ``__init__`` does not accept, it raises
``TypeError: __init__() got an unexpected keyword argument ...`` at runtime — a
whole flow crashes, and unit tests that don't drive that exact screen won't
catch it. This is exactly how stale kwargs survive an upstream merge (e.g. a
``has_passphrase=False`` left on a Keycard xpub-export screen).

This test walks every module under ``seedsigner.views`` and statically verifies
that the kwargs of each such call are a subset of the target's accepted
parameters. It renders nothing and touches no hardware. It is deliberately
conservative: any call whose target class or kwargs can't be resolved purely
statically (dynamic class, ``**spread``, ``VAR_KEYWORD`` sink) is skipped rather
than guessed.
"""
import ast
import importlib
import inspect
import os
import pkgutil

import seedsigner.views as views_pkg

# Importing some view modules standalone triggers the lazy/circular imports the
# app only performs at call-time; importing these first resolves the ordering.
_PRIORITY = ["view", "seed_views", "tools_views", "gpg_views", "password_generator_views"]


def _view_modules():
    view_dir = os.path.dirname(views_pkg.__file__)
    names = [n for _, n, _ in pkgutil.iter_modules([view_dir]) if n != "__init__"]
    ordered = [n for n in _PRIORITY if n in names] + [n for n in names if n not in _PRIORITY]
    return [importlib.import_module(f"seedsigner.views.{n}") for n in ordered]


def _accepted_params(cls):
    """Return (param_names, accepts_var_keyword), or (None, False) if unresolvable."""
    try:
        sig = inspect.signature(cls)
    except (ValueError, TypeError):
        return None, False
    names, var_kw = set(), False
    for p in sig.parameters.values():
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            var_kw = True
        elif p.kind != inspect.Parameter.VAR_POSITIONAL:
            names.add(p.name)
    return names, var_kw


def _resolve_class(node, namespace):
    """Resolve a dotted-name/name AST node to a class object, else None."""
    if not isinstance(node, (ast.Name, ast.Attribute)):
        return None
    try:
        obj = eval(ast.unparse(node), namespace)  # noqa: S307 - trusted first-party source
    except Exception:
        return None
    return obj if isinstance(obj, type) else None


def _static_dict_keys(node):
    """String keys of a ``{...}`` literal or ``dict(...)`` call; None if any key is dynamic."""
    if isinstance(node, ast.Dict):
        keys = set()
        for k in node.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                keys.add(k.value)
            else:
                return None  # e.g. **spread into the dict literal
        return keys
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        if any(kw.arg is None for kw in node.keywords):
            return None
        return {kw.arg for kw in node.keywords}
    return None


def _collect_findings():
    findings = []
    for mod in _view_modules():
        with open(mod.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        rel = os.path.relpath(mod.__file__, os.path.dirname(os.path.dirname(views_pkg.__file__)))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func

            # self.run_screen(Screen_cls, **kwargs)  ->  Screen_cls(**kwargs)
            if isinstance(func, ast.Attribute) and func.attr == "run_screen" and node.args:
                if any(kw.arg is None for kw in node.keywords):
                    continue  # **spread — can't validate statically
                cls = _resolve_class(node.args[0], mod.__dict__)
                if cls is None:
                    continue
                names, var_kw = _accepted_params(cls)
                if names is None or var_kw:
                    continue
                bad = {kw.arg for kw in node.keywords} - names
                if bad:
                    findings.append(
                        f"{rel}:{node.lineno}  run_screen({cls.__name__})  "
                        f"unexpected kwargs: {sorted(bad)}"
                    )

            # Destination(View_cls, view_args={...})  ->  View_cls(**view_args)
            if isinstance(func, ast.Name) and func.id == "Destination":
                view_cls = _resolve_class(node.args[0], mod.__dict__) if node.args else None
                view_args_node = None
                for kw in node.keywords:
                    if kw.arg == "View_cls":
                        view_cls = _resolve_class(kw.value, mod.__dict__)
                    elif kw.arg == "view_args":
                        view_args_node = kw.value
                if view_cls is None or view_args_node is None:
                    continue
                keys = _static_dict_keys(view_args_node)
                if keys is None:
                    continue
                names, var_kw = _accepted_params(view_cls)
                if names is None or var_kw:
                    continue
                bad = keys - names
                if bad:
                    findings.append(
                        f"{rel}:{node.lineno}  Destination({view_cls.__name__})  "
                        f"unexpected view_args: {sorted(bad)}"
                    )
    return findings


def test_run_screen_and_destination_kwargs_match_targets():
    findings = _collect_findings()
    assert not findings, (
        "View-layer calls pass keyword args their target Screen/View does not accept "
        "(would raise TypeError at runtime):\n  " + "\n  ".join(findings)
    )
