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


def _required_params(cls):
    """
    Params with no default, which the caller must supply.

    Passing an unexpected kwarg and omitting a required one are the same class of
    bug -- both raise TypeError the moment the View is instantiated -- but only
    the first is visible from the call site, so the second survives longer.
    """
    try:
        sig = inspect.signature(cls)
    except (ValueError, TypeError):
        return None
    return {
        p.name
        for p in sig.parameters.values()
        if p.default is inspect.Parameter.empty
        and p.kind not in (inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL)
    }


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
                # Destination(View_cls, view_args, ...) -- view_args is frequently
                # passed positionally, which this check used to skip entirely.
                view_args_node = node.args[1] if len(node.args) > 1 else None
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


def _collect_screenshot_findings():
    """
    The screenshot generator instantiates Views directly via ScreenshotConfig, so it
    breaks the same way the View layer does -- but it cannot run on every dev machine
    (it needs libraqm, which Pillow's Windows wheels do not bundle), so a mismatch there
    reaches CI unnoticed. Check it statically alongside the views.
    """
    import importlib

    generator = os.path.join(os.path.dirname(__file__), "screenshot_generator", "generator.py")
    with open(generator, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())

    modules = {}
    for name in ("seed_views", "psbt_views", "tools_views", "settings_views",
                 "scan_views", "smartcard_views", "gpg_views", "view"):
        try:
            modules[name] = importlib.import_module(f"seedsigner.views.{name}")
        except Exception:
            pass

    findings = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "ScreenshotConfig"):
            continue
        if not node.args:
            continue
        target = node.args[0]
        cls_name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
        mod_name = getattr(target.value, "id", None) if isinstance(target, ast.Attribute) else None
        if not cls_name:
            continue

        # view_args is passed positionally or by keyword, as a {...} literal or a
        # dict(...) call; _static_dict_keys handles both forms.
        keys = _static_dict_keys(node.args[1]) if len(node.args) > 1 else None
        for kw in node.keywords:
            if kw.arg == "view_args":
                keys = _static_dict_keys(kw.value)
        if keys is None:
            # No view_args at all is not a reason to skip: the View may still
            # have required params. Only bail out when a view_args was given in
            # a form we cannot read statically.
            supplied = (len(node.args) > 1) or any(k.arg == "view_args" for k in node.keywords)
            if supplied:
                continue
            keys = set()

        search = ([modules[mod_name]] if mod_name in modules else []) + list(modules.values())
        view_cls = next((getattr(m, cls_name) for m in search if hasattr(m, cls_name)), None)
        if view_cls is None:
            continue
        names, var_kw = _accepted_params(view_cls)
        if names is None or var_kw:
            continue
        bad = keys - names
        if bad:
            findings.append(
                f"screenshot_generator/generator.py:{node.lineno}  "
                f"ScreenshotConfig({cls_name})  unexpected view_args: {sorted(bad)}"
            )
        required = _required_params(view_cls) or set()
        missing = required - keys
        if missing:
            findings.append(
                f"screenshot_generator/generator.py:{node.lineno}  "
                f"ScreenshotConfig({cls_name})  missing required view_args: {sorted(missing)}"
            )
    return findings


def test_screenshot_generator_kwargs_match_targets():
    findings = _collect_screenshot_findings()
    assert not findings, (
        "The screenshot generator passes keyword args its target View does not accept "
        "(would raise TypeError when CI generates screenshots):\n  " + "\n  ".join(findings)
    )


def test_run_screen_and_destination_kwargs_match_targets():
    findings = _collect_findings()
    assert not findings, (
        "View-layer calls pass keyword args their target Screen/View does not accept "
        "(would raise TypeError at runtime):\n  " + "\n  ".join(findings)
    )
