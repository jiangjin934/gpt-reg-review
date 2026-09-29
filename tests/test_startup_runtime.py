from pathlib import Path

import start_webui


def test_vendor_available_requires_readable_runtime_dependencies(tmp_path, monkeypatch):
    vendor = tmp_path / ".vendor"
    monkeypatch.setattr(start_webui, "VENDOR", vendor)

    assert start_webui.vendor_available() is False

    fastapi_init = vendor / "fastapi" / "__init__.py"
    fastapi_init.parent.mkdir(parents=True)
    fastapi_init.write_text("", encoding="utf-8")
    (vendor / "typing_extensions.py").write_text("", encoding="utf-8")

    assert start_webui.vendor_available() is True


def test_activate_vendor_leaves_path_unchanged_when_runtime_is_not_importable(tmp_path, monkeypatch):
    vendor = tmp_path / ".vendor"
    fastapi_init = vendor / "fastapi" / "__init__.py"
    fastapi_init.parent.mkdir(parents=True)
    fastapi_init.write_text("", encoding="utf-8")
    (vendor / "typing_extensions.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(start_webui, "VENDOR", vendor)
    monkeypatch.setattr(start_webui, "_runtime_dependencies_importable", lambda: False)

    assert start_webui._activate_vendor() is False
    assert str(vendor) not in start_webui.sys.path
