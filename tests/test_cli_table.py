from __future__ import annotations

import sys

from cairn.cli import RED, _color, _fit, _table, _visible_len


def test_fit_preserves_ansi_and_visible_width(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.delenv("NO_COLOR", raising=False)
    colored = _color("HIGH", RED)
    fitted = _fit(colored, 8)
    assert _visible_len(fitted) == 8
    assert fitted.endswith(" " * 4)
    assert "\x1b[0m" in fitted


def test_table_columns_align_with_colored_cells(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    colors = {"critical": "\x1b[38;5;197m", "high": "\x1b[38;5;208m"}
    rows = [
        [_color("CRITICAL".ljust(8), colors["critical"]), "A very long finding title that needs clipping"],
        [_color("HIGH".ljust(8), colors["high"]), "Short title"],
    ]
    rendered = _table(["severity", "title"], rows, widths=[8, 18])
    plain = [_visible_len(line) for line in rendered.splitlines()]
    assert plain == [8 + 2 + 18, 8 + 2 + 18, 8 + 2 + 18, 8 + 2 + 18]
    assert "needs clipp" not in rendered
    assert "A very long findin" in rendered
