#!/usr/bin/env python3
"""Inline inv1.js and thunder.js into template.html -> dist/index.html (one self-contained page)."""
from pathlib import Path
d = Path(__file__).parent
t = (d / "template.html").read_text()
for tag, f in (("/*__INV1__*/", "inv1.js"), ("/*__THUNDER__*/", "thunder.js")):
    js = (d / f).read_text()
    assert "</script" not in js.lower()
    assert t.count(tag) == 1
    t = t.replace(tag, js)
(d / "dist").mkdir(exist_ok=True)
(d / "dist" / "index.html").write_text(t)
print("dist/index.html", len(t), "bytes")
