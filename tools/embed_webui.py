# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 heydemoura
"""Embed the standalone web UI in the PS5 ELF."""

import json
import pathlib


root = pathlib.Path(__file__).resolve().parents[1]
source = root / "assets" / "webui.html"
target = root / "src" / "webui.inc"
with target.open("w", encoding="utf-8") as output:
    output.write("/* Generated from assets/webui.html. Do not edit. */\n")
    output.write("static const char webui_html[] =\n")
    for line in source.read_text(encoding="utf-8").splitlines(keepends=True):
        output.write(json.dumps(line, ensure_ascii=True) + "\n")
    output.write(";\n")
