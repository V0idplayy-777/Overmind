#!/usr/bin/env python3
"""Parse an HTML file into a JSON DOM tree for tests/harness.js.

Usage: python3 tests/build-dom.py overauth.html > /tmp/dom.json
Keeps tag names, attributes and text; skips the *contents* of <script> and
<style> (they are not DOM nodes the tests care about).
"""
import json
import sys
from html.parser import HTMLParser

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}


class DomBuilder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "#document", "attrs": {}, "children": [], "text": ""}
        self.stack = [self.root]
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip_depth += 1
            return
        node = {"tag": tag, "attrs": {k: (v or "") for k, v in attrs}, "children": [], "text": ""}
        self.stack[-1]["children"].append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        if tag in ("script", "style"):
            return
        node = {"tag": tag, "attrs": {k: (v or "") for k, v in attrs}, "children": [], "text": ""}
        self.stack[-1]["children"].append(node)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip_depth = max(0, self.skip_depth - 1)
            return
        if tag in VOID:
            return
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i]["tag"] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        if self.skip_depth:
            return
        if data.strip():
            self.stack[-1]["text"] += data


def main():
    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    builder = DomBuilder()
    builder.feed(src)
    builder.close()
    json.dump(builder.root, sys.stdout)


if __name__ == "__main__":
    main()
