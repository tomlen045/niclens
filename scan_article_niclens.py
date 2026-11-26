#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_article_niclens.py — 微信排版自检四件套（标签配对/;;/87%宽/显式对齐/敏感串/CDN URL）。"""
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "niclens-article.html")
html = open(PATH, encoding="utf-8").read()
issues = []


def note(ok, label, detail=""):
    print("[ok] " if ok else "[XX] " + label + (" " + detail if detail else ""))
    if not ok:
        issues.append(label)


# 1 标签配对
stack = []
selfclose = {"meta", "br", "img", "hr", "input", "link"}
bad_tag = None
for m in re.finditer(r"<(/?)([a-zA-Z0-9]+)([^>]*?)(/?)>", html):
    close, tag, attrs, selfc = m.group(1), m.group(2).lower(), m.group(3), m.group(4)
    if tag in selfclose or selfc:
        continue
    if not close:
        stack.append(tag)
    else:
        if not stack or stack[-1] != tag:
            bad_tag = (tag, list(stack[-3:]))
            break
        stack.pop()
note(not bad_tag and not stack, "tag pairing",
     "" if (not bad_tag and not stack) else "bad=%s stack_tail=%s" % (bad_tag, stack))

# 2 双分号
n = html.count(";;")
note(n == 0, "double semicolon", "hits=%d" % n)

# 3 87% 宽度
n87 = len(re.findall(r"width:87%", html))
note(n87 >= 8, "width:87% count", "count=%d" % n87)

# 4 显式对齐
p_total = len(re.findall(r"<p[ >]", html))
p_ok = len(re.findall(r"<p[^>]*text-align", html))
note(p_total == p_ok, "explicit text-align on <p>", "%d/%d" % (p_ok, p_total))
s_total = len(re.findall(r"<section[ >]", html))
s_ok = len(re.findall(r"<section[^>]*text-align", html))
note(s_total == s_ok, "explicit text-align on <section>", "%d/%d" % (s_ok, s_total))

# 5 敏感串（含空格变体）
for pat, label in [
    (r"172\.16", "intranet 172.16"), (r"172\.18", "intranet 172.18"),
    (r"10\.92", "doorplate 10.92"), (r"ghp_[A-Za-z0-9]", "github token"),
    (r"\b[0-9a-f]{32}\b", "32-hex"),
]:
    hits = re.findall(pat, html)
    note(not hits, "sensitive " + label, "hits=%d" % len(hits))

# 6 外链
note("href=" not in html.lower(), "no href in body")

# 7 CDN URL 全部 SHA 锚定且可达
urls = re.findall(r'https://gcore\.jsdelivr\.net/gh/tomlen045/niclens@([0-9a-f]+)/shots/[0-9a-z_]+\.png', html)
note(len(urls) == 6, "six CDN images embedded", "found=%d" % len(urls))
note(all(len(u) == 40 for u in urls), "all SHAs are 40-hex", str(sorted(set(len(u) for u in urls))))


for u in set(re.findall(r'https://gcore\.jsdelivr\.net/[^"]+\.png', html)):
    err = ""
    try:
        req = urllib.request.Request(u, method="HEAD")
        r = urllib.request.urlopen(req, timeout=25)
        oku = r.status == 200 and "image/png" in r.headers.get("Content-Type", "")
        err = str(r.status)
    except Exception as e2:
        oku = False
        err = "%s:%s" % (type(e2).__name__, getattr(e2, "code", ""))
    note(oku, "cdn " + u.split("/shots/")[-1], "-> " + err)

print("=" * 50)
print("TOTAL ISSUES: %d" % len(issues))
sys.exit(1 if issues else 0)
