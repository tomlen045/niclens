#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_repos_niclens.py — 双仓匿名读回 + jsDelivr SHA 锚定图床逐张验证。"""
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def head(url):
    req = urllib.request.Request(url, method="HEAD")
    try:
        r = urllib.request.urlopen(req, timeout=25)
        return r.status, r.headers.get("Content-Type", "?")
    except urllib.error.HTTPError as e:
        return e.code, "?"
    except Exception as e:
        return 0, e.__class__.__name__


def get_code(url):
    req = urllib.request.Request(url)
    try:
        r = urllib.request.urlopen(req, timeout=25)
        return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return 0


def main():
    ok = True
    print("=== Gitee anonymous ===")
    for label, url in [
        ("page", "https://gitee.com/tomlen/niclens"),
        ("raw", "https://gitee.com/tomlen/niclens/raw/main/README.md"),
    ]:
        c = get_code(url)
        print("%s: %d" % (label, c))
        ok = ok and c == 200

    print("=== GitHub anonymous ===")
    for label, url in [
        ("api", "https://api.github.com/repos/tomlen045/niclens"),
        ("raw", "https://raw.githubusercontent.com/tomlen045/niclens/main/README.md"),
    ]:
        c = get_code(url)
        print("%s: %d" % (label, c))
        ok = ok and c == 200

    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE,
                         capture_output=True, text=True).stdout.strip()
    print("HEAD sha:", sha)
    print("=== jsDelivr CDN (SHA-anchored, HEAD+Content-Type, 2 retries per file) ===")
    all_ok = True
    for f in ["01_demo_full", "02_live_checkup", "03_verdict_table",
              "04_baseline_flow", "05_selftest_41", "06_json_cron"]:
        url = "https://gcore.jsdelivr.net/gh/tomlen045/niclens@%s/shots/%s.png" % (sha, f)
        seen = []
        for attempt in range(3):
            c, ct = head(url)
            seen.append((c, ct))
            if c == 200 and "image/png" in ct:
                break
            import time
            time.sleep(5)
        c, ct = seen[-1]
        print("%s: %d %s %s" % (f, c, ct, "" if (c == 200 and "image/png" in ct) else seen))
        if not (c == 200 and "image/png" in ct):
            all_ok = False
    print("VERDICT:", "ALL GREEN" if all_ok else "HAS FAILURES")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
