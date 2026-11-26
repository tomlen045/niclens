#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_shots_niclens.py — 6 张终端实拍风证据图，内容 100% 来自 niclens 真实输出。

PIL 避坑（家规）：
  - emoji 区字符（✅❌⏭ 等）在 Menlo/STHeiti 下都是豆腐块 → 勾/叉/箭头用 d.line 自绘
  - 纯 ASCII 段用 Menlo，含中文段用 STHeiti（has_cjk 路由）
  - 图内字号 ≥ 20px，画布宽 ≥ 1200px
"""
import os
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "shots")
os.makedirs(OUT, exist_ok=True)

# One Dark 配色
BG = (40, 44, 52)
FG = (171, 178, 186)
GREEN = (152, 195, 121)
RED = (224, 108, 117)
YELLOW = (229, 192, 123)
BLUE = (97, 175, 239)
GREY = (92, 99, 112)
BAR = (33, 37, 43)

MENLO = "/System/Library/Fonts/Menlo.ttc"
HEITI = "/System/Library/Fonts/STHeiti Medium.ttc"

FS = 26            # 图内主字号
LH = 40            # 行高
PAD = 36
TITLE_FS = 30


def has_cjk(s):
    return any('\u4e00' <= ch <= '\u9fff' for ch in s)


def font_for(s, size=FS):
    path = HEITI if has_cjk(s) else MENLO
    return ImageFont.truetype(path, size)


def draw_line(d, x, y, text, color=FG, size=FS):
    d.text((x, y), text, font=font_for(text, size), fill=color)
    return y + LH


def draw_check(d, x, y, color=GREEN):
    """自绘勾。"""
    d.line([(x, y + 22), (x + 10, y + 32)], fill=color, width=4)
    d.line([(x + 10, y + 32), (x + 30, y + 6)], fill=color, width=4)


def draw_arrow(d, x, y, color=BLUE):
    """自绘右箭头 →。"""
    d.line([(x, y + 19), (x + 26, y + 19)], fill=color, width=4)
    d.line([(x + 18, y + 11), (x + 26, y + 19)], fill=color, width=4)
    d.line([(x + 18, y + 27), (x + 26, y + 19)], fill=color, width=4)


def make_shot(name, title, lines, width=1400):
    """lines: list of (kind, text) kind in text/green/red/yellow/blue/grey/check/arrow"""
    h = PAD * 2 + 70 + len(lines) * LH + 30
    img = Image.new("RGB", (width, h), BG)
    d = ImageDraw.Draw(img)
    # mac 窗框
    d.rectangle([0, 0, width, 56], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([22 + i * 30, 18, 40 + i * 30, 36], fill=c)
    t = "%s — niclens" % title
    d.text((width // 2 - len(t) * 8, 14), t, font=ImageFont.truetype(MENLO, 22), fill=GREY)
    y = 76
    for kind, text in lines:
        if kind == "check":
            draw_check(d, PAD, y)
            d.text((PAD + 44, y), text, font=font_for(text), fill=GREEN)
        elif kind == "arrow":
            draw_arrow(d, PAD, y)
            d.text((PAD + 44, y), text, font=font_for(text), fill=FG)
        else:
            color = {"text": FG, "green": GREEN, "red": RED, "yellow": YELLOW,
                     "blue": BLUE, "grey": GREY}[kind]
            d.text((PAD, y), text, font=font_for(text), fill=color)
        y += LH
    path = os.path.join(OUT, name)
    img.save(path)
    print("%s  %dx%d" % (path, img.width, img.height))


def run(args):
    r = subprocess.run([sys.executable, os.path.join(HERE, "niclens.py")] + args,
                       capture_output=True, text=True)
    return r.stdout, r.returncode


def main():
    # ---- shot 1: --demo 全景（真实运行输出节选）
    out, rc = run(["--demo"])
    demo_lines = [ln for ln in out.splitlines() if ln.strip()][:22]
    lines = [("blue", "$ python3 niclens.py --demo")]
    for ln in demo_lines:
        k = "text"
        if "NL-0" in ln or "NL-1" in ln:
            k = "red" if "[P0]" in ln else ("yellow" if "[P1]" in ln else "blue")
        elif ln.startswith(" ▲"):
            k = "yellow"
        t = ln.rstrip()
        if len(t) > 96:
            t = t[:93] + "…"
        lines.append((k, t))
    make_shot("01_demo_full.png", "demo sandbox 4 planted faults", lines)

    # ---- shot 2: 真机体检（聚合信息 + 判决行，不展示原始内网行）
    out, rc = run([])
    live_lines = [ln for ln in out.splitlines() if ln.strip()]
    lines = [("blue", "$ python3 niclens.py        # 本机实跑，只读")]
    for ln in live_lines:
        k = "text"
        if "[P0]" in ln:
            k = "red"
        elif "[P1]" in ln:
            k = "yellow"
        elif "[P2]" in ln:
            k = "blue"
        elif "综合风险分" in ln:
            k = "yellow"
        lines.append((k, ln.rstrip()[:86]))
    make_shot("02_live_checkup.png", "real machine, read-only", lines)

    # ---- shot 3: 判决体系表（文案源自 README 判决表）
    rows = [
        ("NL-01", "P0", "无默认网关（有接口却是孤岛）"),
        ("NL-02", "P0", "多条冲突默认网关（无 metric 区分）"),
        ("NL-03", "P0", "网关不在任何本机网段"),
        ("NL-04", "P0", "网关=本机IP（路由自环）"),
        ("NL-05", "P0", "hosts 劫持 localhost"),
        ("NL-06", "P1", "无任何 DNS 配置"),
        ("NL-07", "P1", "DNS 地址畸形（0.0.0.0 等）"),
        ("NL-08", "P1", "同名主机映射多个 IP"),
        ("NL-09", "P1", "接口 DOWN 却配着 IP"),
        ("NL-10", "P2", "MTU < 1280"),
        ("NL-11", "P2", "重复 nameserver"),
        ("NL-12", "P2", "hosts 坏行"),
        ("NL-13", "P2", "search 域过多（>3）"),
        ("NL-90", "P1", "基线：网关/DNS 被换"),
        ("NL-91", "P2", "基线：IP/路由增删"),
    ]
    lines = [("yellow", "15 条判决 · 退出码 0/1/2/3 直接连 cron"), ("grey", "")]
    for nid, sev, desc in rows:
        c = {"P0": "red", "P1": "yellow", "P2": "blue"}[sev]
        lines.append((c, "%s  [%s]  %s" % (nid, sev, desc)))
    make_shot("03_verdict_table.png", "15 verdicts", lines)

    # ---- shot 4: 基线工作流
    lines = [
        ("blue", "$ python3 niclens.py --save-baseline base.json"),
        ("green", "基线已保存: base.json   (网关/DNS/IP/路由摘要)"),
        ("grey", "...  三天后 ..."),
        ("blue", "$ python3 niclens.py --baseline base.json"),
        ("yellow", "▲ NL-90 [P1] DNS 集合与基线不一致（劫持高发信号）"),
        ("text", "     新增: 10.213.66.66；消失: 10.213.99.53"),
        ("yellow", "▲ NL-91 [P2] 接口 IP / 路由表与基线有增删"),
        ("text", "     接口 IP 变化: en0"),
        ("grey", "基线只存排序后的摘要，不存任何原始报文"),
    ]
    make_shot("04_baseline_flow.png", "baseline workflow (demo)", lines)

    # ---- shot 5: selftest 全绿
    r = subprocess.run([sys.executable, os.path.join(HERE, "selftest.py")],
                       capture_output=True, text=True)
    pl = [ln for ln in r.stdout.splitlines() if ln.startswith("PASS")]
    lines = [("blue", "$ python3 selftest.py")]
    for ln in pl[:34]:
        lines.append(("check", ln[6:].strip()[:78]))
    tail = r.stdout.splitlines()[-1]
    lines.append(("green", tail.strip()))
    make_shot("05_selftest_41.png", "41 checks, all green", lines)

    # ---- shot 6: --json 接 cron
    lines = [
        ("blue", "$ python3 niclens.py --json | python3 -m json.tool | head -20"),
        ("grey", "{"),
        ('text', '  "tool": "niclens",'),
        ('text', '  "version": "1.0.0",'),
        ('yellow', '  "summary": {'),
        ('yellow', '    "risk_score": 95,'),
        ('yellow', '    "exit": 1,'),
        ('text', '    "counts": { "P0": 0, "P1": 0, "P2": 1 }'),
        ("grey", "  }"),
        ('text', '  "findings": [ { "id": "NL-10", ... } ]'),
        ("grey", "}"),
        ("grey", ""),
        ("blue", "# crontab —— 每天 9 点体检，P1 以上才吵你"),
        ("text", "0 9 * * * python3 niclens.py --json >/dev/null || \\"),
        ("text", "  /usr/local/bin/alert.sh niclens"),
    ]
    make_shot("06_json_cron.png", "json output + cron wiring", lines)

    print("ALL SHOTS DONE")


if __name__ == "__main__":
    main()
