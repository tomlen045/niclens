#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_cover_niclens.py — 产线①自研工具封面 900x383。
自研/故事类家规：不晒星数（0星阶段），用「对话钩子」形态 + 硬指标（15判决/41自测）。"""
import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
W, H = 900, 383
GOLD = (240, 180, 41)
WHITE = (240, 240, 245)
GREY = (150, 158, 170)
DARKBG1 = (11, 14, 26)
DARKBG2 = (26, 15, 46)
HEITI = "/System/Library/Fonts/STHeiti Medium.ttc"
MENLO = "/System/Library/Fonts/Menlo.ttc"


def f(path, size):
    return ImageFont.truetype(path, size)


def main():
    img = Image.new("RGB", (W, H))
    d = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        r = int(DARKBG1[0] + (DARKBG2[0] - DARKBG1[0]) * t)
        g = int(DARKBG1[1] + (DARKBG2[1] - DARKBG1[1]) * t)
        b = int(DARKBG1[2] + (DARKBG2[2] - DARKBG1[2]) * t)
        d.line([(0, y), (W, y)], fill=(r, g, b))
    d.rectangle([0, 0, 10, H], fill=GOLD)
    d.text((36, 30), "自研工具 · 网络体检", font=f(HEITI, 20), fill=GOLD)
    # 对话钩子形态（白句+金句反驳）
    d.text((36, 76), "“网线插着呢，怎么会连不上？”", font=f(HEITI, 38), fill=WHITE)
    d.text((36, 142), "先看配置面有没有病，再怪网线。", font=f(HEITI, 34), fill=GOLD)
    d.text((36, 218), "niclens — 不发包、不改配置，一次只读体检", font=f(HEITI, 24), fill=GREY)
    # 右侧硬指标区——混合串用黑体（Menlo 无 CJK 会出豆腐块）
    d.text((640, 76), "15条", font=f(HEITI, 44), fill=GOLD)
    d.text((648, 132), "配置判决", font=f(HEITI, 20), fill=GREY)
    d.text((640, 176), "41项", font=f(HEITI, 44), fill=GOLD)
    d.text((648, 232), "自测全绿", font=f(HEITI, 20), fill=GREY)
    # 底部黑衬底信息行
    d.rectangle([0, 316, W, H], fill=(0, 0, 0))
    d.text((36, 330), "网卡/路由 · DNS · hosts 三层一次查完", font=f(HEITI, 22), fill=WHITE)
    d.text((36, 356), "零依赖单文件 · 退出码直连 cron", font=f(HEITI, 18), fill=GREY)
    out = os.path.join(HERE, "niclens_cover.png")
    img.save(out)
    print(out, img.size)


if __name__ == "__main__":
    main()
