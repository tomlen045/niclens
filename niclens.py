#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
niclens — 网络配置体检镜（自研哨兵/透镜套件第 8 件）
=====================================================
不发包、不改配置，一次只读体检回答一个问题：
「这台机器的网络配置面本身有没有病？」

管三层：
  1. 网卡与路由：IP/掩码/网关/MTU/接口状态
  2. DNS：resolv.conf（Linux）或 scutil --dns（macOS）
  3. hosts 文件：劫持 / 冲突映射 / 坏行

与套件的分工：
  porteye「谁在听」→ authguard「谁想进来」→ callhome「谁打电话回家」
  → freshlens「什么文件被动了」→ histlens「这台机器跑过什么」
  → niclens「网络配置面有没有病」
  dnsdiff 对账的是【运行态】解析结果（本机 vs 公共池 vs 多数派）；
  niclens 体检的是【配置态】本身——两个工具背靠背，DNS 这块就闭环了。

设计铁律（不变量）：
  1. 只读：不改任何配置、不动网络状态；除 --probe 外零流量
  2. 零依赖：纯标准库，Python 3.8+，单文件
  3. 无需 root：只用免 root 只读命令
  4. 判决可退出码分级：0=干净 1=仅P2 2=含P1 3=含P0（可直接接 cron）
  5. 解析容错：命令输出解析不到就降级 NOTE，不猜不崩

判决体系（NL-01 ~ NL-13 配置判决 + NL-90/91 基线判决）：
  NL-01 P0 无默认网关（有非环回 IPv4 接口却是孤岛）
  NL-02 P0 多条冲突默认网关（不同下一跳且无 metric 区分）
  NL-03 P0 网关不在任何本机 IPv4 网段内
  NL-04 P0 网关 IP 与本机某网卡 IP 相同（路由自环）
  NL-05 P0 hosts 把 localhost 映射到非环回 IP（劫持）
  NL-06 P1 无任何 DNS 配置
  NL-07 P1 DNS 地址畸形（0.0.0.0 / 组播 / 广播段）
  NL-08 P1 hosts 同一主机名映射多个不同 IP（首条生效其余是哑弹）
  NL-09 P1 接口配了 IPv4 但状态 DOWN
  NL-10 P2 MTU 异常（< 1280）
  NL-11 P2 resolv.conf 重复 nameserver
  NL-12 P2 hosts 坏行（列数异常 / IP 非法）
  NL-13 P2 search 域过多（> 3，拖慢解析）
  NL-90 P1 基线对比：默认网关或 DNS 集合变化（DNS 被换 = 劫持高发信号）
  NL-91 P2 基线对比：接口 IP / 路由表增删

用法：
  niclens.py                       # 默认全体检（macOS / Linux / Windows 尽力兼容）
  niclens.py --json                # 机器可读输出（接 cron / webhook）
  niclens.py --probe               # 额外向每个 nameserver 发一次 UDP53 探活（3s 超时）
  niclens.py --demo                # 内置沙箱：合成配置喂同一套解析器，预埋 4 类真实感故障
  niclens.py --save-baseline F     # 保存当前状态为基线
  niclens.py --baseline F          # 对比基线，报 NL-90/91
  niclens.py --hosts P --resolv P  # 体检任意 hosts / resolv 文件（测试用）
"""
import argparse
import ipaddress
import json
import platform
import re
import socket
import struct
import subprocess
import sys
import time

VERSION = "1.0.0"
TOOL = "niclens"
EXIT_MAP = {0: 0, 1: 1, 2: 2, 3: 3}
RISK_WEIGHT = {"P0": 40, "P1": 20, "P2": 5}

# ---------------------------------------------------------------- 常量（示例一律 10.213.x.x 合成池）

LOOPBACK_V4_NET = ipaddress.ip_network("127.0.0.0/8")
MULTICAST_V4_NET = ipaddress.ip_network("224.0.0.0/4")
BROADCAST_V4 = ipaddress.ip_address("255.255.255.255")
ZERO_V4 = ipaddress.ip_address("0.0.0.0")
STUB_DNS = "127.0.0.53"          # systemd-resolved stub，不算畸形
LOOPBACK_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

# ---------------------------------------------------------------- 系统执行（只读白名单命令）

READONLY_CMDS = (
    ["ifconfig", "-a"], ["netstat", "-rn"], ["scutil", "--dns"],
    ["networksetup", "-listallhardwareports"],
    ["ip", "addr", "show"], ["ip", "route", "show"],
    ["route", "print"],
)


def run(args, timeout=20):
    """Run a readonly command, return (rc, stdout). Never raises on nonzero rc."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


# ---------------------------------------------------------------- 解析器（正则在真实 macOS 输出上校准过）

HEAD_RE = re.compile(r"^(\S+?):\s*flags=((?:0x)?[0-9a-fA-F]+)<([^>]*)>(?:\s+mtu\s+(\d+))?")
ETHER_RE = re.compile(r"^\s+ether\s+([0-9a-fA-F:]{12,})")
MEDIA_RE = re.compile(r"^\s+media:\s*(.+?)\s*$")
STATUS_RE = re.compile(r"^\s+status:\s*(\S+)")
INET4_RE = re.compile(
    r"^\s+inet\s+(\d+\.\d+\.\d+\.\d+)(?:\s+netmask\s+(0x[0-9a-fA-F]+))?"
    r"(?:\s+broadcast\s+(\S+))?")
INET6_RE = re.compile(r"^\s+inet6\s+(\S+)\s+prefixlen\s+(\d+)\s*(.*)$")

LINUX_IFACE_RE = re.compile(r"^\d+:\s+(\S+):\s+<([^>]*)>.*?mtu\s+(\d+).*?state\s+(\S+)")
LINUX_INET4_RE = re.compile(r"^\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)")
LINUX_INET6_RE = re.compile(r"^\s+inet6\s+(\S+)")
IFACE_LIKE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.@-]*$")


def netmask_to_prefix(mask_hex):
    """'0xfffffc00' -> 22. None for missing/invalid."""
    if not mask_hex:
        return None
    try:
        v = int(mask_hex, 16)
    except ValueError:
        return None
    return bin(v).count("1")


def netmask_to_dotted(mask_hex):
    """'0xfffffc00' -> '255.255.252.0'."""
    if not mask_hex:
        return None
    try:
        v = int(mask_hex, 16)
    except ValueError:
        return None
    return "%d.%d.%d.%d" % ((v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255)


def parse_ifconfig(text):
    """Parse `ifconfig -a` into {name: iface_dict}."""
    ifaces = {}
    cur = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        m = HEAD_RE.match(raw)
        if m:
            name, hexflags, flagstr, mtu = m.groups()
            cur = {
                "name": name,
                "flags": flagstr.split(",") if flagstr else [],
                "mtu": int(mtu) if mtu else None,
                "status": None,
                "inet4": [],
                "inet6": [],
            }
            ifaces[name] = cur
            continue
        if cur is None:
            continue
        m = INET4_RE.match(raw)
        if m:
            addr, mask, bcast = m.groups()
            cur["inet4"].append({
                "address": addr,
                "netmask": netmask_to_dotted(mask),
                "prefixlen": netmask_to_prefix(mask) if mask else None,
            })
            continue
        m = INET6_RE.match(raw)
        if m:
            cur["inet6"].append({"address": m.group(1), "prefixlen": int(m.group(2))})
            continue
        m = STATUS_RE.match(raw)
        if m:
            cur["status"] = m.group(1)
            continue
        m = ETHER_RE.match(raw)
        if m:
            cur.setdefault("ether", m.group(1).lower())
            continue
        m = MEDIA_RE.match(raw)
        if m:
            cur.setdefault("media", m.group(1).strip())
            continue
        # options=/nd6 options=/groups: 等未知行忽略
    return ifaces


def parse_routes_mac(text):
    """Parse `netstat -rn` into a list of route dicts."""
    routes = []
    family = None
    expire_like = lambda t: (t == "*" or t.isdigit())
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s:
            continue
        if s.startswith("Routing tables"):
            family = None
            continue
        if s == "Internet:":
            family = "inet"
            continue
        if s == "Internet6:":
            family = "inet6"
            continue
        if s.endswith(":") and not line.startswith((" ", "\t")):
            family = None
            continue
        toks = s.split()
        if len(toks) < 4:
            continue
        if toks[0] in ("Destination",) or toks[0].endswith("Internet"):
            continue
        dest, gw, flags = toks[0], toks[1], toks[2]
        netif = None
        expire = None
        last = toks[-1]
        if len(toks) >= 6 and expire_like(last):
            expire = last
            netif = toks[-2]
        else:
            netif = last
        if not IFACE_LIKE.match(netif or "") or netif == dest or netif == gw:
            netif = toks[-2] if len(toks) >= 5 else None
        routes.append({
            "family": family or "inet",
            "destination": dest,
            "gateway": gw,
            "flags": flags,
            "netif": netif,
            "expire": expire,
            "metric": None,
        })
    return routes


def parse_dns_scutil(text):
    """Extract unique nameserver IPs from `scutil --dns`, in order."""
    seen, out = set(), []
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*([0-9a-fA-F:.]+)", text or ""):
        ip = m.group(1)
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def parse_hwports(text):
    """Parse `networksetup -listallhardwareports` -> {device: port name}."""
    ports = {}
    port = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith("VLAN Configurations"):
            break
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            dev = line.split(":", 1)[1].strip()
            if port and dev:
                ports[dev] = port
            port = None
    return ports


def parse_linux_ip_addr(text):
    """Parse `ip addr show` into {name: iface_dict} (same shape as parse_ifconfig)."""
    ifaces = {}
    cur = None
    for raw in text.splitlines():
        m = LINUX_IFACE_RE.match(raw)
        if m:
            name, flagstr, mtu, state = m.groups()
            cur = {
                "name": name,
                "flags": [f for f in flagstr.split(",") if f],
                "mtu": int(mtu) if mtu else None,
                "status": state.lower(),
                "inet4": [],
                "inet6": [],
            }
            ifaces[name] = cur
            continue
        if cur is None:
            continue
        m = LINUX_INET4_RE.match(raw)
        if m:
            cur["inet4"].append({"address": m.group(1), "netmask": None,
                                 "prefixlen": int(m.group(2))})
            continue
        m = LINUX_INET6_RE.match(raw)
        if m:
            cur["inet6"].append({"address": m.group(1), "prefixlen": None})
    return ifaces


def parse_linux_ip_route(text):
    """Parse `ip route show` into route dicts (same shape as parse_routes_mac)."""
    routes = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        toks = s.split()
        dest = toks[0]
        gw = None
        netif = None
        metric = None
        i = 1
        while i < len(toks):
            if toks[i] == "via" and i + 1 < len(toks):
                gw = toks[i + 1]
                i += 2
                continue
            if toks[i] == "dev" and i + 1 < len(toks):
                netif = toks[i + 1]
                i += 2
                continue
            if toks[i] == "metric" and i + 1 < len(toks):
                try:
                    metric = int(toks[i + 1])
                except ValueError:
                    metric = None
                i += 2
                continue
            i += 1
        routes.append({
            "family": "inet6" if ":" in dest else "inet",
            "destination": dest,
            "gateway": gw or "--",
            "flags": "",
            "netif": netif,
            "expire": None,
            "metric": metric,
        })
    return routes


def parse_resolv_conf(text):
    """Parse resolv.conf -> (nameservers [原始顺序, 可含重复], search 域列表)."""
    ns, search = [], []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        toks = line.split()
        if toks[0] == "nameserver" and len(toks) >= 2:
            ns.append(toks[1])
        elif toks[0] == "search":
            search.extend(toks[1:])
        elif toks[0] == "domain" and len(toks) >= 2:
            search.append(toks[1])
    return ns, search


def parse_hosts(text):
    """Parse hosts file -> (entries, badlines, hostmap {name: [ip,...] 按出现序}).

    entries: [{ip, names, lineno}]；badlines: [{lineno, reason, raw}]。
    注释/空行跳过；首列 IP 非法、或只有一列，均为坏行。
    """
    entries, badlines, hostmap = [], [], {}
    for idx, raw in enumerate((text or "").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        toks = line.split()
        if len(toks) < 2:
            badlines.append({"lineno": idx, "reason": "columns<2", "raw": raw.strip()})
            continue
        try:
            ipaddress.ip_address(toks[0])
        except ValueError:
            badlines.append({"lineno": idx, "reason": "invalid-ip", "raw": raw.strip()})
            continue
        names = [t.lower() for t in toks[1:]]
        entries.append({"ip": toks[0], "names": names, "lineno": idx})
        for n in names:
            hostmap.setdefault(n, [])
            if toks[0] not in hostmap[n]:
                hostmap[n].append(toks[0])
    return entries, badlines, hostmap


# ---------------------------------------------------------------- 状态归一化

def normalize_ifaces(ifaces_raw):
    """-> {name: {up, loopback, status, mtu, v4:[(addr,plen)], v6:[addr]}}"""
    out = {}
    for name, it in ifaces_raw.items():
        up = "UP" in it.get("flags", [])
        loopback = (name in ("lo0", "lo")) or ("LOOPBACK" in it.get("flags", []))
        v4 = []
        for a in it.get("inet4", []):
            plen = a.get("prefixlen")
            if plen is None:
                try:
                    plen = ipaddress.ip_network(
                        "%s/%s" % (a["address"], a.get("netmask") or "255.255.255.255"),
                        strict=False).prefixlen
                except ValueError:
                    plen = 32
            v4.append((a["address"], int(plen)))
        v6 = [a["address"] for a in it.get("inet6", [])]
        out[name] = {
            "up": bool(up),
            "loopback": loopback,
            "status": it.get("status"),
            "mtu": it.get("mtu"),
            "v4": v4,
            "v6": v6,
        }
    return out


def default_gateways_v4(routes):
    """[{gw, iface, metric}] from route list (mac or linux shape)."""
    out = []
    for r in routes:
        if r.get("family") != "inet":
            continue
        dest = (r.get("destination") or "").lower()
        if dest not in ("default", "0.0.0.0", "0.0.0.0/0"):
            continue
        gw = r.get("gateway")
        if not gw or gw == "--":
            continue
        out.append({"gw": gw, "iface": r.get("netif"), "metric": r.get("metric")})
    return out


# ---------------------------------------------------------------- 状态采集（活机器 / fixture / 文件）

def _read_file(path, notes):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        notes.append("无法读取 %s: %s" % (path, e.__class__.__name__))
        return ""


def gather_state(hosts_path=None, resolv_path=None):
    """Collect normalized state. Windows: 尽力解析，失败降级 NOTE 不崩。"""
    sysname = platform.system().lower()
    notes = []
    ifaces_norm, routes, dns, search = {}, [], [], []

    if sysname == "darwin":
        rc, ifc = run(["ifconfig", "-a"])
        ifaces_raw = parse_ifconfig(ifc) if rc == 0 else {}
        if rc != 0:
            notes.append("ifconfig 不可用，网卡层跳过")
        rc, rt = run(["netstat", "-rn"])
        routes = parse_routes_mac(rt) if rc == 0 else []
        if rc != 0:
            notes.append("netstat 不可用，路由层跳过")
        if resolv_path:
            dns, search = parse_resolv_conf(_read_file(resolv_path, notes))
        else:
            rc, sd = run(["scutil", "--dns"])
            dns = parse_dns_scutil(sd) if rc == 0 else []
            if rc != 0:
                notes.append("scutil 不可用，DNS 层跳过")
        ifaces_norm = normalize_ifaces(ifaces_raw)

    elif sysname == "linux":
        rc, ia = run(["ip", "addr", "show"])
        ifaces_raw = parse_linux_ip_addr(ia) if rc == 0 else {}
        if rc != 0:
            notes.append("ip 不可用，网卡层跳过")
        rc, rt = run(["ip", "route", "show"])
        routes = parse_linux_ip_route(rt) if rc == 0 else []
        if rc != 0:
            notes.append("ip route 不可用，路由层跳过")
        if resolv_path:
            dns, search = parse_resolv_conf(_read_file(resolv_path, notes))
        else:
            dns, search = parse_resolv_conf(_read_file("/etc/resolv.conf", notes))
        ifaces_norm = normalize_ifaces(ifaces_raw)

    else:
        notes.append("系统 %s：完整体检降级，仅查 hosts" % (sysname or "unknown"))

    if hosts_path:
        hosts_text = _read_file(hosts_path, notes)
    else:
        hosts_text = _read_file("/etc/hosts", notes)
    host_entries, badlines, hostmap = parse_hosts(hosts_text)

    return {
        "os": sysname or "unknown",
        "notes": notes,
        "ifaces": ifaces_norm,
        "routes": routes,
        "gateways": default_gateways_v4(routes),
        "dns": dns,
        "search": search,
        "hosts_entries": host_entries,
        "hosts_badlines": badlines,
        "hostmap": hostmap,
    }


def state_from_fixtures(ifconfig_text="", routes_text="", resolv_text="",
                        hosts_text="", os_name="macos"):
    """Sandbox: feed synthetic texts through the very same parsers."""
    notes = []
    if os_name == "macos":
        ifaces_raw = parse_ifconfig(ifconfig_text)
        routes = parse_routes_mac(routes_text)
    else:
        ifaces_raw = parse_linux_ip_addr(ifconfig_text)
        routes = parse_linux_ip_route(routes_text)
    dns, search = parse_resolv_conf(resolv_text)
    host_entries, badlines, hostmap = parse_hosts(hosts_text)
    return {
        "os": os_name,
        "notes": notes,
        "ifaces": normalize_ifaces(ifaces_raw),
        "routes": routes,
        "gateways": default_gateways_v4(routes),
        "dns": dns,
        "search": search,
        "hosts_entries": host_entries,
        "hosts_badlines": badlines,
        "hostmap": hostmap,
    }


# ---------------------------------------------------------------- 判决引擎

def _is_v4(s):
    try:
        return ipaddress.ip_address(s).version == 4
    except ValueError:
        return False


def _all_loopback(ips):
    """True if every ip is loopback (v4 127/8 or v6 ::1) — 标准双栈 localhost 不算多重映射。"""
    try:
        for ip in ips:
            a = ipaddress.ip_address(ip)
            if not (a.is_loopback or a in LOOPBACK_V4_NET):
                return False
        return bool(ips)
    except ValueError:
        return False


def _in_any_subnet(gw, ifaces):
    try:
        g = ipaddress.ip_address(gw)
    except ValueError:
        return None  # 解析不了 → 调用方降级 NOTE
    if g.version != 4:
        return None
    for it in ifaces.values():
        for addr, plen in it["v4"]:
            try:
                net = ipaddress.ip_network("%s/%d" % (addr, plen), strict=False)
            except ValueError:
                continue
            if g in net:
                return True
    return False


def judge(state, baseline=None):
    """Run all NL verdicts. -> (findings, notes) ; finding = {id,sev,title,detail}"""
    findings = []
    notes = list(state.get("notes", []))
    ifaces = state["ifaces"]
    gws = state["gateways"]
    dns = state["dns"]
    hm = state["hostmap"]

    v4_gws = [g for g in gws if _is_v4(g["gw"])]
    for g in gws:
        if not _is_v4(g["gw"]):
            base = g["gw"].split("%")[0].lower()
            if base.startswith("fe80"):
                notes.append("IPv6 链路本地默认网关（fe80::）属正常，跳过 NL-03")

    v4_ifaces = {n: it for n, it in ifaces.items() if it["v4"] and not it["loopback"]}
    any_v4_iface = bool(v4_ifaces)

    # ---- NL-01 无默认网关
    if any_v4_iface and not gws:
        names = ", ".join(sorted(v4_ifaces))
        findings.append({"id": "NL-01", "sev": "P0",
                         "title": "无默认网关",
                         "detail": "接口 %s 配了 IPv4，但路由表没有任何默认网关——这台机器是座孤岛" % names})
    elif not any_v4_iface and not gws:
        notes.append("未发现带 IPv4 的非环回接口，NL-01 跳过（纯环回/纯 v6 机器）")

    # ---- NL-02 多条冲突默认网关
    distinct = []
    for g in v4_gws:
        if g["gw"] not in [d["gw"] for d in distinct]:
            distinct.append(g)
    if len(distinct) > 1:
        metrics_known = all(g["metric"] is not None for g in distinct)
        if metrics_known and len({g["metric"] for g in distinct}) == len(distinct):
            notes.append("存在 %d 条默认网关，但 metric 可区分（%s），按优先级生效，不算冲突"
                         % (len(distinct),
                            ", ".join("%s(m=%s)" % (g["gw"], g["metric"]) for g in distinct)))
        else:
            det = ", ".join("%s(%s)" % (g["gw"], g["iface"] or "?") for g in distinct)
            findings.append({"id": "NL-02", "sev": "P0",
                             "title": "多条冲突默认网关",
                             "detail": "下一跳不同且无 metric 区分，出网路径随路由排序漂移: %s" % det})

    # ---- NL-03 / NL-04 网关合法性
    own_addrs = {a for it in ifaces.values() for (a, _) in it["v4"]}
    for g in v4_gws:
        try:
            gv = ipaddress.ip_address(g["gw"])
        except ValueError:
            notes.append("默认网关 %s 不是合法 IP，跳过网段校验（DHCP 未完成？）" % g["gw"])
            continue
        if str(gv) in own_addrs:
            findings.append({"id": "NL-04", "sev": "P0",
                             "title": "网关 IP 与本机网卡 IP 相同（路由自环）",
                             "detail": "网关 %s 同时是本机地址，默认路由指向自己，出网必然死循环" % g["gw"]})
            continue
        if gv == ZERO_V4:
            continue  # 0.0.0.0 网关无网段意义，跳过
        r = _in_any_subnet(str(gv), ifaces)
        if r is False:
            findings.append({"id": "NL-03", "sev": "P0",
                             "title": "默认网关不在任何本机网段",
                             "detail": "网关 %s 不属于任何已配 IPv4 网段——要么掩码配错，要么网关填错，ARP 都问不应" % g["gw"]})

    # ---- NL-05 hosts 劫持 localhost
    hijack = []
    for hn in LOOPBACK_HOSTNAMES:
        for ip in hm.get(hn, []):
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.version == 4 and a not in LOOPBACK_V4_NET:
                hijack.append("%s -> %s" % (hn, ip))
            elif a.version == 6 and a != ipaddress.ip_address("::1"):
                hijack.append("%s -> %s" % (hn, ip))
    if hijack:
        findings.append({"id": "NL-05", "sev": "P0",
                         "title": "hosts 把 localhost 映射到非环回 IP",
                         "detail": "本机名被指向外部地址: %s——典型劫持/残留，本机服务可能被引流" % "; ".join(hijack)})

    # ---- NL-06 无 DNS
    if not dns:
        findings.append({"id": "NL-06", "sev": "P1",
                         "title": "无任何 DNS 配置",
                         "detail": "nameserver 列表为空，域名解析会退化为纯 hosts / 直接失败"})

    # ---- NL-07 DNS 畸形
    bad_dns, stub = [], False
    for ip in dns:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            bad_dns.append(ip)
            continue
        if a == ZERO_V4 or a == BROADCAST_V4:
            bad_dns.append(ip)
        elif a.version == 4 and a in MULTICAST_V4_NET:
            bad_dns.append(ip)
        elif str(a) == STUB_DNS:
            stub = True
    if bad_dns:
        findings.append({"id": "NL-07", "sev": "P1",
                         "title": "DNS 地址畸形",
                         "detail": "0.0.0.0/组播/广播段当 DNS 用，解析必挂: %s" % ", ".join(bad_dns)})
    if stub:
        notes.append("%s 是 systemd-resolved 的 stub，真实服务器藏在它后面（resolvectl 查看真实值）" % STUB_DNS)

    # ---- NL-08 同名多 IP（全环回双栈 127.0.0.1+::1 是标准写法，不算）
    dups = {}
    for name, ips in hm.items():
        if len(ips) > 1 and not _all_loopback(ips):
            dups[name] = ips
    if dups:
        parts = ["%s → %s（首条生效）" % (n, ", ".join(ips)) for n, ips in sorted(dups.items())]
        findings.append({"id": "NL-08", "sev": "P1",
                         "title": "hosts 同一主机名映射多个不同 IP",
                         "detail": "%d 个主机名有多重映射，其余全是哑弹: %s" % (len(dups), "; ".join(parts))})

    # ---- NL-09 配了 IPv4 但 DOWN
    for name, it in sorted(ifaces.items()):
        if it["loopback"] or not it["v4"]:
            continue
        down = (it["status"] in ("down", "inactive", "detached")) or ("DOWN" in it.get("flags", []))
        if down or not it["up"]:
            addrs = ", ".join(a for a, _ in it["v4"])
            findings.append({"id": "NL-09", "sev": "P1",
                             "title": "接口配了 IPv4 但处于 DOWN",
                             "detail": "%s (%s) 配着 %s 却没 UP——常见于换网卡后忘删的静态配置"
                                       % (name, it.get("status") or "?", addrs)})

    # ---- NL-10 MTU 异常
    for name, it in sorted(ifaces.items()):
        mtu = it.get("mtu")
        if mtu is not None and mtu < 1280:
            findings.append({"id": "NL-10", "sev": "P2",
                             "title": "MTU 异常（< 1280）",
                             "detail": "%s 的 MTU 只有 %d，低于 IPv6 最小值 1280，大包会被分片/丢弃" % (name, mtu)})

    # ---- NL-11 重复 nameserver（保持原始顺序才有意义）
    seen, dupsn = set(), []
    for ip in dns:
        if ip in seen and ip not in dupsn:
            dupsn.append(ip)
        seen.add(ip)
    if dupsn:
        findings.append({"id": "NL-11", "sev": "P2",
                         "title": "resolv.conf 重复 nameserver",
                         "detail": "同一服务器写了多遍，无意义还拖慢超时轮询: %s" % ", ".join(dupsn)})

    # ---- NL-12 hosts 坏行
    if state["hosts_badlines"]:
        bl = state["hosts_badlines"]
        findings.append({"id": "NL-12", "sev": "P2",
                         "title": "hosts 坏行",
                         "detail": "%d 行格式非法（列数不足或 IP 写错），解析器会整行忽略: 行 %s"
                                   % (len(bl), ", ".join(str(b["lineno"]) for b in bl[:8]))})

    # ---- NL-13 search 域过多
    if len(state["search"]) > 3:
        findings.append({"id": "NL-13", "sev": "P2",
                         "title": "search 域过多（> 3）",
                         "detail": "%d 个 search 域，每个失败解析都要把列表轮一遍，拖慢一切: %s"
                                   % (len(state["search"]), ", ".join(state["search"][:6]))})

    # ---- NL-90 / NL-91 基线对比
    if baseline:
        findings.extend(judge_baseline(state, baseline))

    return findings, notes


def _baseline_snapshot(state):
    return {
        "gateways": sorted(g["gw"] for g in state["gateways"]),
        "dns": sorted(state["dns"]),
        "ips": {n: sorted("%s/%d" % (a, p) for a, p in it["v4"])
                for n, it in state["ifaces"].items() if it["v4"]},
        "routes": sorted(set("%s->%s" % (r["destination"], r["gateway"])
                             for r in state["routes"] if r.get("family") == "inet")),
    }


def judge_baseline(state, baseline):
    """Compare state against saved baseline -> NL-90 / NL-91 findings."""
    findings = []
    cur = _baseline_snapshot(state)
    old_gw = set(baseline.get("gateways", []))
    old_dns = set(baseline.get("dns", []))
    if cur["gateways"] != sorted(old_gw):
        added = [g for g in cur["gateways"] if g not in old_gw]
        removed = [g for g in old_gw if g not in cur["gateways"]]
        findings.append({"id": "NL-90", "sev": "P1",
                         "title": "默认网关与基线不一致",
                         "detail": "新增: %s；消失: %s（基线 %s）"
                                   % (", ".join(added) or "无", ", ".join(removed) or "无",
                                      baseline.get("time", "?"))})
    if cur["dns"] != sorted(old_dns):
        added = [d for d in cur["dns"] if d not in old_dns]
        removed = [d for d in old_dns if d not in cur["dns"]]
        findings.append({"id": "NL-90", "sev": "P1",
                         "title": "DNS 集合与基线不一致（劫持高发信号）",
                         "detail": "新增: %s；消失: %s"
                                   % (", ".join(added) or "无", ", ".join(removed) or "无")})
    old_ips = baseline.get("ips", {})
    diffs = []
    for n in sorted(set(cur["ips"]) | set(old_ips)):
        if cur["ips"].get(n) != old_ips.get(n):
            diffs.append(n)
    old_routes = set(baseline.get("routes", []))
    r_added = [r for r in cur["routes"] if r not in old_routes]
    r_removed = [r for r in old_routes if r not in cur["routes"]]
    if diffs or r_added or r_removed:
        det = []
        if diffs:
            det.append("接口 IP 变化: %s" % ", ".join(diffs))
        if r_added:
            det.append("新增路由: %s" % ", ".join(r_added[:5]))
        if r_removed:
            det.append("消失路由: %s" % ", ".join(r_removed[:5]))
        findings.append({"id": "NL-91", "sev": "P2",
                         "title": "接口 IP / 路由表与基线有增删",
                         "detail": "；".join(det)})
    return findings


def risk_score(findings):
    """0-100：P0 -40 / P1 -20 / P2 -5，下限 5；无判决=100。"""
    if not findings:
        return 100
    score = 100
    for f in findings:
        score -= RISK_WEIGHT.get(f["sev"], 0)
    return max(5, score)


def exit_code(findings):
    if any(f["sev"] == "P0" for f in findings):
        return 3
    if any(f["sev"] == "P1" for f in findings):
        return 2
    if any(f["sev"] == "P2" for f in findings):
        return 1
    return 0


# ---------------------------------------------------------------- 探活（--probe：每 nameserver 一次 UDP53）

def _dns_query_packet(name="probe.example.com"):
    """构造一条极小 A 记录查询。"""
    header = struct.pack(">HHHHHH", 0x1a2b, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + q + struct.pack(">HH", 1, 1)


def probe_dns(dns_list, timeout=3.0):
    """向每个 nameserver 发一次 UDP53 查询。返回 [{ip, ms, status}]。"""
    pkt = _dns_query_packet()
    out = []
    for ip in dns_list:
        t0 = time.time()
        status = "ok"
        try:
            af = socket.AF_INET6 if ":" in ip else socket.AF_INET
            s = socket.socket(af, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (ip, 53))
            s.recvfrom(512)
            s.close()
        except socket.timeout:
            status = "timeout"
        except OSError as e:
            status = "error:%s" % e.__class__.__name__
        out.append({"ip": ip, "ms": round((time.time() - t0) * 1000), "status": status})
    return out


# ---------------------------------------------------------------- 渲染

SEV_MARK = {"P0": "●", "P1": "▲", "P2": "○"}


def render_text(state, findings, notes, probe_results=None, baseline_used=None):
    total_v4 = sum(1 for it in state["ifaces"].values() if it["v4"] and not it["loopback"])
    lines = []
    bar = "=" * 62
    lines.append(bar)
    lines.append(" %s v%s — 网络配置体检镜" % (TOOL, VERSION))
    lines.append(bar)
    lines.append(" 系统: %-8s  时间: %s" % (state["os"], time.strftime("%Y-%m-%d %H:%M:%S")))
    lines.append(" 体检范围: 网卡/路由 · DNS · hosts     模式: 只读，除 --probe 外零流量")
    lines.append("-" * 62)
    lines.append(" [概况] 接口 %d 个（带 IPv4 的 %d 个） · 默认网关 %d 个 · DNS %d 个 · hosts 条目 %d 条"
                 % (len(state["ifaces"]), total_v4, len(state["gateways"]),
                    len(state["dns"]), len(state["hosts_entries"])))
    if baseline_used:
        lines.append(" [基线] %s" % baseline_used)
    lines.append("")
    if findings:
        for f in findings:
            lines.append(" %s %s [%s] %s" % (SEV_MARK.get(f["sev"], "·"), f["id"], f["sev"], f["title"]))
            lines.append("     %s" % f["detail"])
    else:
        lines.append(" ● 全部通过：网卡/路由、DNS、hosts 三层配置面未见异常")
    lines.append("")
    if notes:
        lines.append(" [NOTE]")
        for n in notes:
            lines.append("   · %s" % n)
        lines.append("")
    if probe_results:
        lines.append(" [探活 --probe] UDP53 每服务器一次")
        for p in probe_results:
            mark = "ok" if p["status"] == "ok" else "!!"
            lines.append("   %s %-16s %4d ms  %s" % (mark, p["ip"], p["ms"], p["status"]))
        lines.append("")
    cnt = {"P0": 0, "P1": 0, "P2": 0}
    for f in findings:
        cnt[f["sev"]] += 1
    score = risk_score(findings)
    ec = exit_code(findings)
    lines.append("-" * 62)
    if findings:
        lines.append(" ▲ P0=%d · P1=%d · P2=%d · 综合风险分 %d/100 · 退出码 %d"
                     % (cnt["P0"], cnt["P1"], cnt["P2"], score, ec))
        hint = {3: "含 P0，今晚就修", 2: "含 P1，尽快核对", 1: "仅提示项，顺手清一清"}.get(ec, "")
        if hint:
            lines.append(" ▲ %s" % hint)
    else:
        lines.append(" ▲ 综合风险分 100/100 · 退出码 0")
    lines.append(" ▲ 接 cron 示例: python3 niclens.py --json >/dev/null || ../alert.sh")
    lines.append(bar)
    return "\n".join(lines)


def render_json(state, findings, notes, probe_results=None, baseline_used=None):
    return json.dumps({
        "tool": TOOL,
        "version": VERSION,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "os": state["os"],
        "summary": {
            "risk_score": risk_score(findings),
            "exit": exit_code(findings),
            "counts": {
                "P0": sum(1 for f in findings if f["sev"] == "P0"),
                "P1": sum(1 for f in findings if f["sev"] == "P1"),
                "P2": sum(1 for f in findings if f["sev"] == "P2"),
            },
        },
        "findings": findings,
        "notes": notes,
        "probe": probe_results,
        "baseline": baseline_used,
        "state": {
            "ifaces": state["ifaces"],
            "gateways": state["gateways"],
            "dns": state["dns"],
            "search": state["search"],
            "hosts_entries": len(state["hosts_entries"]),
            "hosts_badlines": len(state["hosts_badlines"]),
        },
    }, ensure_ascii=False, indent=1)


# ---------------------------------------------------------------- 演示沙箱（全部 10.213.x.x 合成数据）

DEMO_IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500
\tinet 10.213.20.15 netmask 0xfffffc00 broadcast 10.213.23.255
\tinet6 fe80::a1b2:c3d4:e5f6:a7b8 prefixlen 64 secured scopeid 0x5
\tmedia: autoselect
\tstatus: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500
\tinet 10.213.99.10 netmask 0xffffff00 broadcast 10.213.99.255
\tstatus: active
en6: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.213.77.2 netmask 0xffffff00 broadcast 10.213.77.255
\tstatus: inactive
utun5: flags=8051<UP,POINTOPOINT,RUNNING> mtu 900
\tinet6 fe80::dead:beef:cafe:1234 prefixlen 64 scopeid 0x11
"""

DEMO_ROUTES = """Routing tables

Internet:
Destination      Gateway          Flags        Refs      Use   Netif Expire
default          10.214.5.1       UGSc           45        0     en0
default          10.213.99.1      UGSc            0        0     en5
10.213.20/22     link#5           UCS             3        0     en0
10.213.99        link#7           UCS             2        0     en5

Internet6:
Destination      Gateway          Flags         Netif Expire
::1              ::1              UH              lo0
fe80::%en0       fe80::a1b2       UcI             en0
"""

DEMO_RESOLV = """# 演示沙箱：畸形 + 重复 + search 过多
nameserver 0.0.0.0
nameserver 10.213.99.53
nameserver 10.213.99.53
search corp.example.net lab.example.net old.example.net staging.example.net dev.example.net
"""

DEMO_HOSTS = """127.0.0.1 localhost
::1 localhost
255.255.255.255 broadcasthost
10.213.99.6 localhost
10.213.99.7 build-server.internal
10.213.99.8 build-server.internal
:not-an-ip artifact line
10.213.99.9 old-service.internal
## 以下为一行超长公钥样本，验证解析器对超长垃圾行的容错
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDcS7u5uT9xKq2vZ8mN4pR6wY1hJ3fL0oP8gA5bC7dE9fG2hI4jK5lM6nO7pQ8rS9tU1vW2xY3zA4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4vW5xY6zA7bC8dE9fG0hI1jK2lM3nO4pQ5rS6tU7vW8xY9zA0bC1dE2fG3hI4jK5lM6nO7pQ8rS9tU demo@host
"""


def run_demo(as_json=False):
    state = state_from_fixtures(DEMO_IFCONFIG, DEMO_ROUTES, DEMO_RESOLV,
                                DEMO_HOSTS, os_name="macos")
    findings, notes = judge(state)
    if as_json:
        return render_json(state, findings, notes, baseline_used="demo-sandbox")
    return render_text(state, findings, notes, baseline_used="demo-sandbox")


# ---------------------------------------------------------------- 主入口

def main(argv=None):
    ap = argparse.ArgumentParser(prog=TOOL, description="网络配置体检镜：只读体检网卡/路由/DNS/hosts")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--probe", action="store_true", help="向每个 nameserver 发一次 UDP53 探活（3s 超时）")
    ap.add_argument("--demo", action="store_true", help="内置演示沙箱（合成数据，零系统访问）")
    ap.add_argument("--save-baseline", metavar="FILE", help="保存当前状态为基线")
    ap.add_argument("--baseline", metavar="FILE", help="与基线对比，报 NL-90/91")
    ap.add_argument("--hosts", metavar="PATH", help="覆盖默认 hosts 路径")
    ap.add_argument("--resolv", metavar="PATH", help="覆盖默认 resolv 路径（macOS 上同时跳过 scutil）")
    args = ap.parse_args(argv)

    if args.demo:
        print(run_demo(as_json=args.json))
        return 0

    state = gather_state(hosts_path=args.hosts, resolv_path=args.resolv)

    baseline_used = None
    baseline = None
    if args.baseline:
        try:
            with open(args.baseline, "r", encoding="utf-8") as f:
                baseline = json.load(f)
            baseline_used = args.baseline
        except (OSError, ValueError) as e:
            state["notes"].append("基线读取失败 %s: %s" % (args.baseline, e.__class__.__name__))

    findings, notes = judge(state, baseline=baseline)

    probe_results = None
    if args.probe and state["dns"]:
        probe_results = probe_dns(state["dns"])

    if args.save_baseline:
        snap = _baseline_snapshot(state)
        snap["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        snap["tool"] = TOOL
        snap["version"] = VERSION
        try:
            with open(args.save_baseline, "w", encoding="utf-8") as f:
                json.dump(snap, f, ensure_ascii=False, indent=1)
            notes.append("基线已保存: %s" % args.save_baseline)
        except OSError as e:
            notes.append("基线保存失败: %s" % e.__class__.__name__)

    if args.json:
        print(render_json(state, findings, notes, probe_results, baseline_used))
    else:
        print(render_text(state, findings, notes, probe_results, baseline_used))
    return EXIT_MAP[exit_code(findings)]


if __name__ == "__main__":
    sys.exit(main())
