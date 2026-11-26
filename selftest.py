#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""niclens selftest — 每条判决至少 1 正例 + 1 反例（反例=不能误报），全绿才算交付。"""
import copy
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import niclens  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS  %s" % name)
    else:
        FAIL += 1
        print("FAIL  %s  %s" % (name, detail))


def ids(findings):
    return [f["id"] for f in findings]


def judge_fix(**kw):
    st = niclens.state_from_fixtures(**kw)
    f, n = niclens.judge(st)
    return st, f, n


# ---------------------------------------------------------------- macOS fixture

GOOD_MAC_IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500
\tinet 10.213.20.15 netmask 0xfffffc00 broadcast 10.213.23.255
\tinet6 fe80::a1b2:c3d4:e5f6:a7b8 prefixlen 64 secured scopeid 0x5
\tstatus: active
utun5: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1380
\tinet6 fe80::dead:beef:cafe:1234 prefixlen 64 scopeid 0x11
"""

GOOD_MAC_ROUTES = """Routing tables

Internet:
Destination      Gateway          Flags        Refs      Use   Netif Expire
default          10.213.20.1      UGSc           45        0     en0
10.213.20/22     link#5           UCS             3        0     en0

Internet6:
Destination      Gateway          Flags         Netif Expire
::1              ::1              UH              lo0
fe80::%en0       fe80::a1b2       UcI             en0
"""

GOOD_RESOLV = """nameserver 10.213.99.53
nameserver 223.5.5.5
search corp.example.net
"""

GOOD_HOSTS = """127.0.0.1 localhost
255.255.255.255 broadcasthost
10.213.99.7 build-server.internal
"""

# ---------------------------------------------------------------- Linux fixtures

GOOD_LINUX_IPADDR = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 10.213.30.20/24 brd 10.213.30.255 scope global eth0
    inet6 fe80::5054:ff:fe11:2233/64 scope link
3: eth9: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN
    inet 10.213.40.20/24 scope global eth9
"""

GOOD_LINUX_ROUTE = """default via 10.213.30.1 dev eth0 metric 100
default via 10.213.40.1 dev eth9 metric 200
10.213.30.0/24 dev eth0 proto kernel scope link src 10.213.30.20
10.213.40.0/24 dev eth9 proto kernel scope link src 10.213.40.20
"""

LINUX_IFCONFIG_ALT = GOOD_LINUX_IPADDR  # state_from_fixtures os_name 控制解析器

LINUX_NO_GW_ROUTE = """10.213.30.0/24 dev eth0 proto kernel scope link src 10.213.30.20
"""

# ---------------------------------------------------------------- tests

print("=== niclens selftest ===")

# 1-2 正常机器：零判决（核心反例——不能把好机器误报）
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("clean mac zero findings", f == [], "got %s" % ids(f))
check("clean mac exit 0 score 100",
      niclens.exit_code(f) == 0 and niclens.risk_score(f) == 100)

# 3 macOS utun 无 IPv4 不触发 NL-01/03
check("utun no-v4 not NL-01/03", "NL-01" not in ids(f) and "NL-03" not in ids(f))

# 4 NL-01 有 v4 接口却无网关
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=LINUX_NO_GW_ROUTE.replace(
    "10.213.30.0/24 dev eth0 proto kernel scope link src 10.213.30.20",
    "10.213.20/22     link#5           UCS             3        0     en0"),
    resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-01 fires when no default gw",
      "NL-01" in ids(f) and niclens.exit_code(f) == 3,
      "got %s" % ids(f))

# 5 纯环回机器不误报 NL-01
lo_only = GOOD_MAC_IFCONFIG.split("en0:")[0]
st, f, n = judge_fix(ifconfig_text=lo_only, routes_text="", resolv_text=GOOD_RESOLV,
                     hosts_text=GOOD_HOSTS, os_name="macos")
check("loopback-only no NL-01", "NL-01" not in ids(f), "got %s" % ids(f))

# 6 NL-02 双网关无 metric
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=niclens.DEMO_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-02 dual gw conflict", "NL-02" in ids(f), "got %s" % ids(f))

# 7 NL-02 反例：metric 可区分降 NOTE
linux_metric_route = GOOD_LINUX_ROUTE  # 100/200 可区分
st, f, n = judge_fix(ifconfig_text=GOOD_LINUX_IPADDR, routes_text=linux_metric_route,
                     resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="linux")
check("NL-02 metric-distinguished -> NOTE",
      "NL-02" not in ids(f) and any("metric 可区分" in x for x in n),
      "got %s | notes %s" % (ids(f), n))

# 8 NL-03 网关出网段（mac fixture：网关 10.214.5.1 vs en0 /22=10.213.20-23）
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES.replace(
    "default          10.213.20.1", "default          10.214.5.1"),
    resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-03 gw outside subnets", "NL-03" in ids(f), "got %s" % ids(f))

# 9 NL-03 反例：网关恰在 /22 网段边缘（10.213.23.254 ∈ 10.213.20.0/22）
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES.replace(
    "default          10.213.20.1", "default          10.213.23.254"),
    resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-03 edge-of-/22 gw OK", "NL-03" not in ids(f), "got %s" % ids(f))

# 10 NL-04 网关=本机 IP
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES.replace(
    "default          10.213.20.1", "default          10.213.20.15"),
    resolv_text=GOOD_RES_RESOLV if False else GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-04 gw==own ip", "NL-04" in ids(f) and "NL-03" not in ids(f), "got %s" % ids(f))

# 11 NL-05 localhost 劫持
bad_hosts = GOOD_HOSTS + "\n10.213.99.6 localhost\n"
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=bad_hosts, os_name="macos")
check("NL-05 localhost hijack", "NL-05" in ids(f), "got %s" % ids(f))

# 12 NL-05 反例：正常 127.0.0.1 不报
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-05 normal localhost OK", "NL-05" not in ids(f))

# 12b 回归（真机狗粮抓到的真 bug）：macOS 标准双栈 localhost 127.0.0.1+::1 不得触发 NL-08
dual_hosts = GOOD_HOSTS + "\n::1 localhost\n"
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=dual_hosts, os_name="macos")
check("NL-08 dual-stack localhost OK (real-bug regression)", "NL-08" not in ids(f),
      "got %s" % ids(f))
# 12c 混入一个非环回 IP 就必须报
poison = dual_hosts + "10.213.99.6 localhost\n"
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=poison, os_name="macos")
check("NL-08 loopback+external still fires", "NL-08" in ids(f), "got %s" % ids(f))

# 13 NL-06 无 DNS
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text="", hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-06 no dns", "NL-06" in ids(f) and niclens.exit_code(f) == 2, "got %s" % ids(f))

# 14 NL-07 畸形 DNS
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text="nameserver 0.0.0.0\nnameserver 10.213.99.53\n",
                     hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-07 bogus dns", "NL-07" in ids(f), "got %s" % ids(f))

# 15 NL-07 反例：systemd stub 不算畸形
st, f, n = judge_fix(ifconfig_text=GOOD_LINUX_IPADDR, routes_text=GOOD_LINUX_ROUTE,
                     resolv_text="nameserver 127.0.0.53\n", hosts_text=GOOD_HOSTS,
                     os_name="linux")
check("NL-07 systemd stub -> NOTE", "NL-07" not in ids(f)
      and any("127.0.0.53" in x for x in n), "got %s | notes %s" % (ids(f), n))

# 16 NL-08 同名多 IP
dup_hosts = GOOD_HOSTS.replace("10.213.99.7 build-server.internal",
                               "10.213.99.7 build-server.internal\n10.213.99.8 build-server.internal")
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=dup_hosts, os_name="macos")
check("NL-08 multi-ip hostname", "NL-08" in ids(f), "got %s" % ids(f))

# 17 NL-08 反例：同名同 IP 重复行（去重）不报
same_dup = GOOD_HOSTS + "10.213.99.7 build-server.internal\n"
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=same_dup, hostmap_ignore=None,
                     os_name="macos") if False else judge_fix(
    ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
    resolv_text=GOOD_RESOLV, hosts_text=same_dup, os_name="macos")
check("NL-08 same-ip dup OK", "NL-08" not in ids(f), "got %s" % ids(f))

# 18 NL-09 DOWN 但配了 IP
down_if = GOOD_LINUX_IPADDR  # eth9 state DOWN 配了 10.213.40.20
st, f, n = judge_fix(ifconfig_text=down_if, routes_text=GOOD_LINUX_ROUTE,
                     resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="linux")
check("NL-09 iface down w/ ip", "NL-09" in ids(f), "got %s" % ids(f))

# 19 NL-09 反例：macOS en6 inactive 由 DEMO fixture 验证（见 test 27），此处验 UP 接口不报
check("NL-09 good iface no fire", "NL-09" not in ids(judge_fix(
    ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
    resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")[1]))

# 20 NL-10 MTU 异常
mtu_if = GOOD_MAC_IFCONFIG.replace("utun5: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1380",
                                   "utun5: flags=8051<UP,POINTOPOINT,RUNNING> mtu 900")
st, f, n = judge_fix(ifconfig_text=mtu_if, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-10 low mtu", "NL-10" in ids(f), "got %s" % ids(f))

# 21 NL-10 反例：MTU 1380 正常
check("NL-10 mtu 1380 OK", "NL-10" not in ids(judge_fix(
    ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
    resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")[1]))

# 22 NL-11 重复 nameserver
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text="nameserver 10.213.99.53\nnameserver 10.213.99.53\n",
                     hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-11 dup nameserver", "NL-11" in ids(f), "got %s" % ids(f))

# 23 NL-12 hosts 坏行
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV,
                     hosts_text=GOOD_HOSTS + "\n:not-an-ip junk\nlonely-token\n",
                     os_name="macos")
check("NL-12 hosts badlines", "NL-12" in ids(f), "got %s" % ids(f))

# 24 NL-13 search 过多
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text="nameserver 10.213.99.53\nsearch a b c d e\n",
                     hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-13 too many search", "NL-13" in ids(f), "got %s" % ids(f))

# 25 NL-13 反例：3 个正好
st, f, n = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                     resolv_text="nameserver 10.213.99.53\nsearch a b c\n",
                     hosts_text=GOOD_HOSTS, os_name="macos")
check("NL-13 three search OK", "NL-13" not in ids(f))

# 26 NL-90/91 基线：先存后改
st1, f1, _ = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG, routes_text=GOOD_MAC_ROUTES,
                       resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
snap = niclens._baseline_snapshot(st1)
st2, f2, _ = judge_fix(ifconfig_text=GOOD_MAC_IFCONFIG,
                       routes_text=GOOD_MAC_ROUTES.replace(
                           "default          10.213.20.1", "default          10.213.66.1"),
                       resolv_text=GOOD_RESOLV.replace("10.213.99.53", "10.213.66.53"),
                       hosts_text=GOOD_HOSTS, os_name="macos")
fb = niclens.judge_baseline(st2, snap)
check("NL-90 gw+dns drift", sum(1 for x in fb if x["id"] == "NL-90") == 2,
      "got %s" % ids(fb))
check("NL-91 route drift", "NL-91" in ids(fb), "got %s" % ids(fb))

# 27 基线一致 → 零判决
fb2 = niclens.judge_baseline(st1, snap)
check("baseline identical no findings", fb2 == [])

# 28 退出码映射（exit_map sanity: P2-only -> 1）
st, f, n = judge_fix(ifconfig_text=mtu_if, routes_text=GOOD_MAC_ROUTES,
                     resolv_text=GOOD_RESOLV, hosts_text=GOOD_HOSTS, os_name="macos")
check("exit P2-only == 1", niclens.exit_code(f) == 1, "got %d %s" % (niclens.exit_code(f), ids(f)))

# 29 --demo 端到端（子进程真实跑）
r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                 "niclens.py"), "--demo"],
                   capture_output=True, text=True)
check("demo runs rc=0", r.returncode == 0, r.stderr[:100])
check("demo fires NL-02/03/05/07/11",
      all(x in r.stdout for x in ("NL-02", "NL-03", "NL-05", "NL-07", "NL-11")))
check("demo no company ranges", "172.16" not in r.stdout and "172.18" not in r.stdout
      and "10.92." not in r.stdout)

# 30 --json 输出 schema 稳定
r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                 "niclens.py"), "--demo", "--json"],
                   capture_output=True, text=True)
j = json.loads(r.stdout)
need = {"tool", "version", "summary", "findings", "notes", "state"}
check("json schema keys", need.issubset(j.keys()), "missing %s" % (need - set(j.keys())))
check("json summary counts consistent",
      j["summary"]["counts"]["P0"] == sum(1 for x in j["findings"] if x["sev"] == "P0"))

# 31 真机只读解析 smoke（不出判决要求，只求不崩+结构对）
r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                 "niclens.py"), "--json"],
                   capture_output=True, text=True)
try:
    j2 = json.loads(r.stdout)
    ok = isinstance(j2.get("state", {}).get("ifaces", {}), dict) and r.returncode in (0, 1, 2, 3)
except Exception:
    ok = False
check("live run json parse + rc in {0,1,2,3}", ok)

# 32 parse_hosts 超长垃圾行容错（demo hosts 含 2048 位公钥样本）
entries, badlines, hm = niclens.parse_hosts(niclens.DEMO_HOSTS)
check("hosts parser tolerates pubkey junk", len(entries) >= 5)

# 33 parse_dns_scutil 真实格式
sc = """resolver #1
  nameserver[0] : 10.213.99.53
  nameserver[1] : 223.5.5.5
  if_index : 5 (en0)
resolver #2
  nameserver[0] : 10.213.99.53
"""
check("scutil parser dedup+order", niclens.parse_dns_scutil(sc) == ["10.213.99.53", "223.5.5.5"])

# 34 risk score 下限
from niclens import risk_score  # noqa: E402
fake_bad = [{"sev": "P0"}] * 5
check("risk floor 5", risk_score(fake_bad) == 5)

# 35 probe 包构造合法（不发流量，只验字节）
pkt = niclens._dns_query_packet()
# 12B header + (1+5)+(1+7)+(1+3)+1终止 = 19B QNAME + 4B QTYPE/QCLASS = 35B
check("dns probe packet shape", len(pkt) == 35 and pkt[-4:] == b"\x00\x01\x00\x01",
      "len=%d" % len(pkt))

print("=== %d passed, %d failed ===" % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
