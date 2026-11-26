# niclens — 网络配置体检镜

[简体中文](README.md) | [English](README_EN.md)

> 不发包、不改配置，一次只读体检回答一个问题：**「这台机器的网络配置面本身有没有病？」**
> 网卡/路由、DNS、hosts 三层一次查完，15 条判决，退出码直接 cron。

[![release](https://img.shields.io/badge/release-v1.0.0-blue)]() [![license](https://img.shields.io/badge/license-MIT-green)]() [![python](https://img.shields.io/badge/python-3.8%2B-informational)]() [![deps](https://img.shields.io/badge/dependencies-zero-success)]()

## 它解决什么问题

这些场景你一定遇到过：

- 迁移/割接之后「有的机器通、有的不通」——最后发现是某台静态网关填错了网段
- 装了 VPN 之后莫名上不了内网，`ping` 网关通，域名全挂——双默认路由在打架
- 服务器换完网卡，老接口的静态 IP 还躺在 DOWN 的接口上，没人记得
- hosts 被某次「临时调试」改过，localhost 被指到了别的机器，半年没人发现
- 接了陌生 Wi-Fi / 入职新电脑，想知道这台机器的网络配置干不干净

`ping` 只告诉你此刻通不通，`ifconfig` 只给你一屏原始参数。**把配置读完、
再判断它「合不合理」，这步没人替你做**——niclens 就是这步。

三层体检范围：

| 层 | 查什么 | 典型病灶 |
|---|---|---|
| **网卡/路由** | IP/掩码/网关/MTU/接口状态 | 无网关孤岛、双网关打架、网关出网段、路由自环、DOWN 接口残留 IP |
| **DNS** | resolv.conf / scutil --dns | 空 DNS、0.0.0.0 畸形值、重复项、search 域堆砌 |
| **hosts** | /etc/hosts 全表 | localhost 劫持、同名多 IP 哑弹、坏行 |

## 安装

```bash
# 方式一：直接拉单文件（仅标准库，Python 3.8+）
curl -fsSLO https://raw.githubusercontent.com/tomlen045/niclens/main/niclens.py

# 方式二：git clone 整仓（含 selftest / demo 沙箱）
git clone https://github.com/tomlen045/niclens.git
```

## 30 秒上手

```bash
python3 niclens.py              # 默认全体检（macOS / Linux，无需 root）
python3 niclens.py --json       # 机器可读输出，接 cron / webhook
python3 niclens.py --probe      # 附加：向每个 nameserver 发一次 UDP53 探活
python3 niclens.py --demo       # 沙箱演示：预埋 4 类故障的合成配置，现场抓给你看
```

退出码分级（可直接接 cron）：

| 退出码 | 含义 |
|---|---|
| 0 | 干净（100 分） |
| 1 | 仅 P2 提示项 |
| 2 | 含 P1 高危 |
| 3 | 含 P0 断网级 |

## 判决体系（NL-01 ~ NL-13 + 基线 NL-90/91）

| 编号 | 级别 | 判决 |
|---|---|---|
| NL-01 | P0 | 无默认网关（有非环回 IPv4 接口却是孤岛） |
| NL-02 | P0 | 多条冲突默认网关（不同下一跳且无 metric 区分；有 metric 区分的降为 NOTE） |
| NL-03 | P0 | 默认网关不在任何本机 IPv4 网段内（IPv6 链路本地网关属正常，跳过） |
| NL-04 | P0 | 网关 IP 与本机网卡 IP 相同（路由自环） |
| NL-05 | P0 | hosts 把 localhost 映射到非环回 IP（劫持） |
| NL-06 | P1 | 无任何 DNS 配置 |
| NL-07 | P1 | DNS 地址畸形（0.0.0.0 / 组播 / 广播段；systemd-resolved stub 127.0.0.53 不算，给 NOTE） |
| NL-08 | P1 | hosts 同一主机名映射多个不同 IP（双栈环回 127.0.0.1+::1 属标准写法，不算） |
| NL-09 | P1 | 接口配了 IPv4 但状态 DOWN（换网卡后忘删的静态配置） |
| NL-10 | P2 | MTU 异常（< 1280） |
| NL-11 | P2 | resolv.conf 重复 nameserver |
| NL-12 | P2 | hosts 坏行（列数不足 / IP 非法） |
| NL-13 | P2 | search 域过多（> 3，每个失败解析都要轮一遍列表） |
| NL-90 | P1 | 基线对比：默认网关 / DNS 集合变化（DNS 被换 = 劫持高发信号） |
| NL-91 | P2 | 基线对比：接口 IP / 路由表增删 |

## 基线：把「今天正常」变成「明天的参照物」

```bash
python3 niclens.py --save-baseline niclens-baseline.json   # 今天：存基线
python3 niclens.py --baseline niclens-baseline.json        # 明天：对比
```

网关被换、DNS 被偷偷改、接口 IP 漂移、路由表多出条目——凡是和基线不一致的，
NL-90（P1）/ NL-91（P2）直接点名。基线只存排序后的网关/DNS/IP/路由摘要，
不存任何原始报文。

## 设计铁律（不变量）

1. **只读**：不改任何配置、不动网络状态；除 `--probe` 外零流量
2. **零依赖**：纯标准库，Python 3.8+，单文件，拷走就能跑
3. **无需 root**：只用免 root 只读命令（ifconfig/netstat/scutil 或 ip）
4. **解析容错**：命令输出解析不到就降级 NOTE，不猜不崩
5. **退出码分级**：cron 里 `||` 一接就能告警

## 与套件其他工具的分工

niclens 是自研运维透镜/哨兵套件的第 8 件：

> **porteye**（谁在听）→ **callhome**（谁打电话回家）→ **authguard**（谁想进来）
> → **freshlens**（什么文件被动了）→ **histlens**（这台机器跑过什么）→ **niclens**（网络配置面有没有病）

与 [dnsdiff](https://gitee.com/tomlen/dnsdiff) 的边界（两个工具背靠背）：

- **dnsdiff** 对账的是**运行态**解析结果——你的电脑实际拿到的答案 vs 公共池 vs 多数派
- **niclens** 体检的是**配置态**本身——resolv.conf / hosts / 网卡路由写的是否合理
- 先用 niclens 确认配置没病，再用 dnsdiff 确认答案没被中途做手脚

## 测试

```bash
python3 selftest.py    # 41 项：每条判决正例+反例（反例=不能误报）+ 真机回归
python3 niclens.py --demo   # 无害沙箱演示，预埋 4 类故障
```

## LICENSE

MIT
