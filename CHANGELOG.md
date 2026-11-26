# Changelog — niclens

## 1.0.0 (2026-11-26)

首个公开版本。

- 15 条判决：NL-01~NL-13 配置判决 + NL-90/91 基线判决
- 三层体检：网卡/路由（macOS ifconfig/netstat、Linux ip）· DNS（scutil --dns / resolv.conf）· hosts
- 退出码分级 0/1/2/3 直接接 cron；综合风险分 0-100
- `--probe`：每 nameserver 一次 UDP53 探活（3s 超时），其余场景零流量
- `--save-baseline` / `--baseline`：把「今天正常」变成「明天的参照物」
- `--demo`：合成沙箱预埋 4 类故障，零系统访问现场演示
- `--hosts` / `--resolv`：体检任意文件（测试用）
- 自测 41 项全绿：每条判决正例+反例（反例=不能误报）
- 真机狗粮修复：macOS 双栈 hosts（127.0.0.1 + ::1）误报 NL-08 → 回归用例 12b/12c
