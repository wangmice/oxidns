# OxiDNS v1.6.1

## 🚀 发布概览

- v1.6.1 相比 v1.6.0 包含 243 个提交，重点更新缓存生命周期与 ECS 语义、UDP/DoH/DoQ 网络可靠性、upstream 连接池、provider 文件自动重载、DoH POST、forward 错误策略以及 HTTP 429 退避恢复。
- 新增配置项均保持兼容默认值：`runtime.provider_file_auto_reload` 默认关闭、DoH `use_post` 默认关闭、`keepalive_interval` 默认关闭、forward `on_error` 默认 `fail`。
- 本版本同时加强 DNS 响应关联校验与 DoH `Content-Type` 校验；此前被容忍但不符合协议的上游响应现在可能被拒绝。

## ✨ 主要亮点

### 缓存与 ECS

- 缓存持久化升级为 framed v3 流式格式，恢复时逐条解码；继续兼容读取 v1/v2 dump，并对截断帧、尾随数据和失败恢复保持事务性处理。
- 修复缓存跨重启 TTL/真实年龄恢复、dump/load 取消安全、dirty 状态、lazy refresh 生命周期、并发 miss 合并、过期条目清理和容量约束等问题。
- 重构 ECS 缓存索引与共享缓存路径，修复 scope/地址恢复、共享 ECS 语义、refresh re-key、索引重建与发布竞态，并将相关热路径和指标收集开销进一步压低。
- API 与 WebUI 已同步新的缓存实现；缓存 flush API 从 `GET` 调整为 `POST`。

### DNS 网络与 upstream

- 新增 SOCKS5 UDP 支持，并可通过 SOCKS5 代理 DoQ 与 DoH3；完善 IPv4/IPv6 跨地址族 relay、UDP ASSOCIATE 生命周期和 QUIC 发送路径。
- UDP、TCP、DoT、DoH、DoH3、DoQ 的响应关联校验进一步统一：校验响应方向、Opcode、Question、事务关联等，避免错误响应被接受或错误占用请求槽位。
- DoH/DoH3 成功响应现在严格校验 `application/dns-message`，支持合法参数语法并拒绝缺失或不受支持的媒体类型。
- Resolver DoT 现在发送 `dot` ALPN；DoH URL 会保留固定 query 参数；IPv6 literal URI、H2 flow-control、H3 GOAWAY、DoQ STOP_SENDING、TCP/DoT shutdown 等边界行为得到修复。
- upstream 连接池强化并发容量、paced expansion、取消和回收生命周期；新增可选 `keepalive_interval`，分别支持 H2 PING、QUIC keepalive 和 TCP keepalive。
- 新增 upstream timeout stage 指标，可区分 `pool_acquire`、`connection_create`、`protocol_handshake` 与 `query_io`，并在 WebUI 中展示。

### Provider 文件自动重载

- `domain_set`、`ip_set`、`adguard_rule`、`geosite`、`geoip` 的文件源支持自动监听并重载。
- 使用 `runtime.provider_file_auto_reload: true` 显式启用；默认关闭，不影响原有手动 reload。
- 自动重载使用有界事件合并和 500 ms trailing debounce；重载失败时保留上一份可用 provider 快照，并在 runtime teardown 时正确停止 watcher。
- `dynamic_domain_set` 的机器管理文件不会加入自动文件监听。

### DoH 与 forward

- upstream 新增 `use_post`：DoH over HTTP/2 与 HTTP/3 可使用 RFC 8484 POST，请求体为 `application/dns-message`；默认仍使用 GET，非 DoH upstream 忽略该选项。
- forward 新增 `on_error: fail | continue`；默认 `fail` 保持原行为，`continue` 可在所有可用 upstream 最终失败后记录错误并继续当前 sequence。
- DoH/DoH3 HTTP 429 增加 per-upstream cooldown 与指数退避：本地退避从 1 秒起步并上限 60 秒，数值型 `Retry-After` 最多采用 300 秒。
- cooldown 到期后只允许一个 half-open probe；处于 cooldown 的 upstream 会被跳过，并可在同一查询预算内尝试健康候选。
- 429 处理经过 generation/ownership 竞态加固，避免 stale 429、probe cancellation、Retry-After publication 与成功恢复之间的状态覆盖和同步自旋；应用层限流不会主动关闭健康的 H2/H3 连接。

### UDP 服务与可观测性

- UDP ingress 在完整 DNS 解析前先做固定 header 分类，对非法 opcode、错误 question count、畸形 datagram 和潜在签名请求采用更严格的处理。
- UDP handler 增加低开销 admission control、可靠 shutdown/drain，并避免错误包或 send backpressure 放大日志和阻塞接收循环。
- UDP response 按 IPv4/IPv6 非 jumbogram 上限约束，增强 reply source/interface 处理与持续 receive-error backoff。
- upstream 日志增加稳定身份信息，并减少重复 connection failure 日志；WebUI 同步新的 UDP、timeout、cache 与 forward 指标和配置项。

### 构建与打包

- 增加 Debian `cargo-deb` 元数据与 systemd 安装脚本/单元文件，便于生成和安装 `.deb` 包。
- 更新多项 Rust 依赖和 feature gating，继续保持 `minimal`、`standard`、`full` bundle 构建路径。

## ⚠️ 升级说明

- **缓存 flush API 有方法变化**：调用缓存 flush 的外部脚本或 API 客户端需要从 `GET` 改为 `POST`；WebUI 已同步。
- **Provider 自动文件重载默认关闭**：如需自动监听规则文件变化，请显式设置：
  ```yaml
  runtime:
    provider_file_auto_reload: true
  ```
- **DoH POST 默认关闭**：需要 POST 时在对应 upstream 中设置 `use_post: true`；未配置时继续使用 GET。
- **Forward 错误策略默认不变**：`on_error` 默认 `fail`；只有显式使用 `continue` 才会在 forward 最终失败后继续 sequence。
- **Upstream keepalive 默认关闭**：`keepalive_interval` 仅在显式配置后启用；UDP upstream 不支持该选项。
- **协议校验更严格**：DoH/DoH3 必须返回正确的 `application/dns-message`，DNS 响应必须与原查询正确关联；若第三方上游此前返回非标准响应，升级后可能暴露为协议错误。
- **缓存 dump 无需强制清理**：v1.6.1 的 v3 持久化格式仍可读取 v1/v2 dump。
- 建议升级前运行 `oxidns check -c <配置文件>`。根 crate 为 `1.6.1`，`oxidns-proto` 为 `0.1.6`，`oxidns-ripset` 为 `0.1.3`；tag 为 `v1.6.1`。

## 📦 下载与校验

- 根据平台和 bundle 选择对应 archive，并使用 GitHub Release asset 的 digest 校验下载文件。
