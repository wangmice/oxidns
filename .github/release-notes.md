# OxiDNS v1.7.1

## 🚀 发布概览

- v1.7.1 是补丁版本，修复上游响应缓冲边界、DNS 压缩指针解析及容器单文件挂载的配置保存问题。

## ✨ 主要亮点

- 新增 `load_balance` 执行器，支持轮询、随机和加权随机；新增 `has_cname` matcher，两者均可用于 minimal bundle。
- 新增 minimal 可用的 `edns_filter` 执行器，支持 `preserve`、`strip`、`strip_unknown` 策略及 option code 白名单/黑名单；默认在后续执行链退出或取消时恢复整个请求。补齐 EDNS 注册代码识别，未实现 payload 解析的选项仍保留原始数据，查询记录同步显示名称。
- 修复 `ecs_handler` 删除客户端 ECS 后未继续应用 `preset`/`send` 的问题；非 IN 查询也遵循删除策略，但不生成 ECS。
- `hosts.format: standard` 支持标准 hosts 文件与地址合并；`learn_domain.rule_kind: registrable_domain` 使用内置公共后缀表学习可注册域及其子域。
- WebUI 查询分析增加统一时间条、自适应趋势桶、统计截断提示和记录下钻，支持精确域名、客户端 IP 与特殊响应分类筛选；补充 EDNS 过滤配置入口并修复 YAML 嵌套字段补全。
- 缓存保留 `ip` 过滤及 keyset/snapshot 分页，新增 `answer_ip` 别名和批量删除；启动时等待恢复，失败的启动/reload 不再覆盖历史 dump，读取失败时保护原文件。
- RouterOS 路由增加可选 `scope`、`target_scope`，修复地址列表重复插入恢复、地址表示及清理。
- 修正 NOTIMP/BADVERS 响应、超大 TCP 帧、TCP keepalive 和 DoQ/DoH3 停机任务等待；支持 OpenWrt `/etc/TZ`，同步 zoneparser 修复。
- 管理 API 限制请求体大小、改进 Basic Auth 凭据比较；配置原子保存保留 Unix 权限、属主、属组及符号链接。
- Docker 新增 ARMv7 镜像；文档源码迁至 `website/`，补充社区 WebUI 推荐。`oxidns-proto` 与 `oxidns-macros` 改为 MIT/Apache-2.0 双许可证，主项目许可证不变。

## ⚠️ 升级说明

- **保留本地 DoH2 修复**：keepalive PING 失败回收失效连接，成功响应解除查询准入门控；保留 IPv6 TLS identity 与连接诊断修复。未启用 HTTP/3 的 DoH 上游，其有效 `idle_timeout` 与启用的 `keepalive_interval` 仍须小于 `2^32` 毫秒；`keepalive_interval` 默认关闭。
- **统计 API 调用变更**：`query_recorder` 的 `/stats/*` 必须提供 `since_ms`、`until_ms`，开始时间早于结束时间，跨度最多 24 小时；旧的不带时间调用会返回 HTTP 400。统计最多使用区间内最近 10,000 条记录；列表、详情与 SSE 接口保持原有时间参数语义。
- **回退行为变更**：显式 `fallback.threshold: 0` 现在立即启动备用分支；如需保留旧延迟，改为 `500`。省略字段仍默认 500 毫秒。
- **ECS 行为修复**：IN 查询依次采用保留的客户端 ECS、`preset`、`send` 对应的客户端地址；`forward: false` 删除原 ECS 后仍可补发。非法 quick-setup IP 现在会导致配置加载失败；旧 `IP/mask` 写法仍忽略 mask，使用 IPv4 `/24`、IPv6 `/48`，自定义前缀请用完整配置。
- 除上述行为修复和校验收紧外，现有 v1.6.1 YAML 配置可继续使用，新增字段均为可选。`edns_filter` 需要显式加入执行链，默认 `policy: preserve`、`restore_request: true`，白名单和黑名单默认留空。管理 API 按 handler 限制请求体大小，缓存 dump 导入采用独立限额；建议同步更新随包 WebUI。
- 从 v1.6.1 升级无需迁移查询历史或重新安装 Windows 服务；更早版本仍须遵循 v1.6.0 的迁移说明。升级前备份配置和持久化数据，并运行 `oxidns check -c <配置文件>`。

- DoH/H2/H3 上游响应体限制为 65,535 字节，限制 `Content-Length` 预分配并逐块校验实际长度，避免缺失或虚报长度头导致无界缓冲。
- DNS 名称解析以每次跳转 O(1) 的边界检查替代已访问偏移扫描，拒绝前向指针及跨标签/指针的循环，保留合法嵌套压缩后缀与既有跳转次数限制。
- Unix 配置保存遇到单文件挂载点的 `EBUSY` 时，校验文件身份后原地写入，保留 inode、权限与属主/属组；普通文件仍原子替换。补充 Docker 与 RouterOS Container 的配置目录挂载说明。

- v1.7.0 YAML 配置可直接升级，没有新增、重命名或删除字段，默认值和 bundle 不变。超出上述大小限制的上游 DoH 响应、包含前向或循环压缩指针的 DNS 报文现在会被拒绝。
- **单文件挂载保存不具备原子性**：中断或 I/O 错误可能留下不完整配置，回退时会记录警告。建议可写挂载配置所在目录并保留备份；只读挂载仍无法通过 WebUI 保存。
- 升级前备份配置和持久化数据，并运行 `oxidns check -c <配置文件>`；更早版本仍须遵循对应版本的迁移说明。
- 根 crate 为 `1.7.1`，tag 为 `v1.7.1`；`oxidns-proto` 为 `0.1.8`、`oxidns-zoneparser` 为 `0.1.4`（更新协议依赖），`oxidns-macros` 保持 `0.1.1`、`oxidns-ripset` 保持 `0.1.3`。本分支保持禁用 crates.io 自动发布，发布 Action 不会上传这些 crate。

## 📦 下载与校验

- 根据平台和 bundle 选择对应 archive，并使用 GitHub Release asset 的 SHA256 digest 校验下载文件。

## ✅ 验证

- `just check`
- `just check-matrix`
- EDNS 补充验证：`cargo test --locked -p oxidns-proto`、`cargo test --locked --no-default-features --features minimal edns_filter`。
- 协议与 zoneparser：`cargo test --locked -p oxidns-proto -p oxidns-zoneparser`。
- 双语文档：在 `website/` 运行 `npm run build`。
- Telegram 发布消息：`python3 -m unittest discover -s .github/scripts -p '*_test.py'`。
- full/minimal：`cargo build --locked --no-default-features --features full` / `minimal`，以及 `oxidns --version`、`oxidns build-info` 和对应的 `oxidns check -c config.yaml` / `oxidns check -c config.minimal.yaml`。
- crates.io workspace dry-run：`cargo publish --locked --dry-run --allow-dirty --workspace`（包含打包后编译验证，未上传）。
