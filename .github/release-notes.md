# OxiDNS v1.6.2

## 🚀 发布概览

- v1.6.2 是面向稳定性的 Patch Release，重点修复 `query_recorder` 的 SQLite 存储恢复、管理操作、定期清理、优雅关闭与插件初始化生命周期问题。
- 同时修复 upstream HTTP 429 冷却恢复边界、API 路由批量注册一致性和 feature gating 问题。
- 现有配置默认行为保持不变，v1.6.1 配置可以直接升级。

## ✨ 主要亮点

### Query Recorder 稳定性

- 强化 SQLite 存储异常恢复，支持连接重建和可写性验证，并处理数据库损坏、只读、磁盘满和文件锁等错误。
- 定期清理增加取消、超时、批量边界与公平重试，避免多个 recorder 共享数据库时清理任务长期饥饿。
- 管理 API 的查询、统计、清理和清空操作增加并发控制与停止检查，避免无限等待；shutdown 会主动关闭 reader gate。
- 改进优雅关闭，尽可能完成健康状态下的 pending record flush，并报告此前批次和最终 flush 的失败信息。
- 初始化失败时回滚 cleanup task、writer thread 和相关资源；API 路由采用批量原子注册，避免部分路由发布或失败 backend 被 handler 持有。

### 性能与 API

- execution path 只复制 recorder 自身新增部分。
- SSE tail 与广播记录使用共享对象，减少重复复制。
- exact/prefix API 路由增加重复检测，批量注册失败时保持注册表不变。
- API-only 构建保持 warning-clean，并将 `fs2` 限制到实际使用它的 feature。

### Upstream 429 恢复

- 修复 HTTP 429 冷却状态在 half-open probe 恢复期间丢失 backoff 的问题。
- 保留跨 generation 的退避状态，避免 upstream 过早恢复或重复探测。

### 测试与生命周期

- 增加初始化回滚、idle writer 唤醒、清理超时与公平重试、管理并发和 full-queue 场景测试。
- 强化 writer shutdown、存储恢复、共享数据库和管理操作竞争场景覆盖。

## ⚠️ 升级说明

- v1.6.1 YAML 配置可以直接升级，本版本没有新增必填配置，也没有改变现有配置默认值。
- query recorder 现有 SQLite 数据库可以继续使用；存储异常恢复和清理操作可能在后台产生额外磁盘 I/O。
- 建议升级前运行：
  ```bash
  oxidns check -c <配置文件>
  ```
- 目标根 crate 版本为 `1.6.2`，`oxidns-proto` 为 `0.1.6`，`oxidns-ripset` 为 `0.1.3`；tag 使用 `v1.6.2`。

### 合入上游 v1.6.1 修复

- TCP/UDP 连接关闭后及时结束后台收发任务、取消等待中的查询，避免已关闭连接持续占用内存与套接字；TCP 写入失败或阻塞时也能退出。
- 正确识别上游 URL 中带方括号的 IPv6 地址，直接连接，不再误走域名 bootstrap 解析；上游探测同步修正。
- 连接池与关闭日志增加上游标识、主机、端口和传输信息；正常并发转发中的查询取消改为 debug 日志。
- 更新 Rust 依赖。

## 📦 下载与校验

- 根据平台和 bundle 选择对应 archive，并使用 GitHub Release asset 的 SHA256 digest 校验下载文件。

## ✅ 验证

- `just check`
- `just check-matrix`
- 文档：`npm run build`
- Telegram 发布消息：`python3 -m unittest discover -s .github/scripts -p '*_test.py'`
- crates.io dry-run：`cargo publish --locked --dry-run --allow-dirty`
- full/minimal：`oxidns build-info`、`oxidns --version`，以及对应的 `oxidns check -c config.yaml` / `oxidns check -c config.minimal.yaml`
