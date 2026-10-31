# OxiDNS v1.6.3

## 🚀 发布概览

- v1.6.3 是面向网络稳定性的 Patch Release，重点修复 DoH HTTP/2 keepalive 与并发 DNS 查询的生命周期竞争。
- 同时完善 IPv6 上游解析与 TLS identity、连接关闭资源回收及连接池诊断。
- 没有新增配置字段或改变默认值；DoH2 超长时长配置需按下方限制调整。

## ✨ 主要亮点

### DoH2 Keepalive 与并发查询

- PING 失败或超时后回收失效空闲连接并通知连接池，不再仅停用 keepalive 后继续复用。
- 统一查询准入与回收的原子状态，避免误杀与 PING 重叠的查询；没有成功响应时等待在途查询结束后回收。
- 任一通过校验的成功 DNS 响应会立即取消回收并解除准入门控，无需等待其他慢查询。
- 活动计数、成功响应 generation 和空闲时间采用 32 位原子；补充 tick 回绕与并发回收回归测试，正常查询路径不引入全局锁。

### IPv6、资源回收与诊断

- 正确识别 URL 中带方括号的 IPv6 地址，避免误走 bootstrap 域名解析；TLS identity 去除 IPv6 方括号，保留原始主机和 HTTP authority 格式。
- 合入上游连接关闭资源释放修复，补充 UDP listener、TCP 收发任务、写入失败与阻塞写取消回归测试。
- 连接池和关闭日志增加 upstream tag、主机、端口与传输信息；正常并发转发中的查询取消改为 debug 日志。
- 更新 Rust 依赖；support crate 代码与版本保持不变。

## ⚠️ 升级说明

- v1.6.2 常规 YAML 配置、缓存文件和 query recorder 数据库无需迁移。
- **DoH2 时长限制**：未启用 HTTP/3 的 DoH 上游，其有效 `idle_timeout` 与启用的 `keepalive_interval` 必须小于 `2^32` 毫秒（约 49.7 天）。达到或超过该值的配置现在会被拒绝，需缩短后升级；其他传输及启用 HTTP/3 的 DoH 不受此新增限制影响。
- `keepalive_interval` 仍默认关闭；启用时建议升级后观察 keepalive、连接回收与 upstream timeout 日志。
- 建议升级前运行：
  ```bash
  oxidns check -c <配置文件>
  ```
- 根 crate 版本为 `1.6.3`，`oxidns-proto` 为 `0.1.6`，`oxidns-ripset` 为 `0.1.3`；tag 使用 `v1.6.3`。

## 📦 下载与校验

- 根据平台和 bundle 选择对应 archive，并使用 GitHub Release asset 的 SHA256 digest 校验下载文件。

## ✅ 验证

- `just check`
- 文档（中英文）：`cd docs && npm run build`
- Telegram 发布消息：`python3 -m unittest discover -s .github/scripts -p '*_test.py'`
