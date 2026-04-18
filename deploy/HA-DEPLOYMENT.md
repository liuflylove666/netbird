# NetBird 自托管高可用（HA）部署指南

本文说明在**开源/自托管**场景下，如何把 NetBird 部署得更可靠，以及与**官方能力边界**的关系。实现前请结合 [NetBird 自托管文档](https://docs.netbird.io/selfhosted/selfhosted-guide) 与 [扩容与拆分](https://docs.netbird.io/selfhosted/maintenance/scaling/scaling-your-self-hosted-deployment) 阅读。

---

## 1. 架构里哪些组件最关键

| 组件 | 作用 | 典型可用性策略（开源） |
|------|------|------------------------|
| **Management** | 账户、策略、Peer 状态、下发网络图 | 单实例 + 健康检查 + **数据库与配置备份**；外置 PostgreSQL 便于备份与运维 |
| **Signal** | Peer 之间交换连接信息（gRPC/WebSocket） | **官方标准部署为单实例**（进程内维护连接状态），不可按 Relay 方式做 active-active 多副本 |
| **Relay + STUN** | NAT 穿透失败时的中继、STUN 候选 | **可多机部署、多地址**，对整体韧性贡献最大 |
| **TURN（如 Coturn）** | 媒体/隧道中继（与 Relay 角色不同但同属“中继面”） | 多实例、多 IP/多区域；与 `management.json` / `config.yaml` 中声明的 URI 一致 |
| **Dashboard / 反代** | Web UI、TLS 终结、路由到 API | 无状态多副本 + 上层负载均衡（需正确处理 gRPC/HTTP2） |
| **IdP（OIDC）** | 登录与令牌 | 使用 IdP 自身的高可用（多副本、地理冗余） |

官方说明摘要：

- 已建立的 Peer 连接在 **Management 短时间不可用**时，仍可能通过已有 **P2P 或 Relay** 维持通信；因此 **稳定、可扩展的 Relay 基础设施**对体验很重要。  
- **Management + Signal 的 active-active 高可用**属于 **企业商业授权**能力，见 [定价 / On‑Prem](https://netbird.io/pricing#on-prem)。  
- **Signal 不可像 Relay 一样水平复制**：见 [Set Up External Signal Server](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-signal) 中 *“cannot be replicated as it maintains in-memory connection state”*。  
- **Relay 可多实例**：见 [Set Up External Relay Servers](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-relays) 与 [Multiple Proxy Instances](https://docs.netbird.io/selfhosted/maintenance/scaling/multiple-proxy-instances)。

---

## 2. 推荐的分层高可用策略（开源可落地）

### 2.1 控制面：Management（单活 + 韧性）

1. **进程与编排**  
   - 使用 `restart: always` / Kubernetes `livenessProbe` + `readinessProbe`（仓库内 `deploy/docker-compose.prod.yml` 对 `netbird-server`、nginx 等带有健康检查示例，可作参考）。  
   - 单机故障时依赖编排器在**另一节点**拉起新容器；RTO 取决于镜像拉取与启动时间。

2. **数据层**  
   - 默认 SQLite 适合小规模；生产建议迁移到 **PostgreSQL**（或官方支持的 MySQL），便于 **PITR、从库只读、云厂商托管 RDS** 等运维手段。  
   - 迁移步骤：[Migrate from SQLite to PostgreSQL](https://docs.netbird.io/selfhosted/maintenance/scaling/migrate-sqlite-to-postgresql)。

3. **配置与密钥**  
   - `management.json` / `config.yaml`、TLS 证书、TURN 密钥、`DataStoreEncryptionKey` 等纳入 **Git 加密仓或密钥管理（Vault 等）+ 定期备份**。  
   - 变更 `Signal` 对外 URL 时，官方文档注明客户端需 **`netbird down` / `netbird up`** 重连（见 External Signal 文档），变更窗口要纳入变更管理。

4. **“第二套冷备”**（非 active-active）  
   - 在**另一区域**维护同版本镜像、同配置模板与**数据库恢复演练**；主站点灾难时切换 DNS / 负载均衡指向备机，并接受 RPO 为备份间隔。  
   - 这不是双写热备，而是**灾备切换**，与商业版 active-active 不同。

### 2.2 信令面：Signal（单实例 + 隔离）

- 默认与 Management 同机（combined 容器）即可；若要与控制面**故障域隔离**，可将 Signal 拆到独立主机：  
  [Set Up External Signal Server](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-signal)  
- 仍为**单实例**；高可用形态为：**快速自动重启**、**监控告警**、**备用机 + 人工/半自动切换**（切换时关注客户端重连）。

### 2.3 数据面：Relay / STUN / TURN（优先做多副本）

这是开源场景下**性价比最高**的 HA 投入：

1. 按官方文档部署 **多台 Relay**（每台可带 **STUN**），在 `config.yaml` 的 `relays.addresses`（或经典 `management.json` 的 `Relay.Addresses`）中填入多个 `rels://` / `rel://` 地址。  
2. 为不同区域准备不同 Relay 主机，降低单区域断网对全网的影响。  
3. **所有 Relay 使用相同的 `authSecret` / `NB_AUTH_SECRET`**，与主服务器配置一致。  
4. **防火墙**：TCP 443（Relay）、UDP 3478（STUN）及文档要求的 TURN UDP 端口段按云厂商放行（如 Hetzner / OCI 特例见 [自托管指南 - 云厂商说明](https://docs.netbird.io/selfhosted/selfhosted-guide#advanced-additional-configurations-for-cloud-providers)）。

### 2.4 入口层：反向代理与 Dashboard

- 使用 **Traefik / Nginx / Caddy** 等支持 **HTTP/2 与 gRPC** 的反代（官方有模板）：  
  [External Reverse Proxy Configuration](https://docs.netbird.io/selfhosted/external-reverse-proxy)  
- Dashboard 静态资源可 **多副本 + 任意七层负载均衡**；注意 **WebSocket、gRPC 路径**与超时时间，避免长连接被中间设备过早断开。  
- TLS 证书：Let’s Encrypt 自动续期或企业 PKI；到期监控与告警。

### 2.5 身份提供方（IdP）

- NetBird 依赖 OIDC；IdP 应使用其厂商推荐的 **多副本、数据库高可用、跨 AZ**。  
- 监控 IdP 与 Management 之间的 **JWKS 拉取、clock skew、证书轮换**。

---

## 3. 备份、恢复与演练

官方备份要点（配置 + Management 数据目录）见：  
[Self-hosted guide - Backup](https://docs.netbird.io/selfhosted/selfhosted-guide#backup-net-bird)

建议：

1. **备份**：`docker-compose.yml`、`management.json` / `config.yaml`、`turnserver.conf`、以及 **Management 存储**（SQLite 文件或 Postgres 逻辑备份）。  
2. **停服一致性**：备份 SQLite 或做数据库快照时，按文档短暂 **stop management** 再拷贝，避免半写状态。  
3. **每季度演练**：在隔离环境 **restore + 启动旧版本或目标版本**，验证升级路径与 RTO。

---

## 4. 监控与告警

- Management / Signal / Relay 均暴露 **Prometheus metrics**（端口以各镜像文档为准，如 Signal 默认 `:9090/metrics`）。  
- 建议采集：进程存活、HTTP/gRPC 错误率、Relay 连接数、Management API 延迟、证书到期时间、磁盘与内存。  
- 对 **PostgreSQL**、**Redis（若你自建有旁路缓存）**、**Coturn** 同步监控。

---

## 5. 网络与 DNS

- 对外域名（Management、Signal、Relay）建议 **短 TTL**（如 300s），便于灾备切换。  
- 拆分 Relay 到多机时，确保 **客户端解析到的每个主机名** 均可达且证书与 `rels://` 主机名一致。

---

## 6. 能力边界小结（避免错误预期）

| 需求 | 开源自托管典型做法 |
|------|-------------------|
| Relay / STUN 水平扩展 | **支持**，官方文档为主依据 |
| Management 数据库高可用 / 读写分离 | **PostgreSQL 等由你选型**；Management 进程仍多为单活 |
| Signal active-active 多活 | **标准产品不支持**；企业版咨询官方 |
| 控制面“双机热备不停机写” | **非开源默认能力**；用冷备 + DNS/编排切换 |

---

## 7. 参考链接（官方）

- [How NetBird works](https://docs.netbird.io/about-netbird/how-netbird-works)  
- [Scaling your self-hosted deployment](https://docs.netbird.io/selfhosted/maintenance/scaling/scaling-your-self-hosted-deployment)  
- [External Relay Servers](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-relays)  
- [External Signal Server](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-signal)  
- [Migrate SQLite to PostgreSQL](https://docs.netbird.io/selfhosted/maintenance/scaling/migrate-sqlite-to-postgresql)  
- [External Reverse Proxy](https://docs.netbird.io/selfhosted/external-reverse-proxy)  
- [GitHub: HA configuration mode discussion](https://github.com/netbirdio/netbird/issues/5724)  

---

## 8. 与本仓库 `deploy/` 的关系

- `deploy/docker-compose.yml`：本地/开发向组合。  
- `deploy/docker-compose.prod.yml`：生产向示例（健康检查、资源限制等），可作为 **单区域单栈** 基线，再按上文拆分 Relay、外置数据库与反代。  

高可用不是单一 Compose 文件能“一键开启”的，而是 **Relay 多节点 + 数据备份 + 入口与 IdP 韧性 + 运维演练** 的组合；需要 **Management/Signal 双活** 时请通过官方渠道了解企业 On‑Prem 方案。
