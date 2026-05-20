# NetBird 区域边缘部署：Router 与 Relay 同机方案

本文说明如何在**不改动**仓库内现有 `docker-compose.yml`、`peer.env` 等文件的前提下，将 **Routing Peer** 与 **区域 Relay** 部署在同一台边缘 VM 上，降低跨境延迟，避免所有 Relay 流量绕道新加坡主站 `netbird-server` 的内嵌 Relay。

相关文档：

- **[优化方案.md](./优化方案.md)** — **生产环境分阶段实施路线图（推荐阅读）**
- [MULTI-REGION-RELAY-OPTIMIZATION.md](./MULTI-REGION-RELAY-OPTIMIZATION.md) — 多区域 Relay、主站 `config.yaml`、OCI/AWS 防火墙与 Docker P2P
- [HA-DEPLOYMENT.md](./HA-DEPLOYMENT.md) — Relay 水平扩展摘要

---

## 1. 目标与原则

### 1.1 要解决的问题

当前常见路径（国内 Mac 访问日本资源）：

```text
Mac
  → rels://netbird.flaship.org:443（新加坡主站内嵌 Relay）
  → 海外 Router（可能再次 Relayed）
  → 目标内网
```

延迟来自：**Relay 控制面在新加坡**，与 Router 物理位置（JP/HK/OCI）无关。

### 1.2 设计原则

| 原则 | 说明 |
|------|------|
| 控制面集中 | Management、Signal、Dashboard 继续在新加坡主站（getting-started + Traefik 或自建 compose） |
| 数据面分散 | 在 **HK / TW / JP** 各部署 **Relay +（可选）Router** |
| 同机共置 | 同一区域 VM 上跑 Relay 与 Router，共享地域与公网 IP 策略 |
| 不改仓库 compose | 边缘栈在**边缘 VM 独立目录**自建 `docker-compose.edge.yml`，不修改 `deploy/docker-compose.yml` |

### 1.3 不推荐的做法

- 把 `netbirdio/relay` 塞进新加坡主站与 `netbird-server` **同一个** compose，指望日本用户变快 — **无效**。
- 在 `deploy/docker-compose.yml` 里仅启用注释掉的 `netbird-router`（`NB_MANAGEMENT_URL=http://netbird-server`）— 仅适合**本地联调**，不能替代区域边缘。
- Router 使用默认 **bridge** Docker 网络跑在**有公网 IP 的 AWS EC2** 上 — 会导致 P2P 失败、长期 Relayed（见 MULTI-REGION 文档 8.10 节）。

---

## 2. 推荐拓扑

```text
┌─────────────────────────────────────────────────────────────┐
│ 新加坡 · 主站（~/netbird 或生产 Traefik 栈）                    │
│  netbird.flaship.org :443                                    │
│  netbird-server：Management + Signal + Dashboard             │
│  config.yaml：server.relays + server.stuns（关闭内嵌 Relay）    │
└───────────────────────────────┬─────────────────────────────┘
                                │ 下发网络图 / Relay 列表
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│ 日本边缘 VM    │       │ 香港边缘 VM    │       │ 台湾边缘 VM    │
│ relay-jp.*    │       │ relay-hk.*    │       │ relay-tw.*    │
│ :443 / :3478  │       │ 同上           │       │ 同上           │
│ netbird-router│       │ netbird-router│       │ netbird-router│
│ host 网络     │       │ host 网络      │       │ host 网络      │
└───────────────┘       └───────────────┘       └───────────────┘
```

优化后的 Relay 路径（示例：国内 Mac 访问日本）：

```text
Mac ──Relay──► relay-jp.flaship.org:443 ──► oci-jp / aws-8237-jp 内网
```

---

## 3. 主站配置（新加坡）

在主站 `config.yaml`（getting-started 生成的 `~/netbird/config.yaml` 或自建部署中的挂载文件）增加 **外部 Relay**，并关闭内嵌 Relay/STUN。

### 3.1 配置示例

```yaml
server:
  listenAddress: ":80"
  exposedAddress: "https://netbird.flaship.org:443"

  stuns:
    - uri: "stun:relay-hk.flaship.org:3478"
      proto: "udp"
    - uri: "stun:relay-tw.flaship.org:3478"
      proto: "udp"
    - uri: "stun:relay-jp.flaship.org:3478"
      proto: "udp"

  relays:
    addresses:
      - "rels://relay-hk.flaship.org:443"
      - "rels://relay-tw.flaship.org:443"
      - "rels://relay-jp.flaship.org:443"
    secret: "<与 server.authSecret 完全相同>"
    credentialsTTL: "24h"

  authSecret: "<原有值，可与 relays.secret 一致>"

  # 配置 relays 后注释掉内嵌 STUN
  # stunPorts:
  #   - 3478

  # ... 其余 auth、store、reverseProxy 保持不变 ...
```

### 3.2 主站 Compose 调整（手工，不改仓库文件）

若主站 compose 中有 `netbird-server` 的端口映射：

```yaml
ports:
  - "3478:3478/udp"   # 删除此行
```

重启后检查日志：

```text
Relay: false
Relay addresses: [rels://relay-hk... rels://relay-tw... rels://relay-jp...]
```

**切勿**重新执行 `getting-started.sh` 覆盖已改好的 `config.yaml`。

---

## 4. 边缘 VM：Relay + Router 同机部署

在每台区域 VM（建议 1 vCPU / 1GB+，公网 IP，DNS A 记录）上**单独建目录**，例如 `/opt/netbird-edge`。

### 4.1 防火墙

| 方向 | 协议 | 端口 | 说明 |
|------|------|------|------|
| 入站 | TCP | 80 | Let's Encrypt（Relay） |
| 入站 | TCP | 443 | Relay `rels://` |
| 入站 | UDP | 3478 | STUN |
| 入站 | UDP | 51820 | Router WireGuard（公网 VM；与 `NB_WIREGUARD_PORT` 一致） |
| 出站 | 全部 | — | 访问 `https://netbird.flaship.org:443` |

### 4.2 文件清单（在边缘 VM 上自建）

在 `/opt/netbird-edge` 创建以下三个文件（**不**放入本仓库 `deploy/` 目录）。

#### `relay.edge.env`

```bash
NB_LOG_LEVEL=info
NB_LISTEN_ADDRESS=:443
NB_EXPOSED_ADDRESS=rels://relay-jp.flaship.org:443
NB_AUTH_SECRET=<主站 config.yaml 中的 authSecret，一字不差>

NB_LETSENCRYPT_DOMAINS=relay-jp.flaship.org
NB_LETSENCRYPT_EMAIL=admin@flaship.org
NB_LETSENCRYPT_DATA_DIR=/data/letsencrypt

NB_ENABLE_STUN=true
NB_STUN_PORTS=3478
NB_HEALTH_LISTEN_ADDRESS=:9000
```

香港 / 台湾：仅改 `NB_EXPOSED_ADDRESS`、`NB_LETSENCRYPT_DOMAINS` 为 `relay-hk.*` / `relay-tw.*`。

#### `peer.edge.env`

```bash
NB_SETUP_KEY=<Dashboard 中为 Routing Peer 创建的 Setup Key>
NB_HOSTNAME=edge-jp-router-01
NB_MANAGEMENT_URL=https://netbird.flaship.org:443
NB_LOG_LEVEL=info
NB_WIREGUARD_PORT=51820
```

- **必须**使用公网 Management URL（`:443`），不要用 docker 内网服务名。
- 与 Dashboard 安装弹窗中的简单 `docker run` 不同：公网 Router **必须**配合下文 `network_mode: host`。

#### `docker-compose.edge.yml`

```yaml
services:
  netbird-relay:
    image: netbirdio/relay:${NETBIRD_VERSION:-latest}
    container_name: netbird-relay-edge
    restart: unless-stopped
    network_mode: host
    env_file:
      - relay.edge.env
    volumes:
      - relay_edge_data:/data
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "2"

  netbird-router:
    image: netbirdio/netbird:${NETBIRD_VERSION:-latest}
    container_name: netbird-router-edge
    restart: unless-stopped
    network_mode: host
    env_file:
      - peer.edge.env
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - SYS_RESOURCE
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv4.conf.all.src_valid_mark: "1"
    volumes:
      - netbird_router_edge_data:/var/lib/netbird
    depends_on:
      - netbird-relay
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "2"

volumes:
  relay_edge_data:
  netbird_router_edge_data:
```

### 4.3 启动

```bash
cd /opt/netbird-edge
export NETBIRD_VERSION=0.67.1   # 与主站、客户端大版本一致

docker compose -f docker-compose.edge.yml up -d
docker compose -f docker-compose.edge.yml logs -f
```

验证 Relay：

```bash
curl -vk https://relay-jp.flaship.org/
# HTTP 404 正常，确认 TLS 有效
```

验证 Router：

```bash
docker exec netbird-router-edge netbird status -d
```

### 4.4 为何两者都用 `network_mode: host`

| 组件 | 原因 |
|------|------|
| **Relay** | 需在宿主机 **443 / 3478** 监听，与弹性 IP、DNS 一致 |
| **Router** | UDP **51820** 必须直达进程；bridge 模式下 SG 放行 51820 仍无法进容器，导致 Relayed |

二者同机**不**表示 Router 与 Relay 在容器间互转流量；而是让**该区域**的用户与中继节点地理上靠近。

---

## 5. 与现有部署的关系

### 5.1 仓库 `deploy/docker-compose.yml`

| 服务 | 角色 | 与边缘方案关系 |
|------|------|----------------|
| `netbird-server` | 控制面 +（默认）内嵌 Relay | 主站改 `config.yaml` 后关闭内嵌 Relay |
| `netbird-router`（注释） | 本地测试 Peer | 不用于生产跨境优化 |
| `nginx` / `dashboard` | 本地开发 UI | 与边缘无关 |

边缘栈**独立目录、独立 compose 文件名**，不修改仓库内任何 compose。

### 5.2 生产主站（getting-started + Traefik）

- Traefik 占用主站 **443**，区域 Relay 使用**另一台 VM** 的 **443**（不同域名，如 `relay-jp.flaship.org`）。
- 不要把区域 Relay 绑到 `netbird.flaship.org` 同一 443 端口。

### 5.3 已有 AWS `aws-8237-jp-router`（公网 + Docker）

迁移步骤：

1. 主站 `config.yaml` 注册 `relay-jp.flaship.org`。
2. 在 **54.95.171.5** 上停止旧 `docker run` 容器（避免重复 Peer / 端口冲突）。
3. 使用本节 `docker-compose.edge.yml` 或等价 `docker run --network host` 命令。
4. 安全组：UDP **51820** ← `0.0.0.0/0`（见 MULTI-REGION 8.10 节）。
5. Mac `netbird down/up`，确认 Relays 含 `relay-jp` 且到 JP 为 P2P 或本地 Relay。

### 5.4 已有 OCI `oci-jp-router`（私网 + NAT Gateway）

- Router 可继续仅私网；**Relay 必须**在**有公网 IP 的 VM** 上（可与 Router 同机仅当该机有 EIP，或 Relay 单独一台）。
- 私网 Router 长期 Relayed 可接受；关键是 Mac 使用 **relay-jp** 而非新加坡 Relay（见 MULTI-REGION 第 8 节）。

---

## 6. 不用 Compose 的等价 `docker run`（单命令参考）

若不用 compose，在日本 VM 上可分别执行（先 Relay 后 Router）：

**Relay：**

```bash
docker run -d --name netbird-relay-edge --restart unless-stopped \
  --network host \
  --env-file relay.edge.env \
  -v relay_edge_data:/data \
  netbirdio/netbird:0.67.1
```

**Router：**

```bash
docker run -d --name netbird-router-edge --restart unless-stopped \
  --network host \
  --privileged \
  --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=SYS_RESOURCE \
  --device /dev/net/tun \
  --env-file peer.edge.env \
  -v netbird_router_edge_data:/var/lib/netbird \
  netbirdio/netbird:0.67.1
```

---

## 7. Dashboard 安装命令说明

Dashboard「Install NetBird → Docker」中的命令模板在源码  
`dashboard/src/modules/setup-netbird-modal/DockerTab.tsx`  
中为简化版（仅 `NET_ADMIN`、bridge 网络），**不适合**公网 Routing Peer。

生产 Router 请以本文 **host 网络 + `NB_WIREGUARD_PORT`** 为准；Management URL 来自 `dashboard.env` 的 `NETBIRD_MGMT_GRPC_API_ENDPOINT`（构建时注入）。

---

## 8. 客户端验证

在 Mac 或其它客户端：

```bash
netbird down && netbird up
netbird status -d
```

**期望：**

```text
Relays:
  [stun:relay-jp.flaship.org:3478] is Available
  [stun:relay-hk.flaship.org:3478] is Available
  ...
  [rels://relay-jp.flaship.org:443] is Available
```

对日本 Router：尽量 **P2P** 或 Relay 地址为 **`relay-jp.*`**，而非仅 `netbird.flaship.org`。

**Exit Node 注意：** 在 Peer 仍为 Relayed 时，不要挂 **`0.0.0.0/0`** 到该 Router，否则全网流量双重绕路。

---

## 9. 区域规划表

| 区域 | Relay 域名 | 边缘目录示例 | Router 示例 hostname |
|------|------------|--------------|----------------------|
| 日本 | `relay-jp.flaship.org` | `/opt/netbird-edge-jp` | `edge-jp-router-01` |
| 香港 | `relay-hk.flaship.org` | `/opt/netbird-edge-hk` | `edge-hk-router-01` |
| 台湾 | `relay-tw.flaship.org` | `/opt/netbird-edge-tw` | `edge-tw-router-01` |
| 新加坡（可选） | `relay-sg.flaship.org` | 独立 VM，勿与主站抢 443 | — |

三台边缘 VM 的 `NB_AUTH_SECRET` **必须相同**，且与主站 `relays.secret` 一致。

---

## 10. 部署检查清单

### 主站（新加坡）

- [ ] `config.yaml` 已配置 `relays` + `stuns`
- [ ] 已注释 `stunPorts`，compose 已去掉 `3478:3478/udp`（若有）
- [ ] 日志 `Relay: false`，列出各区域 `rels://` 地址

### 每台边缘 VM

- [ ] DNS A 记录指向本机公网 IP
- [ ] 防火墙 TCP 80/443、UDP 3478、UDP 51820（有 Router 时）
- [ ] `relay.edge.env` / `peer.edge.env` 已填写，`NB_AUTH_SECRET` 与主站一致
- [ ] `docker compose -f docker-compose.edge.yml up -d` 成功
- [ ] `curl -vk https://relay-xx.flaship.org/` TLS 正常

### 客户端

- [ ] `netbird status -d` 显示多区域 STUN/Relay Available
- [ ] 访问区域资源时 Relay 地址为 `relay-xx.*` 或 P2P
- [ ] 未对 Relayed Peer 长期开启 `0.0.0.0/0` Exit Node

---

## 11. 参考链接

- [Set Up External Relay Servers](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-relays)
- [Docker Installation](https://docs.netbird.io/how-to/installation/docker)
- [How Routing Peers Work](https://docs.netbird.io/manage/networks/how-routing-peers-work)
- [Understanding NAT and Connectivity](https://docs.netbird.io/about-netbird/understanding-nat-and-connectivity)

---

## 12. 附录：当前生产主站（`netbird.flaship.org` / Traefik）

以下对应主机 **`ip-10-20-9-49`**（`~/netbird`）上 getting-started **选项 0** 部署：Traefik + `netbird-server:dev` + `netbird-dashboard:dev`，LDAP 在 `10.20.9.49:389`。

### 12.1 当前状态（改造前）

| 项 | 当前值 | 说明 |
|----|--------|------|
| 域名 | `netbird.flaship.org` | Traefik 终结 TLS（80/443） |
| `exposedAddress` | `https://netbird.flaship.org:443` | 正确 |
| Relay/STUN | **内嵌**（`stunPorts: 3478` + Traefik `/relay`） | 客户端走新加坡 |
| `docker-compose` | `3478:3478/udp` 映射到 `netbird-server` | 外置 Relay 后可删 |
| `authSecret` | `config.yaml` 中 `server.authSecret` | **边缘 Relay 必须用同一值** |
| 存储 | SQLite | 改造 Relay 不影响 |
| 镜像 | `netbird-server:dev` / `netbird-dashboard:dev` | 与构建版本一致即可 |

**不要**在生产机上重新执行 `getting-started.sh`，否则会覆盖 `config.yaml`、`docker-compose.yml`、`dashboard.env`。

### 12.2 主站 `config.yaml` 改造示例

在现有 `server:` 块中**保留** `auth`、`store`、`reverseProxy`（`trustedHTTPProxies: 172.30.0.10/32` 已正确），**增加** `stuns` / `relays`，**注释** `stunPorts`：

```yaml
server:
  listenAddress: ":80"
  exposedAddress: "https://netbird.flaship.org:443"

  stuns:
    - uri: "stun:relay-jp.flaship.org:3478"
      proto: "udp"
    - uri: "stun:relay-hk.flaship.org:3478"
      proto: "udp"
    - uri: "stun:relay-tw.flaship.org:3478"
      proto: "udp"

  relays:
    addresses:
      - "rels://relay-jp.flaship.org:443"
      - "rels://relay-hk.flaship.org:443"
      - "rels://relay-tw.flaship.org:443"
    secret: "<与现有 server.authSecret 完全相同，勿重新生成>"
    credentialsTTL: "24h"

  authSecret: "<保持现有值不变>"

  # stunPorts:
  #   - 3478

  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"
  dataDir: "/var/lib/netbird"

  auth:
    issuer: "https://netbird.flaship.org/oauth2"
    # ... 现有 LDAP owner/connectors 等全部保留 ...

  reverseProxy:
    trustedHTTPProxies:
      - "172.30.0.10/32"
    trustedPeers:
      - "172.30.0.0/16"

  store:
    engine: "sqlite"
    encryptionKey: "<保持现有值>"
```

改前建议备份：

```bash
cd ~/netbird
cp config.yaml config.yaml.bak.$(date +%Y%m%d)
```

### 12.3 主站 `docker-compose.yml` 改造

在 **`netbird-server`** 服务中删除 STUN 端口（外置 Relay 负责 STUN）：

```yaml
  netbird-server:
    # ...
    networks: [netbird]
    # 删除以下整块 ports（若仅有 3478）：
    # ports:
    #   - '3478:3478/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
```

**Traefik / dashboard 无需修改**（`netbird-backend` 的 `/relay` 路由可保留，内嵌 Relay 关闭后基本闲置）。

**本机 `10.20.9.49` 不要**再部署区域 Relay：Traefik 已占用 **443**，且主站职责是控制面。

### 12.4 主站重启与验证

```bash
cd ~/netbird
docker compose down
docker compose up -d

docker compose logs netbird-server 2>&1 | tail -30
# 期望：Relay: false
# Relay addresses: [rels://relay-jp... rels://relay-hk... rels://relay-tw...]

curl -sk https://netbird.flaship.org/oauth2/.well-known/openid-configuration | head
```

`dashboard.env` 可保持：

```bash
NETBIRD_MGMT_API_ENDPOINT=https://netbird.flaship.org
NETBIRD_MGMT_GRPC_API_ENDPOINT=https://netbird.flaship.org
```

（与现网一致；客户端也可用 `:443`。）

### 12.5 边缘节点与主站分工

```text
┌─────────────────────────────────────────────────────────────┐
│ 10.20.9.49（新加坡 VPC）· 仅控制面                            │
│  netbird.flaship.org → Traefik:443 → dashboard / netbird-server │
│  不再承担数据面 Relay（config 改完后 Relay: false）            │
└─────────────────────────────────────────────────────────────┘
         │
         │ Management / Signal 仍为 https://netbird.flaship.org
         ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ 日本边缘 VM       │  │ 香港边缘 VM       │  │ 台湾边缘 VM       │
│ relay-jp.* :443  │  │ relay-hk.*       │  │ relay-tw.*       │
│ + Router (host)  │  │ + Router         │  │ + Router         │
│ NB_AUTH_SECRET = │  │ 同上 authSecret  │  │ 同上             │
│ 主站 authSecret  │  │                  │  │                  │
└──────────────────┘  └──────────────────┘  └──────────────────┘
```

边缘栈按本文 **第 4 节** 在 `/opt/netbird-edge` 自建 `docker-compose.edge.yml`（不放入 `~/netbird` 目录）。

| 边缘 `relay.edge.env` | 值 |
|------------------------|-----|
| `NB_AUTH_SECRET` | 与主站 `config.yaml` 的 `authSecret` **一字不差** |
| `NB_EXPOSED_ADDRESS` | 如 `rels://relay-jp.flaship.org:443` |

| 边缘 `peer.edge.env` | 值 |
|----------------------|-----|
| `NB_MANAGEMENT_URL` | `https://netbird.flaship.org:443` |
| `NB_SETUP_KEY` | Dashboard 创建的 Routing Peer Key |
| `network_mode` | **host**（见 4.4 节） |

已有 **AWS `aws-8237-jp-router`**（`54.95.171.5`）时：可在该机用边缘 compose **替代**原 `docker run`（bridge），并保留 SG **UDP 51820**。

### 12.6 主站安全组 / 防火墙（`10.20.9.49`）

改造后主站仅需：

| 端口 | 说明 |
|------|------|
| TCP 80 / 443 | Traefik（Dashboard、API、gRPC、OAuth2） |
| ~~UDP 3478~~ | 可关闭（STUN 移到各区域 Relay） |

区域 Relay VM 仍需：TCP 80/443、UDP 3478；Router 公网 VM 另需 UDP 51820。

### 12.7 与现有 Peer 的对应关系

| Dashboard Peer | 建议 |
|----------------|------|
| `tw-office-router-01` | 已 P2P，可不变；或迁到 `relay-tw` 区域 |
| `aws-8237-jp-router-01` | 日本边缘 Relay + **host** Docker；取消 Mac 对其 `0.0.0.0/0` Exit（若仍 Relayed） |
| `oci-jp-router-01` | 私网 NAT，依赖 **relay-jp**；见 MULTI-REGION 第 8 节 |
| `aws-8237-hk-router-01` | 配合 **relay-hk** + 公网 SG UDP 51820 |
| Mac 客户端 | `netbird down/up` 后应看到多个 `relay-*.flaship.org` |

### 12.8 改造顺序（推荐）

1. 日本/香港/台湾各部署 **Relay**（DNS → 公网 IP，`NB_AUTH_SECRET` = 主站现有值）。  
2. 主站改 `config.yaml` + 去掉 `3478` 映射 → `docker compose up -d` → 确认 `Relay: false`。  
3. 各区域部署 **Router**（host 网络 compose 或修正后的 `docker run`）。  
4. Mac 重连，检查 `netbird status -d`。  
5. 收紧 Exit Node / DNS（见 MULTI-REGION 第 7 节）。

### 12.9 回滚

```bash
cd ~/netbird
cp config.yaml.bak.YYYYMMDD config.yaml
# 恢复 docker-compose 中 3478:3478/udp
docker compose down && docker compose up -d
```

---

将文中 `flaship.org`、版本号与 hostname 替换为你的实际环境即可用于生产。**切勿**将真实 `authSecret`、LDAP 密码、`encryptionKey` 写入版本库或对外文档。
