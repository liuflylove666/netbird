# NetBird 跨境访问优化与多区域 Relay 部署指南

本文面向使用官方一键脚本部署、主站位于新加坡、Traefik 自动 TLS 的自托管环境（例如 `netbird.flaship.org`）。涵盖问题诊断、多区域 Relay 部署、主站配置变更、客户端验证、**OCI 私网 Router（NAT Gateway）** 与日常运维。

相关文档：

- [官方 External Relay](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-relays)
- 仓库内 [HA-DEPLOYMENT.md](./HA-DEPLOYMENT.md)（Relay 水平扩展摘要）

---

## 1. 现状与问题诊断

### 1.1 典型 `netbird status -d` 现象

| 现象 | 含义 |
|------|------|
| 部分 Peer 为 **P2P**（`srflx/srflx`，延迟约 100ms+） | NAT 穿透正常，路径最优 |
| 部分 Peer 为 **Relayed**（ICE `-/-`） | 流量经 Relay 中转，无法直连 |
| Relay 地址为 `rels://netbird.flaship.org:443` | 所有中继走新加坡主站 |
| **Default route** → 某 Exit Node（`0.0.0.0/0`） | 本机大量公网流量经出口节点，且可能仍为 Relayed |
| DNS **All upstream servers failed**（1.1.1.1 / 8.8.8.8） | 国内环境常见，影响解析与体感卡顿 |
| **Interface: Userspace**（macOS） | 略慢于内核模式，通常不是主因 |

### 1.2 根因归纳

国内客户端访问海外慢，通常不是单一原因，而是路径叠加：

```text
Mac（国内）
  → 新加坡主站 Relay（rels://netbird.flaship.org:443）   # 跨境 1
  → 海外 Router / Exit Node（可能再次 Relayed）          # 跨境 2
  → 目标内网或公网
```

若同时开启 **全流量默认路由（0.0.0.0/0）** 到远端 Exit Node，会进一步放大延迟与抖动。

### 1.3 优化目标

1. **数据面**：在 HK / TW / JP 部署独立 Relay，缩短必须中继时的路径。
2. **控制面**：主站继续在新加坡，仅承担 Management + Signal + Dashboard（现有 Traefik 栈）。
3. **业务面**：收紧 Exit Node 与路由前缀；推动 Router P2P；修正 DNS 上游。

---

## 2. 架构说明

### 2.1 推荐拓扑

```text
┌─────────────────────────────────────────────────────────────┐
│ 新加坡 · 主站（getting-started.sh + Traefik）                  │
│  netbird.flaship.org :443 → Traefik → dashboard / netbird-server │
│  职责：Management + Signal + Dashboard + OAuth2              │
│  关闭：embedded Relay + embedded STUN（配置外部 Relay 后自动关闭）│
└─────────────────────────────────────────────────────────────┘
                              │
              下发多个 Relay / STUN 地址到所有客户端
                              │
     ┌────────────────────────┼────────────────────────┐
     ▼                        ▼                        ▼
┌─────────────┐        ┌─────────────┐        ┌─────────────┐
│ 香港 VM      │        │ 台湾 VM      │        │ 日本 VM      │
│ relay-hk.*  │        │ relay-tw.*  │        │ relay-jp.*  │
│ TCP 443     │        │ 同上         │        │ 同上         │
│ UDP 3478    │        │              │        │              │
│ netbirdio/  │        │              │        │              │
│ relay 独立  │        │              │        │              │
│ TLS+STUN    │        │              │        │              │
└─────────────┘        └─────────────┘        └─────────────┘
```

### 2.2 为何区域 Relay 不挂在主站 Traefik 上

| 项目 | 说明 |
|------|------|
| 主站 443 | 已被 Traefik 占用（Dashboard、gRPC、API、OAuth2） |
| 内嵌 Relay | 走 `https://域名/relay`（WebSocket 反代） |
| 外部 Relay | 客户端使用 `rels://域名:443` **直连** Relay 进程，不经过 Traefik |
| 国内用户 | 应优先选 HK/TW Relay，而非绕新加坡主站 |

### 2.3 配置规则（combined server）

1. 配置 `server.relays.addresses` 后，**内嵌 Relay 与内嵌 STUN 自动关闭**。
2. 必须同时配置 `server.stuns`，列出**每一台** Relay 机器上的 STUN。
3. 所有 Relay 的 `NB_AUTH_SECRET` 与主站 `relays.secret`（及 `authSecret`）**必须完全一致**。
4. 客户端会探测所有 STUN；在可用 Relay 列表中选择（支持 failover）。

---

## 3. 部署前准备

### 3.1 主站（新加坡）收集信息

```bash
cd ~/netbird   # 安装目录：含 docker-compose.yml、config.yaml、traefik 等

# 共享密钥（勿重新生成）
grep authSecret config.yaml

# 与 Relay 镜像对齐的版本
docker compose images | grep netbird-server
```

| 记录项 | 用途 |
|--------|------|
| `authSecret` | 所有区域 Relay 的 `NB_AUTH_SECRET` |
| `netbird-server` 镜像 tag | 区域机 `netbirdio/relay` 使用相同版本（如 `v0.67.1`） |

### 3.2 区域机器规划

| 区域 | 建议域名 | 规格 | 防火墙 |
|------|----------|------|--------|
| 香港 | `relay-hk.flaship.org` | 1 vCPU / 1GB+ | TCP 80、443；UDP 3478 |
| 台湾 | `relay-tw.flaship.org` | 同上 | 同上 |
| 日本 | `relay-jp.flaship.org` | 同上 | 同上 |

每台：公网 IP、DNS A 记录、Docker 已安装。

### 3.3 可选：新加坡第四台 Relay

若希望新加坡 Peer 也走本地中继：

- 使用**另一台** SG 小机 + `relay-sg.flaship.org`。
- **不要**与主站共用 443（Traefik 已占用）。

生产环境分阶段实施见 **[优化方案.md](./优化方案.md)**；技术细节见 [ROUTER-RELAY-EDGE-DEPLOYMENT.md](./ROUTER-RELAY-EDGE-DEPLOYMENT.md)。

---

## 4. 区域 Relay 部署（HK / TW / JP）

以下以**香港**为例；台湾、日本复制目录，仅改域名与容器名。

### 4.1 创建目录

```bash
sudo mkdir -p /opt/netbird-relay && cd /opt/netbird-relay
```

### 4.2 环境变量 `relay.env`

```bash
NB_LOG_LEVEL=info
NB_LISTEN_ADDRESS=:443
NB_EXPOSED_ADDRESS=rels://relay-hk.flaship.org:443
NB_AUTH_SECRET=<主站 config.yaml 中的 authSecret，一字不差>

# Let's Encrypt（与 Traefik 可使用相同邮箱）
NB_LETSENCRYPT_DOMAINS=relay-hk.flaship.org
NB_LETSENCRYPT_EMAIL=admin@flaship.org
NB_LETSENCRYPT_DATA_DIR=/data/letsencrypt

NB_ENABLE_STUN=true
NB_STUN_PORTS=3478
NB_HEALTH_LISTEN_ADDRESS=:9000
```

**自有证书**时，删除 `NB_LETSENCRYPT_*`，改为：

```bash
NB_TLS_CERT_FILE=/certs/fullchain.pem
NB_TLS_KEY_FILE=/certs/privkey.pem
```

并在 compose 中挂载 `/certs:ro`。

### 4.3 `docker-compose.yml`

```yaml
services:
  relay:
    image: netbirdio/relay:v0.67.1   # 替换为主站实际版本
    container_name: netbird-relay-hk
    restart: unless-stopped
    network_mode: host
    env_file:
      - relay.env
    volumes:
      - relay_data:/data

volumes:
  relay_data:
```

> 建议使用 `network_mode: host`，避免 Docker NAT 影响 UDP STUN。若使用 bridge，须映射 `443:443` 与 `3478:3478/udp`。

### 4.4 启动与验证

```bash
docker compose up -d
docker compose logs -f

# 期望日志：
# Starting relay server on :443
# Starting STUN server on port 3478

curl -vk https://relay-hk.flaship.org/
# HTTP 404 为正常；确认 TLS 证书有效即可
```

### 4.5 台湾 / 日本

| 文件项 | 台湾 | 日本 |
|--------|------|------|
| `NB_EXPOSED_ADDRESS` | `rels://relay-tw.flaship.org:443` | `rels://relay-jp.flaship.org:443` |
| `NB_LETSENCRYPT_DOMAINS` | `relay-tw.flaship.org` | `relay-jp.flaship.org` |
| `container_name` | `netbird-relay-tw` | `netbird-relay-jp` |

三台 `NB_AUTH_SECRET` 必须相同。

---

## 5. 主站配置（新加坡 · Traefik + combined）

### 5.1 修改 `config.yaml`

在 `server:` 块中调整（**保留** `auth`、`store`、`reverseProxy` 等其余配置）。

**变更要点：**

- 增加 `stuns` 与 `relays`。
- 注释 `stunPorts`。
- `exposedAddress` 保持 `https://netbird.flaship.org:443`（Management/Signal 不变）。
- `relays.secret` 与 `authSecret` 相同。

**示例：**

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
    secret: "<与 authSecret 相同>"
    credentialsTTL: "24h"

  authSecret: "<原有值>"

  # stunPorts:
  #   - 3478

  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"
  dataDir: "/var/lib/netbird"

  reverseProxy:
    trustedHTTPProxies:
      - "172.30.0.10/32"   # getting-started 默认 Traefik IP，勿随意删除

  auth:
    issuer: "https://netbird.flaship.org/oauth2"
    # ... 其余 auth / store 配置保持不变 ...
```

### 5.2 修改 `docker-compose.yml`

在 `netbird-server` 服务中**删除** STUN 端口映射：

```yaml
  netbird-server:
    # ...
    ports:
      # 删除：
      # - '3478:3478/udp'
```

**Traefik 无需修改**（`netbird-backend` 的 `/relay` 路由可保留；内嵌 Relay 关闭后该路径基本闲置）。

**切勿**重新执行 `getting-started.sh`，否则会覆盖 `config.yaml` 与 `docker-compose.yml`。

### 5.3 重启主站

```bash
cd ~/netbird
docker compose down
docker compose up -d

docker compose logs netbird-server 2>&1 | tail -40
```

**期望日志：**

```text
Relay: false
Relay addresses: [rels://relay-hk.flaship.org:443 rels://relay-tw.flaship.org:443 rels://relay-jp.flaship.org:443]
```

若仍为 `Relay: true`，检查 `relays.addresses` 是否非空、`config.yaml` 挂载是否正确。

---

## 6. 客户端验证

### 6.1 重连并查看状态

```bash
netbird down
netbird up
netbird status -d
```

**期望 Relays 段：**

```text
Relays:
  [stun:relay-hk.flaship.org:3478] is Available
  [stun:relay-tw.flaship.org:3478] is Available
  [stun:relay-jp.flaship.org:3478] is Available
  [rels://relay-xx.flaship.org:443] is Available
```

对仍为 `Relayed` 的 Peer，确认 **Relay server address** 为区域域名，而非 `netbird.flaship.org`。

### 6.2 强制 Relay 端到端测试（测完关闭）

```bash
sudo netbird service reconfigure --service-env NB_FORCE_RELAY=true
# 对海外 Peer 内网 IP 执行 ping 等测试

sudo netbird service reconfigure --service-env NB_FORCE_RELAY=false
```

### 6.3 故障切换测试

停止某台区域 Relay（如 HK），再次 `netbird status -d`，应显示该 STUN/Relay Unavailable，客户端改用 TW/JP。

---

## 7. 业务与路由优化（与 Relay 同等重要）

多区域 Relay **不能**替代以下策略；否则仍可能感觉慢、卡。

### 7.1 Exit Node / 默认路由

| 建议 | 说明 |
|------|------|
| 避免长期 `0.0.0.0/0` | Dashboard 中勿让国内 Mac 长期走远端全流量出口 |
| 按网段分流 | 仅路由业务前缀（如 `10.20.0.0/16`、Jira/Confluence 相关网段） |
| 优选近端出口 | 若必须出口，优先 P2P 可达的 TW/HK Router，避免 Relayed 的新加坡节点 |

### 7.2 推动 P2P（减少 Relay 依赖）

在每台海外 Router 上：

- 安全组 / 防火墙放行出站 UDP（STUN、打洞）及 TCP 443（Management / Relay）。
- **有公网 IP** 的节点：P2P 成功率最高。
- **仅私网 + NAT Gateway**（如 OCI `oci-jp-router-01`）：见 [第 8 节](#8-oci-私网-routernat-gateway)。

P2P 成功后，内网访问走 Mac ↔ Router 直连，延迟通常优于任何 Relay。

### 7.3 DNS

- 勿将仅使用 `1.1.1.1` / `8.8.8.8` 作为全球唯一上游（国内 probe 易失败）。
- Dashboard DNS 中为国内用户配置可达上游，或使用区域 Router 提供的 DNS。
- 对 `*.flaship.org` 等可使用 Custom zones 指向内网解析。

### 7.4 客户端版本

保持 Agent 与主站版本接近；`netbird status` 中提示新版本时，在维护窗口升级（需兼顾各 Router 版本策略）。

---

## 8. OCI 私网 Router（NAT Gateway）

本节针对 **仅内网 IP、无公网 VNIC**，且子网默认路由 **`0.0.0.0/0 → NAT Gateway`** 的 Routing Peer（示例：`oci-jp-router-01`，`10.2.1.15`，Security List `office-jp-east-devops-private`，区域 Japan East）。

### 8.1 网络实际路径

```text
Mac / 其他 Peer（公网，可有 srflx）
        ↕ UDP 打洞 或 Relay（rels://relay-jp...）
OCI NAT Gateway（公网 IP，SNAT 出口）
        ↕ 仅有状态回程；NAT GW 不做入站 DNAT
10.2.1.15（netbird-router，私网，如 10.2.1.0/24）
```

| 能力 | 私网 + NAT Gateway |
|------|---------------------|
| 出站访问 Management / Signal / Relay | ✅ 可以 |
| STUN 获得 `srflx`（NAT 公网 IP:临时端口） | ✅ 通常可以 |
| 公网主动 DNAT 到 `10.2.1.15` | ❌ NAT GW 不支持 |
| 稳定 P2P | ⚠️ 取决于 NAT 类型与对端，不保证 |
| Relay 访问 advertised 内网 | ✅ 可以（常见为 **Relayed**） |

### 8.2 如何确认走 NAT Gateway

在 OCI 控制台：

```text
Networking → VCN → Subnets → 10.2.1.0/24 所在子网 → Route Table
```

查看 **`0.0.0.0/0`** 下一跳：

| 下一跳 | 含义 |
|--------|------|
| **NAT Gateway** | 私网出网 SNAT；VM 无公网入站（本环境） |
| Internet Gateway | 公网子网，可绑 Public IP |
| 无默认路由 | 可能无法访问 STUN/Relay |

CLI：

```bash
oci network route-table get --rt-id <route-table-ocid>
```

### 8.3 Security List 要点（OCI）

#### 出站（Egress）

示例环境已配置：

```text
Destination: 0.0.0.0/0，All Protocols，全部端口
```

对 NetBird **足够**，无需再为「P2P」单独开出站规则。

#### 入站（Ingress）常见误解

若存在规则 **Source = `10.2.1.15/32`**（All Protocols）：

- OCI Ingress 的 **Source = 报文来源 IP**，不是「保护本机 10.2.1.15」。
- 挂在 **Router 本机** 时：表示允许「来源 IP 为 10.2.1.15」的入站，**不能**替代「Mac/公网打洞进 Router」。
- 对 **外网 P2P 入站** 几乎无帮助；可忽略或删除以免误解。

#### 官方与 OCI 有状态规则

[NetBird Ports & Firewalls](https://docs.netbird.io/about-netbird/ports-and-firewalls)：**客户端不要求在边界防火墙上开放入站端口**；打洞依赖出站 + ICE/STUN。

OCI Security List 在 **Stateless = No** 时，对**由本机发起**的 UDP 会话通常允许回程，故**多数情况不必**添加 `0.0.0.0/0 → UDP 51820` 入站。若长期 **Relayed** 且希望验证 P2P，可加一条可选入站（见 8.5）。

### 8.4 策略选择

| 策略 | 适用 | 说明 |
|------|------|------|
| **A. Relay + 区域 Relay** | 默认推荐 | 私网 + NAT 下最常见；部署 `relay-jp.flaship.org`，避免走新加坡主站 Relay |
| **B. 出站 + 打洞** | 零改动优先 | Egress 已全开即可；Router 固定 `wireguard-port` |
| **C. 可选 UDP 入站** | B 仍 Relayed | Security List 增加 UDP 入站（与 Wg 端口一致） |
| **D. VNIC 公网 IP** | 要稳定 P2P | OCI 为 Router 绑定 Public IP，最有效 |

### 8.5 Router 主机配置

#### 固定 WireGuard 端口（同 NAT 后多 Peer 时建议）

```bash
sudo netbird down
sudo netbird up --wireguard-port 51821
netbird status -d
```

持久化（任选）：

```bash
# /etc/default/netbird 或 systemd drop-in
NB_WIREGUARD_PORT=51821
```

`wireguard-port` 为 `0` 时使用随机端口（见客户端文档）。

#### 有公网且已做 DNAT 时（本环境通常不适用）

仅当边界防火墙将 **公网 IP:端口** 映射到 `10.2.1.15` 时：

```bash
netbird up --external-ip-map <公网IP>/10.2.1.15 --wireguard-port 51820
```

纯 NAT Gateway、无 DNAT 时**不要**填写不存在的公网映射。

#### Linux 主机防火墙

```bash
# UFW
sudo ufw allow in on wt0
# 或
sudo ufw allow in on wt0 from 100.64.0.0/10

# firewalld
sudo firewall-cmd --permanent --zone=trusted --add-interface=wt0
sudo firewall-cmd --reload
```

### 8.6 可选：OCI Ingress 规则（验证 P2P）

在 **绑定到 Router VNIC** 的 Security List 新增（端口与 `--wireguard-port` 一致）：

| Stateless | Source | Protocol | Dest Port | 说明 |
|-----------|--------|----------|-----------|------|
| No | `0.0.0.0/0` | UDP | `51821` | 可选；更严可缩小 Source 范围 |

仍 **Relayed** 时属正常，继续用策略 A 或 D。

### 8.7 验证步骤

在 `10.2.1.15` 上：

```bash
# 出站可达控制面 / JP Relay
curl -vk --connect-timeout 5 https://netbird.flaship.org/
curl -vk --connect-timeout 5 https://relay-jp.flaship.org/

netbird status -d
```

**P2P 成功时** 对端可见类似：

```text
Connection type: P2P
ICE candidate (Local/Remote): srflx/srflx  或  host/srflx
ICE candidate endpoints: .../<NAT出口公网IP>:51821
```

**仍为 Relayed**（`ICE -/-` 或 `relay/...`）：

- 优先确认 **JP Relay** 已部署且客户端 `rels://relay-jp...` Available。
- 需要低延迟 P2P 时为 VNIC 添加 **Public IP**。

在 Mac 上查看与 `oci-jp-router-01` 的连接类型及 **Relay server address** 是否为 `relay-jp.*`。

### 8.8 与多区域 Relay 的配合

```text
Mac（国内）─Relay─► relay-jp.flaship.org ─► NAT GW ─► 10.2.1.15 ─► 10.2.x 内网
```

比「Mac → 新加坡 netbird.flaship.org Relay → 日本私网」路径更短。私网 Router **不必**强求 P2P，但应保证 **出站** 与 **日本 Relay** 可用。

### 8.9 速查表

| 问题 | 答案 |
|------|------|
| `0.0.0.0/0` 走 NAT GW 是否正常？ | ✅ 私网子网标准做法 |
| `10.2.1.15` 无公网能否用 NetBird？ | ✅ 可以 |
| 是否必须在 OCI 开入站 UDP 51820？ | **通常不必**；可选用于排查 |
| Source `10.2.1.15/32` 入站能否帮助 P2P？ | **基本不能**（方向理解错误） |
| 如何稳定 P2P？ | VNIC **Public IP** |
| 实用默认方案 | **relay-jp** + 收紧 Exit / 路由前缀 |

### 8.10 AWS 公网 Router（IGW + Elastic IP）

适用于 **公有子网 + Internet Gateway + 弹性 IP** 的 Routing Peer（示例：`aws-8237-jp-router-01` / `netbird-jp-router-01`，公网 `54.95.171.5`，私网 `10.168.10.10`，东京 `ap-northeast-1`，安全组 `sec-netbird-jp-router`）。

#### 8.10.1 与 OCI 私网 + NAT GW 的区别

```text
Peer（Mac 等）
    ↕ UDP 51820 / ICE
Elastic IP 54.95.171.5（host 候选）
    ↕ IGW，无 SNAT 遮挡入站（若安全组放行）
EC2 10.168.10.10（netbird-router）
```

| 项目 | AWS 公网 + IGW | OCI 私网 + NAT GW |
|------|----------------|-------------------|
| Dashboard 显示 Public IP | ✅ 有 | ❌ 通常无 |
| P2P 前提 | **安全组入站**须允许 Peer 的 UDP | 主要靠打洞或 Relay |
| 当前仅允许单 IP 入站 | ❌ **会阻断绝大多数 P2P** | — |

你之前 `netbird status -d` 中该节点为 **Relayed、ICE -/-**，在已有公网 IP 的情况下，**首要怀疑安全组入站过严**（例如仅 `18.162.66.231/32`）。

#### 8.10.2 安全组 `sec-netbird-jp-router` 推荐规则

**出站（已满足则可不动）：**

| 类型 | 协议 | 端口 | 目标 | 说明 |
|------|------|------|------|------|
| 全部流量 | 全部 | 全部 | `0.0.0.0/0` | STUN、Relay、打洞出站 |

**入站（P2P 关键 — 在「入站规则」中新增或调整）：**

| 优先级 | 类型 | 协议 | 端口 | 源 | 说明 |
|--------|------|------|------|-----|------|
| 1 | 自定义 UDP | UDP | `51820` | `0.0.0.0/0` | NetBird 默认 WireGuard/ICE 端口 |
| 2 | 自定义 UDP | UDP | `51821` | `0.0.0.0/0` | 若使用 `--wireguard-port 51821` |
| 3 | SSH（按需） | TCP | `22` | 管理机 IP/网段 | 运维；勿对全网开放 |
| 4 | 保留原规则 | 全部 | 全部 | `18.162.66.231/32` | 若该 IP 为跳板/监控，可保留 |

说明：

- **不要**只保留「来源 `18.162.66.231` 的全部流量」作为唯一入站——Mac（国内动态 IP）、其他 Router、办公室出口 IP 均无法直连，只能 **Relayed**。
- NetBird 官方：边界**不强制**入站 51820，但在 **有公网 IP 且需 host/srflx P2P** 时，AWS 安全组必须允许来自 Peer 的 **UDP 入站**，否则公网 IP 无意义。
- 更严做法：源设为 `[NetBird 客户端公网网段]`（难维护）；生产 Router 常用 **UDP 51820–51830 + 0.0.0.0/0**。

**不建议**对全网开放 TCP 51820；NetBird 数据面为 **UDP**。

#### 8.10.3 EC2 / 子网检查

- [ ] 子网路由表：`0.0.0.0/0` → **Internet Gateway**（非 NAT Gateway）。
- [ ] 实例 **自动分配公有 IPv4** 或已关联 **Elastic IP**（`54.95.171.5`）。
- [ ] 网络 ACL 未拒绝 UDP 51820（默认 NACL 通常放行；若自定义 NACL 需同步放行）。
- [ ] 实例 **源/目标检查**（Source/Dest Check）：一般为启用；标准 EC2 路由 Peer 保持默认即可。

#### 8.10.4 Router 主机（Alpine Linux）

```bash
# 查看监听端口
ss -ulnp | grep netbird

# 固定端口（与同 VPC 其他 netbird 节点错开）
netbird down
netbird up --wireguard-port 51820

# 一般无需 external-ip-map：Dashboard 已显示 Public IP 54.95.171.5
# 仅当 agent 识别的公网 IP 不对时再指定：
# netbird up --external-ip-map 54.95.171.5/10.168.10.10 --wireguard-port 51820
```

Alpine 若启用 `iptables`：

```bash
# 允许 NetBird 接口（接口名可能是 wt0）
iptables -I INPUT -i wt0 -j ACCEPT
```

#### 8.10.5 验证

安全组修改后，在 **Mac** 上：

```bash
netbird down && netbird up
netbird status -d
```

查看 `aws-8237-jp-router-01` 一项，期望：

```text
Connection type: P2P
ICE candidate (Local/Remote): srflx/host 或 srflx/srflx
ICE candidate endpoints: .../54.95.171.5:51820
```

仍 Relayed 时：检查 NACL、主机防火墙、是否 `--wireguard-port` 与 SG 端口不一致。

#### 8.10.6 速查

| 问题 | 答案 |
|------|------|
| 有公网为何还 Relayed？ | 入站 SG 仅允许单 IP 时最常见 |
| 最小入站改动 | UDP **51820**（及实际 Wg 端口）来源 `0.0.0.0/0` |
| 出站 | 保持 `0.0.0.0/0` 即可 |
| 与 relay-jp | 公网 P2P 成功后访问日本内网延迟更低；Relay 仍作兜底 |

---

## 9. Traefik 部署对照表

| 组件 | 端口 / 路径 | 多区域 Relay 后 |
|------|-------------|-----------------|
| Traefik | 80 → 301 到 443 | 不变 |
| Dashboard | `Host(netbird.flaship.org)` | 不变 |
| gRPC | `/signalexchange.*`、`/management.ManagementService/` | 不变 |
| API / OAuth2 | `/api`、`/oauth2` | 不变 |
| `/relay` | 反代到 netbird-server:80 | 可保留，数据面不再依赖 |
| netbird-server STUN | 原 `3478:3478/udp` | **删除**端口映射 |
| 区域 Relay | 独立 VM `rels://relay-xx:443` | 新增 |

---

## 10. 故障排查

| 现象 | 可能原因 | 处理 |
|------|----------|------|
| 主站 `Relay: true` | `relays.addresses` 未生效 | 检查 config 挂载与 YAML 缩进 |
| 客户端仍显示主站 Relay | 未重连 | `netbird down && netbird up` |
| Relay 连接失败 | secret 不一致 | 对齐 `NB_AUTH_SECRET`、`relays.secret`、`authSecret` |
| STUN Unavailable | UDP 3478 未放行 | 云安全组 + `network_mode: host` |
| 证书错误 | DNS 或 80 端口 | `dig` 验证 A 记录；放行 TCP 80 供 ACME |
| 配置被还原 | 重跑 getting-started | 仅手工改配置，勿覆盖安装目录 |
| 国内仍慢 | Exit 全流量 + 远端 Relay | 见第 7 节 |
| OCI 私网 Router 长期 Relayed | NAT GW 无入站；打洞失败 | 见 [第 8 节](#8-oci-私网-routernat-gateway)；部署 relay-jp 或绑公网 IP |
| 误以为 Source 10.2.1.15/32 可收 P2P | OCI Ingress Source 含义 | 见 8.3；需对 0.0.0.0/0 或 peer 网段开 UDP 入站（可选） |
| 有公网仍 Relayed（AWS） | SG 入站仅允许单 IP（如 18.162.66.231/32） | 见 [8.10 节](#810-aws-公网-routerigw--elastic-ip)；放行 UDP 51820 来源 0.0.0.0/0 |
| 密钥泄露风险 | 文档 / 工单明文 | 轮换 secret 需同时改主站与所有 Relay 并重启 |

---

## 11. 部署检查清单

### 区域 Relay（每台）

- [ ] DNS A 记录正确
- [ ] TCP 80、443 与 UDP 3478 已放行
- [ ] `NB_AUTH_SECRET` 与主站一致
- [ ] `curl -vk https://relay-xx.flaship.org/` TLS 正常
- [ ] 镜像版本与主站 `netbird-server` 一致

### 主站（新加坡）

- [ ] `config.yaml` 已配置 `stuns` + `relays`
- [ ] 已注释 `stunPorts`
- [ ] `docker-compose.yml` 已删除 `3478:3478/udp`
- [ ] 日志 `Relay: false` 且列出三个 `rels://` 地址
- [ ] 未重跑 `getting-started.sh` 覆盖配置

### 客户端

- [ ] `netbird status -d` 显示区域 STUN/Relay Available
- [ ] Relayed Peer 的 Relay 地址为区域域名
- [ ] 已评估 Exit Node / 路由前缀 / DNS

### OCI 私网 Router（如 10.2.1.15）

- [ ] Route Table 确认 `0.0.0.0/0` → NAT Gateway
- [ ] Egress 允许访问 `netbird.flaship.org` 与 `relay-jp.*`
- [ ] 已配置 `--wireguard-port`（多 Peer 同 NAT 时）
- [ ] 主机防火墙已放行 `wt0`
- [ ] 理解 Ingress `Source 10.2.1.15/32` 不等于「对外开放 P2P」
- [ ] 可选：UDP 入站验证；仍 Relayed 则依赖 relay-jp 或 Public IP

### AWS 公网 Router（如 aws-8237-jp-router-01）

- [ ] 子网 `0.0.0.0/0` → Internet Gateway（非 NAT GW）
- [ ] Elastic IP 已绑定（如 54.95.171.5）
- [ ] 安全组入站：UDP 51820（及实际 Wg 端口）← `0.0.0.0/0`
- [ ] 勿仅用「来源 18.162.66.231/32 全部流量」作为唯一入站
- [ ] `netbird status -d` 显示对该 Peer 为 P2P + `host`/`srflx`

---

## 12. 参考链接

- [Set Up External Relay Servers](https://docs.netbird.io/selfhosted/maintenance/scaling/set-up-external-relays)
- [Scaling Your Self-Hosted Deployment](https://docs.netbird.io/selfhosted/maintenance/scaling/scaling-your-self-hosted-deployment)
- [External Reverse Proxy](https://docs.netbird.io/selfhosted/external-reverse-proxy)
- [Understanding NAT and Connectivity](https://docs.netbird.io/about-netbird/understanding-nat-and-connectivity)
- [Ports & Firewalls](https://docs.netbird.io/about-netbird/ports-and-firewalls)
- 仓库 [HA-DEPLOYMENT.md](./HA-DEPLOYMENT.md)

---

## 13. 附录：域名与路径速查

| 角色 | 示例 FQDN | 协议 |
|------|-----------|------|
| 控制面 | `netbird.flaship.org` | `https://` Management / Signal / Dashboard |
| Relay HK | `relay-hk.flaship.org` | `rels://` :443 + `stun:` :3478 |
| Relay TW | `relay-tw.flaship.org` | 同上 |
| Relay JP | `relay-jp.flaship.org` | 同上 |
| 可选 Relay SG | `relay-sg.flaship.org`（独立 VM） | 同上 |
| OCI JP Router | `oci-jp-router-01`（示例 `10.2.1.15`） | 私网 + NAT GW；见 8.1–8.9 |
| AWS JP Router | `aws-8237-jp-router-01`（示例 `54.95.171.5`） | 公网 + IGW；见 8.10 |

将文中 `flaship.org` 替换为你的实际域名即可用于生产。
