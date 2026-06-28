# mysub Cloudflare Worker 部署与运维说明

这套配置用于把 Clash/Mihomo 与 Shadowrocket 模板托管到 Cloudflare Worker + KV。

核心思路：

- 模板文件存在 KV，不需要每次改模板都重新部署 Worker。
- 客户端只使用固定链接 `/config?...`。
- Worker 在返回配置时注入 `PUBLIC_BASE_URL` 和客户端 `token`。
- Worker 同时反代真实订阅与私有规则，避免真实订阅地址直接暴露给客户端配置文件。

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `clash.yaml` | Clash/Mihomo 模板，包含 `BASE_URL` 和 `DEVICE_TOKEN` 占位符 |
| `ss.conf` | Shadowrocket 模板，包含 `BASE_URL` 和 `DEVICE_TOKEN` 占位符 |
| `src/worker.js` | Cloudflare Worker 主逻辑 |
| `wrangler.toml.example` | Wrangler 配置示例 |
| `scripts/upload-templates.sh` | 一键上传两份模板到 KV |
| `README.md` | 简要说明 |

## 前置要求

本机需要：

- Node.js 18+
- npm
- Cloudflare 账号
- 已登录 Wrangler

安装并登录：

```bash
npm install
npx wrangler login
```

## 第一次部署

### 1. 创建 KV namespace

```bash
npx wrangler kv namespace create SUB_KV
npx wrangler kv namespace create SUB_KV --preview
```

命令会输出类似：

```toml
[[kv_namespaces]]
binding = "SUB_KV"
id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
preview_id = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
```

记录 `id` 和 `preview_id`。

### 2. 创建 Wrangler 配置

```bash
cp wrangler.toml.example wrangler.toml
```

编辑 `wrangler.toml`：

```toml
name = "mysub"
main = "src/worker.js"
compatibility_date = "2026-06-28"

kv_namespaces = [
  { binding = "SUB_KV", id = "你的 KV id", preview_id = "你的 preview KV id" }
]

[vars]
PUBLIC_BASE_URL = "https://sub.example.com"
MAIN_SUB_URL = "https://真实主订阅地址"
BOOTSTRAP_SUB_URL = "https://真实 bootstrap 订阅地址"
HOME_SECRET_RULE_URL = "https://真实 home-secret.list 地址"
SENSITIVE_RULE_URL = "https://真实 sensitive.list 地址"
ALLOWED_TOKENS = "dev_iphone_xxx,macbook_xxx"
```

说明：

- `PUBLIC_BASE_URL`：客户端访问 Worker 的公开域名，不要带结尾 `/`。
- `MAIN_SUB_URL`：真实主订阅地址，只保存在 Worker 环境变量里。
- `BOOTSTRAP_SUB_URL`：真实 bootstrap 订阅地址。
- `HOME_SECRET_RULE_URL`：私有 Home 规则地址。
- `SENSITIVE_RULE_URL`：私有敏感规则地址。
- `ALLOWED_TOKENS`：可选白名单，逗号分隔。留空表示任意非空 token 都可用。

不要把真实订阅或管理员密钥提交到公开仓库。

### 3. 设置管理员密钥

`ADMIN_SECRET` 必须用 secret 保存，不要写进 `wrangler.toml`：

```bash
npx wrangler secret put ADMIN_SECRET
```

建议生成一个长随机值：

```bash
openssl rand -base64 32
```

### 4. 本地语法检查

```bash
npm run check
```

### 5. 部署 Worker

```bash
npm run deploy
```

如果你使用自定义域名，在 Cloudflare Dashboard 里把 Worker 绑定到例如：

```text
sub.example.com
```

并确保 `PUBLIC_BASE_URL=https://sub.example.com`。

### 6. 上传模板到 KV

```bash
./scripts/upload-templates.sh https://sub.example.com '你的 ADMIN_SECRET'
```

或手动上传：

```bash
curl -X POST "https://sub.example.com/admin/update-template" \
  -F "admin=你的 ADMIN_SECRET" \
  -F "type=clash" \
  -F "template=@clash.yaml"

curl -X POST "https://sub.example.com/admin/update-template" \
  -F "admin=你的 ADMIN_SECRET" \
  -F "type=shadowrocket" \
  -F "template=@ss.conf"
```

## 客户端地址

Clash/Mihomo：

```text
https://sub.example.com/config?type=clash&token=dev_iphone_xxx
```

Shadowrocket：

```text
https://sub.example.com/config?type=shadowrocket&token=dev_iphone_xxx
```

如果 `ALLOWED_TOKENS` 已配置，`token` 必须在白名单内。

## 路由说明

### 公开与客户端路由

| 路由 | 说明 |
| --- | --- |
| `GET /health` | 健康检查 |
| `GET /template?type=clash` | 下载未注入 token 的 Clash 模板 |
| `GET /template?type=shadowrocket` | 下载未注入 token 的 Shadowrocket 模板 |
| `GET /config?type=clash&token=xxx` | 下载注入 token 后的 Clash 配置 |
| `GET /config?type=shadowrocket&token=xxx` | 下载注入 token 后的 Shadowrocket 配置 |

### 订阅与规则反代

| 路由 | 后端来源 |
| --- | --- |
| `GET /main?token=xxx` | `MAIN_SUB_URL` |
| `GET /bootstrap?token=xxx` | `BOOTSTRAP_SUB_URL` |
| `GET /rules/home-secret?token=xxx` | `HOME_SECRET_RULE_URL` |
| `GET /rules/sensitive?token=xxx` | `SENSITIVE_RULE_URL` |

### 管理员路由

| 路由 | 说明 |
| --- | --- |
| `POST /admin/update-template` | 上传或覆盖 KV 模板 |
| `GET /admin/get-template?type=clash&admin=...` | 查看当前模板 |
| `GET /admin/list-templates?admin=...` | 列出支持的模板类型 |

## 日常更新模板

只改 `clash.yaml` 或 `ss.conf` 时，不需要重新部署 Worker。

改完后执行：

```bash
./scripts/upload-templates.sh https://sub.example.com '你的 ADMIN_SECRET'
```

客户端下一次刷新订阅时会拿到新模板。

如果只更新 Clash：

```bash
curl -X POST "https://sub.example.com/admin/update-template" \
  -F "admin=你的 ADMIN_SECRET" \
  -F "type=clash" \
  -F "template=@clash.yaml"
```

如果只更新 Shadowrocket：

```bash
curl -X POST "https://sub.example.com/admin/update-template" \
  -F "admin=你的 ADMIN_SECRET" \
  -F "type=shadowrocket" \
  -F "template=@ss.conf"
```

## 日常更新 Worker 代码

只有修改 `src/worker.js`、`wrangler.toml` 或环境变量时，才需要重新部署：

```bash
npm run check
npm run deploy
```

## 验证命令

检查 Worker 是否可用：

```bash
curl -i https://sub.example.com/health
```

检查模板是否已上传：

```bash
curl -i "https://sub.example.com/template?type=clash"
curl -i "https://sub.example.com/template?type=shadowrocket"
```

检查 token 注入：

```bash
curl -s "https://sub.example.com/config?type=clash&token=dev_iphone_xxx" | grep 'dev_iphone_xxx'
curl -s "https://sub.example.com/config?type=shadowrocket&token=dev_iphone_xxx" | grep 'dev_iphone_xxx'
```

检查真实订阅反代：

```bash
curl -i "https://sub.example.com/main?token=dev_iphone_xxx"
curl -i "https://sub.example.com/bootstrap?token=dev_iphone_xxx"
```

## 回滚

### 回滚模板

如果新模板有问题，重新上传旧版本即可：

```bash
curl -X POST "https://sub.example.com/admin/update-template" \
  -F "admin=你的 ADMIN_SECRET" \
  -F "type=clash" \
  -F "template=@backup/clash.yaml"
```

### 回滚 Worker 代码

用 Git 回到旧提交后重新部署：

```bash
git checkout <stable-commit>
npm run deploy
```

如果没有 Git 仓库，保留旧版 `src/worker.js` 备份，恢复后执行：

```bash
npm run check
npm run deploy
```

## 安全建议

- `ADMIN_SECRET` 只用 `wrangler secret put`，不要写进仓库。
- 真实订阅地址只放在 Worker 环境变量里，不放进模板。
- 如果客户端固定，建议配置 `ALLOWED_TOKENS` 白名单。
- 不要公开 `/admin/get-template` 的管理员链接。
- `clash.yaml` 里 `allow-lan: true` 适合可信局域网；在不可信网络下建议关闭或限制监听。

## 常见问题

### `/config` 返回 `Config template is not configured`

说明 KV 里还没有模板。执行：

```bash
./scripts/upload-templates.sh https://sub.example.com '你的 ADMIN_SECRET'
```

### `/config` 返回 `missing token`

客户端 URL 没带 `token` 参数。使用：

```text
https://sub.example.com/config?type=clash&token=dev_iphone_xxx
```

### `/config` 返回 `invalid token`

`ALLOWED_TOKENS` 已启用，但当前 token 不在白名单里。修改 `wrangler.toml` 的 `ALLOWED_TOKENS` 后重新部署。

### Clash/Mihomo 提示某些字段不支持

`clash.yaml` 是 Mihomo 风格配置。请使用新版 Mihomo 内核，或移除不兼容字段，例如 `dialer-proxy`、`hidden`、`sniffer`、`tun.auto-redirect`。

### Shadowrocket 没有节点

`ss.conf` 是规则和策略组模板，不包含真实节点。Shadowrocket 需要另行导入节点订阅，或后续扩展 Worker 做订阅格式转换。
