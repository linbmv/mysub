# mysub

Cloudflare Worker subscription gateway for Clash/Mihomo and Shadowrocket templates.

完整部署、更新、验证和回滚步骤见 [DEPLOY.md](./DEPLOY.md)。

## Config review

### `clash.yaml`

The Clash/Mihomo template is structurally reasonable:

- Uses `BASE_URL` and `DEVICE_TOKEN` placeholders for private subscription and rule endpoints.
- Splits bootstrap and main providers so the main subscription can be fetched through a bootstrap updater path.
- Uses separate groups for sensitive accounts, media, YouTube, home access, and general international traffic.
- Uses private rule providers through `/rules/home-secret` and `/rules/sensitive`.

Notes:

- This is a Mihomo-oriented config. Options such as `geox-url`, `sniffer`, `tun.auto-redirect`, `dialer-proxy`, and `hidden` may not work on old Clash cores.
- `allow-lan: true`, `external-controller`, and TUN options are desktop-oriented. For untrusted LANs, restrict the controller and LAN exposure.
- Public rule URLs from GitHub Raw are acceptable but can fail in restricted networks. If needed, proxy those lists through the Worker too.

### `ss.conf`

The Shadowrocket template is reasonable for iOS routing and chain/relay groups, with one important fix applied:

- Private Home/Sensitive rule URLs now use `BASE_URL/rules/...?...DEVICE_TOKEN` instead of public gist URLs.
- The file is a template and does not contain real nodes. Actual nodes still come from Shadowrocket subscription import or existing local nodes.

Notes:

- Shadowrocket does not use Clash-style `proxy-providers`; if you want the Worker to be the single client URL, keep using `/config?type=shadowrocket&token=...` as a rule/group template and import node subscriptions separately, or extend the Worker to output converted node lines.
- `policy-regex-filter` relies on node naming conventions. If provider node names change, groups may be empty.

## Worker routes

Public/template routes:

- `GET /health`
- `GET /template?type=clash`
- `GET /template?type=shadowrocket`
- `GET /config?type=clash&token=dev_iphone_xxx`
- `GET /config?type=shadowrocket&token=dev_iphone_xxx`

Subscription/rule proxy routes:

- `GET /main?token=xxx` -> `MAIN_SUB_URL`
- `GET /bootstrap?token=xxx` -> `BOOTSTRAP_SUB_URL`
- `GET /rules/home-secret?token=xxx` -> `HOME_SECRET_RULE_URL`
- `GET /rules/sensitive?token=xxx` -> `SENSITIVE_RULE_URL`

Admin routes:

- `POST /admin/update-template`
- `GET /admin/get-template?type=clash&admin=...`
- `GET /admin/list-templates?admin=...`

KV keys:

- `config:template:clash`
- `config:template:shadowrocket`

## Deploy

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create KV namespace:

   ```bash
   npx wrangler kv namespace create SUB_KV
   npx wrangler kv namespace create SUB_KV --preview
   ```

3. Copy and edit Wrangler config:

   ```bash
   cp wrangler.toml.example wrangler.toml
   ```

   Set:

   - optional `PUBLIC_BASE_URL`
   - `MAIN_SUB_URL`
   - `BOOTSTRAP_SUB_URL`
   - `HOME_SECRET_RULE_URL`
   - `SENSITIVE_RULE_URL`
   - optional `ALLOWED_TOKENS`

4. Store admin secret:

   ```bash
   npx wrangler secret put ADMIN_SECRET
   ```

5. Deploy:

   ```bash
   npm run deploy
   ```

6. Upload templates:

   ```bash
   ./scripts/upload-templates.sh https://sub.example.com 'your-admin-secret'
   ```

## Manual template upload

```bash
curl -X POST "https://sub.example.com/admin/update-template" \
  -F "admin=your-admin-secret" \
  -F "type=clash" \
  -F "template=@clash.yaml"

curl -X POST "https://sub.example.com/admin/update-template" \
  -F "admin=your-admin-secret" \
  -F "type=shadowrocket" \
  -F "template=@ss.conf"
```

## Client URLs

Clash/Mihomo:

```text
https://sub.example.com/config?type=clash&token=dev_iphone_xxx
```

Shadowrocket:

```text
https://sub.example.com/config?type=shadowrocket&token=dev_iphone_xxx
```

If `ALLOWED_TOKENS` is set, only tokens in that comma-separated list are accepted. If it is omitted or empty, any non-empty token is accepted and only used for template injection.
