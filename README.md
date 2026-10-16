# CPA Key Model Access 插件

CLIProxyAPI（CPA）原生动态库插件。CPA 继续使用顶层 `api-keys` 完成下游认证；本插件只在 RequestInterceptor 中读取 CPA 提供的 `Metadata.caller_scope`，为**已经存在的 CPA API Key**执行模型 allow/deny。

> `0.1.x` 相对 `0.0.2` 是 breaking pre-1 minor。v1 策略不兼容，从 0.0.2 升级前必须完成下文的迁移步骤。

## 工作边界

- API Key 的创建、删除、保存和认证完全由 CPA 内置 provider 负责。
- 插件不创建、删除或保存原始 Key，也不提供 Key 管理或认证 provider；Web UI 只读获取现有 CPA Key 以关联 scope。
- CPA 认证成功后把稳定的 `caller_scope` 放入 RequestInterceptor Metadata；插件只用该 scope 查找模型策略。
- 没有关联策略的现有 Key 默认允许全部模型。
- 已有关联策略时：`deny_models` 优先；`allow_models` 非空时作为白名单；`allow_models` 为空时允许所有未被 deny 的模型。
- `*` 匹配任意长度字符（包括 `/`），`?` 匹配一个字符；匹配区分大小写。
- 模型名优先取 CPA 的 `RequestedModel`，为空时取 `Model`。

本插件不是认证层。未知或无效 Key 是否可用，由 CPA 顶层 `api-keys` 决定；不要把 Key 只写在插件配置中。

## 兼容性

- CLIProxyAPI **v7.2.103 或更新版本**。
- 最低要求 CPA 插件 RPC schema 2，用于 RequestInterceptor 主动返回结构化 `403`；插件最高声明 schema 6，在新后端上保留管理响应的原始业务字符串，避免 HTML 实体转义改变模型规则或路径。
- RPC schema 与策略文件版本独立：策略仍为 **version 2**，无需迁移。宿主协商 schema 2–5 时，是否转义管理响应取决于宿主实现；使用含特殊字符的路径或规则时建议升级到支持 schema 6 的后端。
- 支持 CPA 动态插件的 CGO 构建；需要 Go 1.24、C 编译器和 `CGO_ENABLED=1`。
- 可通过任一 Management API 响应头 `X-CPA-SUPPORT-PLUGIN: 1` 确认 CPA 二进制支持插件。

## 安装

### 1. 构建或安装动态库

```bash
make test
make build
make package
```

macOS arm64 使用默认版本时会生成：

```text
dist/key-model-access.dylib
dist/key-model-access_0.1.3_darwin_arm64.zip
dist/key-model-access_0.1.3_darwin_arm64.zip.sha256
```

动态库扩展名：

- macOS：`key-model-access.dylib`
- Linux / FreeBSD：`key-model-access.so`
- Windows：`key-model-access.dll`

自动安装到本机 CPA 平台目录：

```bash
make install CPA_DIR=/path/to/CLIProxyAPI
```

也可手动复制到：

```text
<CPA>/plugins/<GOOS>/<GOARCH>/key-model-access.<ext>
```

动态库基础 ID 必须是 `key-model-access`，并与 `plugins.configs.key-model-access` 一致；也可使用 CPA 支持的 `key-model-access-v<version>.<ext>` 后缀。`c-shared` 产物应在目标系统上构建，不能只设置 `GOOS` 做普通交叉编译。

可覆盖构建参数：

```bash
make build GOOS=darwin GOARCH=arm64 BUILD_DIR=/path/to/plugins/darwin/arm64
make package VERSION=0.2.0
```

### 2. 配置 CPA Key 与空的 v2 策略

将 [`config.example.yaml`](./config.example.yaml) 合并到 CPA `config.yaml`。首次启动建议使用内联空策略，不要引用尚不存在的文件：

```yaml
api-keys:
  - "replace-with-a-real-api-key"

plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-model-access:
      enabled: true
      priority: 100
      version: 2
      policies: []
```

此状态下，CPA 顶层 `api-keys` 仍负责认证，插件对所有已认证 Key 默认允许全部模型。随后应在维护窗口内通过 Web UI 为需要限制的 Key 生成 v2 策略。

### 3. 默认持久化

首次打开 Web UI 时，页面会通过 CPA 官方 Management API 读取实际的 `plugins.dir`，自动创建：

```text
<plugins.dir>/key-model-access/config.toml
```

随后页面会将该路径写入 `plugins.configs.key-model-access.policy_file`，由 CPA 保存配置并触发插件重配置。初始化会保留当前有效的内联 v2 策略；若目标文件已经存在，只会校验并复用，不会覆盖。之后 UI 修改会以 `0600` 权限原子保存，CPA 或插件重启后仍然存在。

之所以由 Web UI 发现目录，而不是由动态库猜测自身路径，是因为 CPA 的插件 ABI 不传递 `plugins.dir`，该目录可自定义，且 Windows 会从临时 shadow copy 加载 DLL。

新版后端的插件列表接口对 `plugins_dir` 使用 HTML 实体转义，UI 仅在该字段读取边界解码一次。旧后端若原样返回含 `&lt;` 等实体字面量的目录名，无法从响应区分两者；此类旧部署应显式配置 `policy_file`，跳过自动目录发现。

如需把策略放到其他位置，可显式配置已有的 YAML 或 TOML 文件：

```yaml
policy_file: "config/key-model-access-policies.yaml"
```

显式目标必须预先存在且是有效的 v2 文档；不存在或无效时插件会 fail closed。相对路径以 CPA 工作目录为准。配置了 `policy_file` 后，该文件是权威策略来源；内联 `version` / `policies` 不再生效。

Docker 部署应以**可写**方式持久化整个插件目录：

```yaml
volumes:
  - ./plugins:/CLIProxyAPI/plugins
```

若显式使用其他策略目录，也要持久化整个目录。不要只 bind mount 单个策略文件；插件使用同目录临时文件、`fsync` 和 `rename` 原子替换，单文件挂载通常会阻止保存。插件目录只读或 CPA 配置文件不可写时，自动初始化会在 UI 中报告错误并继续使用内存模式。

## 从 0.0.2 / v1 升级

v1 的 Key 身份和 v2 的 `caller_scope` 架构不同，旧策略不能原地转换。升级前必须：

1. 在受控维护窗口内停止外部流量，并备份 CPA 配置和旧策略。
2. 确保每个仍需使用的**原始 Key**都保留或迁移到 CPA 顶层 `api-keys`。只有旧 `key_sha256` 而没有原始 Key 时，无法把该凭据恢复到 CPA；应创建替代 Key 并更新客户端。
3. 从插件配置和旧策略中移除 v1 字段：`keys`、`default_action`、`models_endpoint`、`allow_query_keys`。
4. 移除指向 v1 文件的 `policy_file`，先改为内联 `version: 2`、`policies: []`。不要让 0.1.0 读取 v1 文件；它会拒绝 v1 并在首次启动时 fail closed。
5. 安装 0.1.0 并重启 CPA，先验证顶层 Key 仍由 CPA 正常认证。
6. 打开 Web UI，读取当前 CPA Key，并为需要限制的 Key **重新生成 v2 策略**。
7. 打开新版 Web UI，让它自动创建并配置默认 `config.toml`，重新核对并保存。若使用显式自定义路径，则先创建有效的 v2 文件。

空 v2 策略会默认允许所有已认证 Key 调用所有被拦截器覆盖的模型。迁移期间应保持外部流量关闭，直到限制策略已重新生成并验证。

## Web UI

插件启用后访问：

```text
http://<CPA_HOST>:<CPA_PORT>/v0/resource/plugins/key-model-access/settings
```

页面会以“模型权限”注册到支持插件资源菜单的 CPAMC 管理界面。UI 不再要求重复输入 Management Key，而是只读复用 CPAMC 已保存的 `cli-proxy-auth` 同源会话，并自动同步 CPAMC 的主题。自动接入要求：

- CPAMC 页面与 CPA API 使用相同 origin（协议、主机和端口均相同）；
- 登录 CPAMC 时启用“记住密码”，使 Management Key 存在于 CPAMC 的 Local Storage 会话中。

条件不满足时，页面会提示返回 CPAMC 修复会话，不提供手工密钥输入。接入成功后 UI 会：

1. 若尚未持久化，读取 CPA 的 `plugins_dir`，创建 `<plugins.dir>/key-model-access/config.toml`，再通过 CPA 官方插件配置 API 写入 `policy_file`；
2. `GET /v0/management/api-keys`，只读获取 CPA 当前顶层 Key；
3. 在浏览器内按 CPA 的规则计算对应 `caller_scope`；
4. 临时使用第一个 CPA API Key 读取 `GET /v1/models`，生成可搜索、多选的模型目录；
5. 读取插件 v2 策略并按 scope 关联；
6. 通过选择器编辑、保存 `allow_models` 和 `deny_models`。选择器提供精确模型、全部模型 `*` 及当前目录可识别的常用模型家族通配符；已有的其他自定义通配符会继续保留并显示其目录匹配结果。

UI 不创建、修改或删除 CPA Key，也不会向 `/v0/management/api-keys` 发出写请求。Key 生命周期仍应通过 CPA 配置或 CPA 自身管理能力完成。UI 会在策略保存前后核对 CPA Key 集合：保存前发现变化会中止并要求刷新；保存后发现变化会立即警告新 Key 当前默认允许全部。两次请求之间仍无法形成事务，因此 Key 变更和策略保存应由运维流程串行化。不再对应当前 Key 的旧 scope 会标记为失效策略，并在保存时保留，避免静默删除。

### UI 安全边界

- `/v0/management/api-keys` 会把原始 Key 返回给已通过 Management 认证的浏览器。UI 仅在 JavaScript 中短暂用于计算 scope，并用第一个 Key 读取模型目录；随后尽力清空临时数组。为便于辨认，UI 只显示每个 Key 的掩码片段（例如 `sk-abcd••••••wxyz`；短 Key 显示更少字符，少于 8 位则完全隐藏）。完整 Key 不会写入 DOM、Local Storage、Session Storage、URL 或插件策略。
- Management Key 由 CPAMC 决定是否持久化。插件只读解析 CPAMC 的同源会话，在自己的 JavaScript 内存中使用，不会复制或再次写入存储。
- CPAMC 当前的浏览器端存储是可逆混淆，不是安全边界。同源页面、浏览器扩展和同机恶意软件均属于信任边界。
- 页面只读同步 CPAMC 的主题，不再维护独立主题偏好。
- 界面支持简体中文与英文：优先跟随 CPAMC 当前语言（嵌入页 `<html lang>`，其次 `cli-proxy-language` / `i18nextLng`），再按浏览器语言选择；其他语言默认显示英文，切换语言时页面实时更新。
- 页面响应使用随机 nonce CSP、`frame-ancestors 'self'`、`X-Frame-Options: SAMEORIGIN`、`form-action 'none'` 和 `Cache-Control: no-store`。
- 应使用 HTTPS、限制 Management API 的网络可达范围，并只在可信浏览器和设备中打开 UI。
- 页面壳不包含 Key 或策略数据；所有 Management API 数据请求都受 CPA Management Key 保护。

## 策略 schema v2

v2 文档顶层只有 `version` 和 `policies`。每条策略只有：

- `caller_scope`：CPA 为已有 API Key 派生的 64 位十六进制 scope；应由 Web UI 生成并关联，不是原始 Key，也不是旧版 `key_sha256`。
- `allow_models`：允许模式数组。
- `deny_models`：拒绝模式数组。

推荐不要手工猜测或复用旧哈希。使用 UI 获取 CPA 当前 Key 并生成正确 scope。

### YAML

参见 [`policies.example.yaml`](./policies.example.yaml)：

```yaml
version: 2
policies:
  - caller_scope: "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
    allow_models:
      - "gpt-5*"
      - "claude-sonnet-*"
    deny_models:
      - "*-preview"
```

### TOML

默认生成的 `config.toml` 使用同一 schema：

```toml
version = 2

[[policies]]
caller_scope = "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
allow_models = ["gpt-5*", "claude-sonnet-*"]
deny_models = ["*-preview"]
```

### JSON

Management API 的 PUT 请求体使用同一 schema：

```json
{
  "version": 2,
  "policies": [
    {
      "caller_scope": "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a",
      "allow_models": ["gpt-5*", "claude-sonnet-*"],
      "deny_models": ["*-preview"]
    }
  ]
}
```

匹配语义：

1. Key 没有对应策略：允许全部模型。
2. 命中任意 `deny_models`：拒绝，优先级最高。
3. `allow_models` 非空：只有命中 allow 且未命中 deny 才允许。
4. `allow_models` 为空：允许所有未命中 deny 的模型。
5. allow 和 deny 都为空等同于允许全部；UI 通常不会为这种 Key 写入策略。

YAML、TOML 和 JSON 都严格拒绝未知字段、重复 `caller_scope` 和非 64 位十六进制 scope。旧的 `key`、`key_sha256`、`id`、`enabled` 等身份字段不会被接受。

## Management API

插件路由由 CPA Management Key 保护：

| 方法 | 路径 | 用途 |
|---|---|---|
| `GET` | `/v0/management/plugins/key-model-access/status` | 查看版本、策略来源、持久化和 fail-closed 状态；不返回 scope |
| `GET` | `/v0/management/plugins/key-model-access/policies` | 获取完整 v2 策略和 revision |
| `PUT` | `/v0/management/plugins/key-model-access/policies` | 用 JSON 原子替换全部策略 |
| `POST` | `/v0/management/plugins/key-model-access/reload` | 从已配置的 `policy_file` 重载 |
| `POST` | `/v0/management/plugins/key-model-access/initialize-storage` | 在给定的 CPA 插件根目录创建或校验默认 `config.toml` |

UI 还会调用 CPA 自带的 `GET /v0/management/plugins` 获取实际插件目录，并通过 `PATCH /v0/management/plugins/key-model-access/config` 仅写入 `policy_file`。它会只读调用 `GET /v0/management/api-keys`；该接口会向已授权管理客户端返回 CPA Key，请勿记录或转发响应。

准备变量并查询状态：

```bash
export CPA_URL=http://127.0.0.1:8317
export CPA_MANAGEMENT_KEY='your-management-key'

curl -sS \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_URL/v0/management/plugins/key-model-access/status"
```

读取策略并保留响应中的 `ETag: "rev-N"`：

```bash
curl -i \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_URL/v0/management/plugins/key-model-access/policies"
```

整体替换策略：

```bash
curl -sS -X PUT \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "rev-N"' \
  "$CPA_URL/v0/management/plugins/key-model-access/policies" \
  --data-binary @- <<'JSON'
{
  "version": 2,
  "policies": [
    {
      "caller_scope": "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a",
      "allow_models": ["gpt-5*"],
      "deny_models": ["*-preview"]
    }
  ]
}
JSON
```

`GET policies` 返回 revision 和 ETag。携带 `If-Match` 可避免覆盖并发修改；revision 不匹配时返回 `412`。为兼容调用方，当前后端仍接受不带 `If-Match` 的 PUT，但不推荐。

配置 `policy_file` 后，PUT 会以 `0600` 权限原子持久化；Web UI 会在首次打开时自动完成默认配置。自动初始化失败或尚未打开 UI 时，未配置文件的 PUT 仍只更新内存。reload 在未配置文件时返回 `409`，文件无效时保留最后一个有效策略并报告错误。

## 验证

查看 CPA 已注册插件：

```bash
curl -sS \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_URL/v0/management/plugins"
```

确认状态至少包含：

```json
{
  "version": "0.1.3",
  "schema_version": 2,
  "auth_mode": "cpa_builtin_api_keys",
  "identity_source": "Metadata.caller_scope",
  "unconfigured_key_action": "allow",
  "fail_closed": false
}
```

使用同一个 CPA 顶层 Key 测试允许和拒绝模型：

```bash
# 应允许
curl -i "$CPA_URL/v1/chat/completions" \
  -H 'Authorization: Bearer your-existing-cpa-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}'

# 若策略只 allow gpt-5*，应由插件返回结构化 403，且请求不应到达上游
curl -i "$CPA_URL/v1/chat/completions" \
  -H 'Authorization: Bearer your-existing-cpa-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-sonnet","messages":[{"role":"user","content":"hi"}]}'

# 不在 CPA 顶层 api-keys 中的 Key 应由 CPA 认证层拒绝，而不是由插件管理
curl -i "$CPA_URL/v1/chat/completions" \
  -H 'Authorization: Bearer unknown-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}'
```

本地质量检查：

```bash
gofmt -w types.go
go test ./...
go vet ./...
make test-web # Node.js 18+，无需安装 npm 依赖
git diff --check
```

## 当前限制

CPA 的 RequestInterceptor 目前没有完整覆盖以下路径或流程：

- `/v1/models`
- `alpha/search`
- Codex Live（包括相关实时/sideband 流程）

因此不要依赖本插件对这些功能实施完整的 per-Key 模型隔离。`/v1/models` 可能返回 CPA 全局模型列表。对于确实进入 RequestInterceptor 的请求，已配置策略的 Key 若缺少模型名会 fail closed；未配置策略的 Key 仍按默认规则允许。若上述未覆盖入口必须受限，应在 CPA/上游 provider 配置、反向代理或网络层禁用或限制，直到 CPA 提供完整 hook 覆盖。

此外：

- 本插件只约束进入 RequestInterceptor 且带可识别模型名的请求，不过滤 CPA 的全局模型目录。
- 有策略存在但 CPA 未提供 `caller_scope` 时，已覆盖请求会 fail closed；完全空策略时，没有 scope 的请求不会由插件拒绝，认证仍由 CPA 负责。
- 首次加载无效配置、旧 v1 文件或不存在的 `policy_file` 会使插件策略 fail closed；后续无效热更新会保留最后一个有效快照。
- 策略变化只影响后续请求，不会中断已经在上游执行的请求。

## 安全说明

- 原生插件与 CPA 同进程运行，只安装可信构建产物。
- 原始 API Key 只应存在于 CPA 顶层 `api-keys`；不要放进插件配置、策略文件或 PUT 请求。
- `caller_scope` 是稳定的伪名标识，仍应视为敏感管理数据；不要公开策略响应和文件。
- Management API 响应设置 `Cache-Control: no-store`；应限制 Management Key 权限并定期轮换。
- 默认策略位于 `<plugins.dir>/key-model-access/config.toml`；应限制插件目录权限并将该插件专属子目录纳入安全备份。显式 `policy_file` 同样应仅允许 CPA 进程用户访问。
- 无策略默认允许全部。新增 CPA Key 后，应及时在 UI 中刷新并配置限制；需要默认拒绝的新 Key 接入流程时，应在外层自动化或网络边界中实现。

## 构建与发布产物

GitHub Actions 工作流 [`.github/workflows/build.yml`](./.github/workflows/build.yml) 负责测试、构建和发布格式。版本 0.1.3 的压缩包命名为：

```text
key-model-access_0.1.3_<goos>_<goarch>.zip
checksums.txt
```

本地生成当前平台压缩包和聚合校验文件：

```bash
make checksums VERSION=0.2.0
```

维护者创建 0.2.0 发布标签的示例：

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

## 官方资料

- https://help.router-for.me/cn/plugin/development
- https://help.router-for.me/cn/plugin/request-interceptor
- https://help.router-for.me/cn/plugin/management-api
- https://github.com/router-for-me/CLIProxyAPI/tree/main/examples/plugin
