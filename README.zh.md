# @theoabw/dsh-secrets

[![npm](https://img.shields.io/npm/v/@theoabw/dsh-secrets?label=npm)](https://www.npmjs.com/package/@theoabw/dsh-secrets)

[English](https://github.com/theoabw/dsh-secrets/blob/main/README.md) | 中文

本文件是英文文档的翻译。若两者不一致，以英文版为准；`SECURITY.md` 与 `docs/` 中的安全说明只提供英文，以免翻译滞后带来错误陈述。

面向 [deepseek-harness](https://github.com/deepseek-ai/deepseek-harness)（dsh）
的、需要所有者同意的密钥代理插件。

给 Agent 一个凭据，通常意味着把它粘贴进对话。这样值会进入 transcript、会话
日志、轨迹，以及之后每一次上下文压缩。本插件去掉这一步：Agent 按名字申请密钥，
**你**为那个会话批准访问，值从你的密码管理器直接进入需要它的那条 shell 命令的
环境变量。模型只会看到一个 handle：

```
secret_request   -> 你允许本会话从 "vault" 读取
secret_fetch     -> { handle: "A1B2…", env: "DSH_SECRET_A1B2…" }
$DSH_SECRET_A1B2… -> 值本身，出现在你的命令里
```

本插件不实现任何密码库协议，也不保存凭据。provider 就是普通命令，原本负责解锁
密码库的那个 CLI 继续负责它。

这是成对插件中的 broker 一半。
[dsh-secret-prompt](https://github.com/theoabw/dsh-secret-prompt) 是 ask 一半：
在任务进行中把一个凭据输入到掩码输入框。

## 为什么这样设计

- **Agent 永远拿不到值。** 工具结果里只有 handle 和环境变量名。harness 把真正的
  值注入命令进程的环境变量，与 `DSH_SESSION_ID` 走同一条通道。
- **访问按会话授权，默认关闭。** 新会话读不到任何东西。授权是你的一次点击，有
  范围、有期限，会话结束或服务重启即失效。
- **密码库登录不会交到 Agent 手上。** 对命令 provider 来说，`op`、`pass` 或你
  自己的脚本在终端里自行完成认证。对 `kind: bitwarden` 来说，主密码只在宿主
  进程内使用一次，用完即丢弃，因此 Agent 无法自行进入密码库。两种情况都不落盘。
- **泄漏是可控的。** 值处于活动状态期间，所有模型可见的工具结果都会改写为
  `[redacted]`，shell 为截断输出写出的临时文件也会就地清洗。

## 为什么在已有大型密码库插件之外还要有这个

dsh 有一个成熟的 Vaultwarden 插件，带密码库浏览、写入、passkey 导出和设置页。
本插件刻意做得更小，因为把密码库交给那样规模的集成，并不是每个人都愿意做的决定：

- 1935 行运行时 TypeScript，没有运行时依赖，只在你配置的那一台服务器上调用三个
  HTTP 端点。
- 不写入密码库。没有缓存、没有状态文件、不保存主密码。
- 取到的值不会回到模型，只进入命令的环境变量。
- 授权是按会话、有范围、有期限的，而且模型不能自己回答授权卡片。

[docs/audit.md](https://github.com/theoabw/dsh-secrets/blob/main/docs/audit.md)
列出了每一次网络调用、每一个进程、每一个文件和每一个保留的值，并给出逐条核对的
grep 命令。如果你更看重功能覆盖而不是攻击面大小，请用那个更大的插件；两者在同一个定位上
并不是竞品。

## 安装

```sh
dsh plugin --profile web add @theoabw/dsh-secrets
```

然后把 loader 行加入你的 profile patch（`~/.dsh/profiles/<name>/cordis.patch.yml`）：

```yaml
- insert:
    - id: secrets
      name: '@theoabw/dsh-secrets'
      config:
        providers:
          vault:
            command: ["rbw", "get", "{item}", "--field", "{field}"]
            list: ["rbw", "list"]
        grantMinutes: 30
```

本插件只存在于宿主侧，因此需要重启服务（`dsh.service`）才会出现。重启会结束当前
活动中的会话。

### 从源码安装

```sh
git clone https://github.com/theoabw/dsh-secrets
cd dsh-secrets
pnpm install
bash scripts/link-deps.sh   # 把运行中的 dsh 的 @deepseek-ai 包链接进来
pnpm run build              # 生成 lib/，profile 安装的就是它
dsh plugin --profile web add "file:$PWD"
```

`pnpm run check` 会跑类型检查、构建和三个测试套件。

## 配置 provider

provider 是一个 argv 模板，不经过 shell 执行。`{item}` 和 `{field}` 由工具调用
替换，`{query}` 由 `secret_list` 替换，命令的 stdout 就是值。

| 密码库 | `command` | `list` |
|---|---|---|
| Bitwarden / Vaultwarden | `kind: bitwarden`，见下文 | 内置 |
| rbw | `["rbw", "get", "{item}", "--field", "{field}"]` | `["rbw", "list"]` |
| 1Password | `["op", "read", "op://{item}/{field}"]` | `["op", "item", "list", "--format", "json"]` |
| pass | `["pass", "show", "{item}"]` | `["pass", "ls"]` |
| sops | `["sops", "-d", "--extract", "[\"{item}\"]", "secrets.enc.yaml"]` | |

对 Bitwarden 和 Vaultwarden 来说，`rbw` 是最省事的选择：它在内存里保持一个已
解锁的 agent，因此会话密钥永远不会变成 dsh 里的值。先用
`rbw config set base_url https://vault.example.com` 指向你的服务器，然后在你
自己的终端里 `rbw register` 和 `rbw unlock`。

`list` 是可选的。不配置它时，`secret_list` 会提示 Agent 自己说出条目名。

### 掩码输入

插件向所有者索取值时，会用 `dsh-secret` header 发出这个问题。
[dsh-secret-prompt](https://github.com/theoabw/dsh-secret-prompt) 会为该 header
渲染掩码输入框，插件正是通过它索取主密码。没有这个配套插件时，问题会回退到普通
卡片，输入不带掩码，所以在用于任何重要凭据之前请先安装它。两者是配套设计的：
一个索取单个凭据，另一个按范围代理某个 provider 的访问。

## Bitwarden 与 Vaultwarden

`kind: bitwarden` 在宿主进程内完成登录和解密，这正是让授权具有约束力、而不是
仅作提示的原因：

- 每个会话由你提供一次主密码，输入在掩码框中。
- 插件派生密钥、登录并同步。只有授权范围内的条目会被解密。之后密码和派生出的
  密钥都会被丢弃。
- 不把会话 token 交给任何子进程，也不留下已解锁的 agent，因此没有可供其他进程
  复用的东西。
- Agent 最终持有的只有：账号邮箱、服务器地址、你授权过的条目名，以及 handle。
  没有密码，没有主密钥，没有用户密钥。

```yaml
providers:
  vault:
    kind: bitwarden
    email: agent@example.com          # KDF 的盐，不是秘密
    server: https://vault.example.com
```

`secret_lock` 会丢弃密钥，授权失效时同样如此。

要求：账号的 KDF 为 PBKDF2（默认值），且没有启用两步验证。Argon2id 账号会被
明确拒绝，2FA 挑战会被报告而不是重试，因为 TOTP 密钥将不得不和主密码放在同一处。

不经过 dsh 检查一个账号：

```sh
node lib/live-check.js --server https://vault.example.com \
  --email agent@example.com --password-env VAULT_PASSWORD
```

它会打印 KDF 参数、条目数量和条目名称，从不打印任何值。密码来自指定的环境变量，
因此不会出现在进程参数里。

设计与协议步骤见
[docs/bitwarden-provider.md](https://github.com/theoabw/dsh-secrets/blob/main/docs/bitwarden-provider.md)。

## 工具

| 工具 | 作用 |
|---|---|
| `secret_request` | 向你申请授权：provider、范围、理由和时长。选项是短暂允许、允许到会话结束，或拒绝。 |
| `secret_fetch` | 通过 provider 读取一个条目，返回 `{ handle, env }`。需要覆盖该条目的授权。 |
| `secret_list` | 当前授权下可见的条目名。只有名字，永远没有值。 |
| `secret_status` | 已配置的 provider、各自命令是否可用、本会话的授权、活动值数量。 |
| `secret_lock` | 忘记某个 handle，或丢弃本会话的全部值和授权。 |

范围：`*` 表示所有条目，以 `*` 结尾表示前缀（例如 `deploy*`），也可以是一个精确
的条目名。

## 一个会话是什么样子

```
secret_request  provider="vault" scope="deploy*" reason="读取部署 token"
                -> 所有者允许 30 分钟
secret_fetch    item="deploy-token" field="password"
                -> { handle: "9F3A…", env: "DSH_SECRET_9F3A…" }
bash            curl -H "Authorization: Bearer $DSH_SECRET_9F3A…" https://…
secret_lock
```

## 威胁模型

受保护的内容：

- 值不会出现在 Agent 的上下文、对话、会话 JSONL，或本插件写的任何日志里。
- 值不会被持久化：它只存在于宿主进程内存，用随机 handle 寻址，在 `handleMinutes`
  内未被使用就会被忘记。
- 会话读不到没有被授权的 provider，读不到授权范围之外的条目，也不能回答自己的
  授权卡片。子代理会话不允许发起授权卡片。
- 随时可以用 `secret_lock` 收回访问，它不会比会话或服务活得更久。

明确不保护的内容，以及原因：

- **已获授权的会话可以通过它被允许执行的命令外带值**（例如
  `echo $DSH_SECRET_x | base64`）。值必须经过命令的进程空间才可用，所以授权是
  策略闸门、脱敏是安全网，而不是沙箱。
- **同一个操作系统用户可以读取进程环境和承载值的子进程**。要把密钥与以你的身份
  运行的 Agent 隔离开，需要的是操作系统边界，而不是插件。
- **脱敏是精确文本匹配。** 经过编码或变换的值不会被拦截。短于 `minRedactLength`
  的值完全不做脱敏，这样一个只有一个字符的极端密钥也不会毁掉每一条工具结果的可读性。
- **主密码在 dsh 进程内使用。** 授权有效期间，派生出的密钥就在该进程内存里。唯一
  可能读到它们的是以同一 OS 用户运行的恶意进程，这与保护主机其余部分的是同一条
  边界；而它严格强于 CLI 方案，那里凭据可以通过 `/proc` 触达。
- **provider 的错误文本会展示给 Agent**，截断为一行，因为“密码库已锁定”正是让
  失败可处理的信息。如果 provider 在失败时把值打印到 stderr，就会泄漏，因为此时
  该值还没有登记用于脱敏。请把 provider CLI 的错误输出视为信任面的一部分。

## 非目标

- 实现密码库协议，或同步你的密码库。
- 保存密码库登录信息，或以任何形式静态保存密钥。
- 远程或带外批准、多用户部署、硬件令牌。
- 给 Agent 做沙箱。见上面的威胁模型。

## 配置参考

| 字段 | 默认值 | 含义 |
|---|---|---|
| `providers` | `{}` | provider id 到 `{ command, list, timeoutMs, env }`。 |
| `grantMinutes` | `30` | 短暂允许选项提供的分钟数。 |
| `maxGrantMinutes` | `240` | 单次授权可申请的分钟上限。 |
| `handleMinutes` | `30` | 取到的值在多久未被使用后被忘记。 |
| `maxSecretsPerSession` | `20` | 每个会话的活动值上限。 |
| `minRedactLength` | `4` | 会被脱敏的最短值长度。 |

## 开发

```sh
pnpm run typecheck
pnpm run build
pnpm test
```

三个套件都针对构建产物 `lib/` 运行：

- `crypto-test.mjs` 用独立实现校验 Bitwarden 的密钥派生。期望的主密钥、拉伸后
  的密钥、登录哈希和密文都由 Python 的 `cryptography` 和 OpenSSL 生成，而不是由
  本仓库代码生成，因为自洽的测试在密钥派生错误时也会通过。
- `smoke-test.mjs` 驱动插件本体：注册、授权卡片形状、授权范围、真实的 provider
  命令、按会话注入、内容/反馈/值替换/溢出文件的脱敏，以及锁定。
- `bitwarden-test.mjs` 用本地 HTTP 服务器代替密码库，提供用真实密钥派生加密的
  内容，因此 prelogin、密码授权、同步、密钥解包、解密和锁定都能在没有真实服务器
  的情况下端到端跑通。

## 相关工作

broker 这种模式并不新鲜，已有多个项目采取“值不进入模型”的立场。本插件存在的
理由是在 dsh 这个场景里，小且可审计的攻击面比功能覆盖更重要。

- [dsh-vaultwarden](https://github.com/BuvkB/dsh-vaultwarden)：功能完整的
  Vaultwarden 集成，带密码库浏览、写入和 passkey。
- [dsh-key-panel](https://github.com/MoruTeaven/dsh-key-panel)：把 API key 注入
  assistant shell 的 `$DSH_*` 变量。
- [dsh-safebox](https://github.com/jiangzhenguo/dsh-safebox)：只写凭据，Agent
  只能看到元数据。
- [agent-secret](https://github.com/kovyrin/agent-secret)：macOS 上的批准 broker，
  把批准的密钥注入单个子进程。
- [secret-broker](https://pypi.org/project/secret-broker/)：AWS、1Password 和
  Vault 之上的联邦门面，只给引用，不给值。

## 许可证

MIT

## 另见

[dsh-secret-prompt](https://github.com/theoabw/dsh-secret-prompt) 是 ask 一半：
一个 `prompt_secret` 工具，把单个凭据收集到 GUI 的掩码输入框里，并且只以
`$DSH_SECRET_<handle>` 的形式暴露。本插件在它提出的问题上沿用同一套约定。
