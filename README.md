# dsh-veil · 密钥面纱

> 把 DSH 的「显示层遮罩」升级为**执行层强制**：密钥在进入模型上下文 / 会话日志 / 出站请求之前被拦住或抹掉。

## 为什么需要它

DSH 自带 `ui-secret-mask`，但它只是浏览器渲染层把 `sk-...` 画成 `***`。数据本身仍然以明文：

1. 进入**模型上下文**（工具结果一旦被接受，就会出现在之后每一步请求的前缀里）；
2. 进入**会话日志** `~/.dsh/sessions/**/session.v4.jsonl.zstd`（zstd 是压缩，不是加密）；
3. 作为**工具参数**被拼进出站请求（提示注入把密钥塞进 URL / `curl`）。

本插件在 `tools/pre-execute` / `tools/post-execute` 两个官方扩展点上做确定性强制执行，不改 DSH 源码、不注册任何工具（**零 schema 税**）。

## 四层能力

| 层 | 钩子 | 行为 |
|---|---|---|
| A 结果脱敏 | `tools/post-execute` | 结果进入上下文/日志前，抹掉**已知真值**（`~/.dsh/.credentials.yaml` 里的值、环境变量里的 KEY/TOKEN/SECRET）+ 常见密钥形态（sk- / ghp_ / AKIA / JWT / Bearer / PEM 私钥 / `KEY=value` / 带密码连接串） |
| B 凭据读拦截 | `tools/pre-execute` | 参数指向凭据库（`.credentials.yaml`、`.ssh/*`、`.aws/credentials`、`.npmrc`、`.netrc`、`.git-credentials` …）时直接拒绝，含 shell 拼接 |
| C 外发拦截 | `tools/pre-execute` | 出站类调用（web/mcp/带 URL/`curl`/`Invoke-WebRequest`/ssh…）的参数里出现密钥 → 拒绝 |
| D 信任边界 | `tools/post-execute` | 给 web/mcp 结果包一层确定性的「不可信数据」边界，降低间接注入成功率 |

## 安装

```powershell
# 从 GitHub 安装
dsh plugin add github:yhl4466/dsh-veil

# 或本地目录（开发时）
dsh plugin add <本目录>
```

已在本机 `desktop` profile 安装并验证：Loader entry `include:dsh-veil`，`fiberPhase=active`。

## 配置（覆盖 profile 的 `cordis.patch.yml`）

```yaml
- id: dsh-veil
  name: dsh-veil
  config:
    redactResults: true        # A 结果脱敏
    denyCredentialReads: true  # B 凭据读拦截
    blockSecretEgress: true    # C 外发拦截
    envelopeUntrusted: true    # D 信任边界
    watchCredentialStore: true # 从 ~/.dsh/.credentials.yaml 读真值（只读，不落盘）
    exemptTools: []            # 不脱敏的工具名
    untrustedTools: []         # 额外声明为不可信来源的工具名
    extraSecrets: []           # 额外已知密钥（字符串数组）
    protectPaths: []           # 覆盖受保护路径列表（整体替换）
```

> patch 的 `config` 是**整体替换**：覆盖时请把需要保留的字段一并写全。

## 状态查看

输入 `/veil`（命令不进工具列表，不占每次请求的 token）：

```
dsh-veil 凭据护栏
开关：结果脱敏=开 凭据读拦截=开 外发拦截=开 信任边界=开
本会话：脱敏 2 次 / 拦读 1 次 / 拦外发 0 次 / 加边界 3 次
近 24h 全局：...
命中规则 Top5：...
```

账本：`~/.dsh/veil/ledger.jsonl`，**只记「命中了哪条规则、几次」**，永不写密钥原文；超过 2 MB 自动轮转。

## 设计约束（与 dsh-fence 同一套缓存契约）

- **前向一次性**：结果只在进入会话那一刻改写一次，绝不回改已发送的消息；
- **确定性**：同一 `(工具, 参数, 结果)` 每次得到同样字节（信任边界里不放时间戳）；
- **失败开放**：脱敏异常时放行原结果，绝不把一次成功的工具调用变成报错；
- **不落明文**：账本与日志都不含密钥值。

## 已验证 / 已知边界

已验证（见 `test/veil-test.mjs`，16/16，`npm test` 可跑）：
- `sk-` 形态与凭据库真值都被脱敏；凭据读被拒；`curl` + 密钥被拒；普通读文件、`grep` pattern、含 URL+密钥的 `write` 正文、提到 `.credentials.yaml` 的 shell 文档写法均不被误拦；
- 信任边界确定性；账本无明文；重复输入同样字节；图片块原样透传；`/veil` 输出无明文。
- 实测会话日志：被脱敏的 `tool/result` 事件里存的就是脱敏后的副本。

已知边界：
1. **模型自己生成的内容**（assistant 文本、tool-call 参数、你手动粘贴的消息）不经过 `tools/post-execute`，不在本插件范围；输入侧请配合 `dsh-secret-paste` 一类插件。
2. 官方 spill / dsh-fence 若在链上先把超大结果落盘，落盘副本可能仍含原文（只拦内存中的模型可见副本）；凭据读拦截已把主要入口关掉。
3. 图片/二进制内容不做脱敏。
4. UI 工具卡片仍显示原始结果（脱敏只作用于模型可见副本），这是刻意保留的排查能力。
