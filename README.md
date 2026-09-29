# ChatGPT 批量注册 / 支付能力探测 工具链

**纯协议 + 浏览器双引擎**的 ChatGPT 账号注册工具，附带一套**支付能力探测**（结算页金额 / 0 元试用判定）与可视化 **WebUI**。

- **纯协议引擎**：`curl_cffi` 复刻浏览器 TLS/HTTP2 指纹 + QuickJS 跑 OpenAI 官方 `sdk.js` 解 Sentinel PoW，全程无浏览器。
- **浏览器引擎**（可选）：Camoufox / Playwright 真浏览器内核，注册链路卡风控时的备选路径。
- **支付能力探测**：协议直连 `payments/checkout`（创建未支付会话读金额）+ 可选外接探测服务 + 浏览器回退。
- **环境一致性**：出口 IP / 浏览器指纹在任务开始前**冻结并写台账**，任务间出口与画像全历史唯一；时区、语言、分辨率、Client Hints 全部跟出口国家对齐。
- **WebUI**：号池导入、批量跑号、实时 SSE 日志、注册结果与凭证一键导出。

> ⚠️ **仅供技术研究与自建测试**。使用者需自行确保符合 OpenAI 服务条款与所在地法律；请勿用于批量注册滥用、绕过风控牟利等用途。作者不对任何使用后果负责。

---

## 快速开始

### Windows（推荐，一键脚本）

```bat
:: 1) 装 Python 3.12（安装时勾选 Add to PATH）
:: 2) 双击 install_deps.cmd  ← 装依赖 + 下载浏览器内核
:: 3) 双击 run_webui.cmd     ← 启动，浏览器打开 http://127.0.0.1:8765/
```

### 任意平台

```bash
git clone https://github.com/jiangjin934/gpt-reg-review.git
cd gpt-reg-review
pip install -r requirements.txt
python -m camoufox fetch        # 可选：只在用浏览器引擎时需要
python -m playwright install chromium   # 可选：同上
python start_webui.py                                    # 默认 127.0.0.1:8765
python start_webui.py --host 0.0.0.0 --port 8765         # 公网监听
```

启动后到 WebUI 的「代理池」「邮箱池」填好资源，再在「全自动批量」页点开始即可。

Sentinel PoW 需要 node（`pip install playwright` 会自带一份，程序会自动找到；也可装 Node.js LTS 或设 `OPENAI_SENTINEL_NODE_PATH`）。

---

## 核心能力

### 1. 注册链路（`auth_flow.py`）

```
GET  chatgpt.com/api/auth/csrf                      → csrf_token
POST chatgpt.com/api/auth/signin/openai              → auth_url
GET  auth.openai.com/authorize?...                   → device_id (oai-did)
POST sentinel.openai.com/backend-api/sentinel/req    → Sentinel PoW token（QuickJS 跑官方 sdk.js）
POST auth.openai.com/api/accounts/authorize/continue → 判定 signup / 已有账号
POST auth.openai.com/api/accounts/user/register      → 设置密码
POST auth.openai.com/api/accounts/email-otp/send     → 触发验证码
     mail_provider.wait_for_otp()                     → 取码（IMAP XOAUTH2 / 中转站 HTTP）
POST auth.openai.com/api/accounts/email-otp/validate → 验证
POST auth.openai.com/api/accounts/create_account      → 建号
GET  chatgpt.com/api/auth/session                     → access_token + cookies
POST auth.openai.com/oauth/token (PKCE)               → refresh_token（可选）
```

关键点：

- **Sentinel 用真 sdk.js**（QuickJS 执行），不是仿造算法；`node` 缺失时自动降级到纯 Python 实现并给出明确日志。
- **2FA 与密码在拿到时就落盘**（`save_password_early` / `save_totp_early`），流程后半段中断也不会丢——TOTP secret 服务端一次性下发、取不回。
- **完整性门槛**：只有「密码 + 2FA secret + access_token」齐备的账号才计入结果页与导出。缺凭证的半成品留在库里（重跑可续用），但不污染统计。
- **按钮级拟人节奏**：关键步骤间插入三段右偏分布停顿（80% 短 / 17% 中 / 3% 长尾），只改时序不改请求内容。

### 2. 环境分配（`webui/environment.py` + `fingerprint.py`）

- **出口冻结**：任务开始前探测出口 IP / 国家，写进台账；任务中途出口变化会被检测并处置。
- **画像全套**：UA、Client Hints、TLS impersonate 三者版本严格自洽；时区 / 语言 / 分辨率 / 平台跟出口国家配套（`country_profiles`）。
- **全局唯一**：出口 IP 与画像签名在历史台账里唯一，任务之间不重复。
- **粘性会话**：`sessionize_proxy` 给每个任务注入独立 sid，任务内出口恒定、任务间不重复。

### 3. 支付能力探测（`payment_probe.py` / `checkout_service_probe.py`）

三种路径，通过设置 `checkout_probe_source` 切换：

| 实现 | 说明 |
|---|---|
| `payment_probe.py`（自研协议） | 直连 `chatgpt.com/backend-api/payments/checkout`。**必须带 sentinel 双头**（`openai-sentinel-token` + `openai-sentinel-so-token`，flow=`chatgpt_checkout`）—— 从网页版 bundle 反解出来的要求，缺一个就是 400 `unusual activity`。 |
| `checkout_service_probe.py`（外接服务） | 把 AT + 出口交给探测服务，服务端建 checkout 读金额。含 429 按 `retryAfterSeconds` 退避、传输失败自动换会话重试。 |
| `browser_checkout_probe.py`（浏览器回退） | Camoufox 打开页面，在页面上下文内 `fetch` checkout。 |

判定口径：

- **0 元可领**：`one_click_trial_eligible=true`，或折扣/促销字段非空。
- **需付金额**：checkout 响应本体不含金额（在 Stripe 会话内部），需付款时按结算地市场定价落库，并在 `amount_source.basis=market` 留痕。
- **限流防护**：429 只跳过该号并记录可重试时间（限流按 token，号与号互不影响），到点自动补探；限流/传输类失败**不会覆盖**已探到的金额。

### 4. 邮箱来源

| kind | 说明 |
|---|---|
| `icloud_relay` | iCloud「隐藏我的邮箱」+ 中转站取码接口（`email----取件链接` 两段格式） |
| `cf_temp` | 自建 `cloudflare_temp_email` Worker catch-all |
| `outlook` | Outlook IMAP XOAUTH2（`email----password----client_id----refresh_token` 四段） |
| `mail_com` | mail.com 别名 |

### 5. 浏览器引擎（可选）

`browser_flow.py` + `browser_launcher.py`：Camoufox（反指纹 Firefox）/ Playwright 内核。两处工程细节值得一提，都是实测踩出来的：

- **带认证的 SOCKS5**：Playwright / Camoufox 不支持，代理池全是带认证的 → 起本地免认证 SOCKS5 中继（`local_socks_relay.py`）转一手。
- **屏幕/视口对齐**：Camoufox 默认随机生成 screen，与冻结画像不一致会被运行时校验拦下 → 用 `config=` 把 screen/viewport 钉死到画像。

---

## 文件清单

### 协议核心

| 文件 | 作用 |
|---|---|
| `auth_flow.py` | 纯协议注册/登录状态机（最大单体） |
| `sentinel.py` / `sentinel_quickjs.py` / `openai_sentinel_quickjs.js` | Sentinel PoW（纯 Python + QuickJS 两条路） |
| `fingerprint.py` | 浏览器画像生成 + 国家画像表 + 版本自洽校验 |
| `http_client.py` | `curl_cffi` 会话工厂（TLS 指纹 / 代理 / 流量统计 / TLS 瞬断重试） |
| `browser_flow.py` / `browser_launcher.py` | 浏览器引擎 |
| `local_socks_relay.py` | 本地 SOCKS5 中继（把带认证代理变成免认证） |
| `payment_probe.py` | 自研支付探测（含 sentinel 双头） |
| `checkout_service_probe.py` | 外接探测服务客户端 |
| `browser_checkout_probe.py` | 浏览器内 checkout |
| `plus_trial_checker.py` | 只读查询 coupon / accounts 接口 |
| `sms_provider.py` | SMS 接码（SmsBower / HeroSMS / sms-activate 协议系） |
| `checkout_probe_standalone.py` | 单文件版探测脚本（可单独拷到别的机器跑） |
| `registration_probe.py` / `reg_batch_probe.py` | 批量判定邮箱是否已注册 |

### WebUI

| 文件 | 作用 |
|---|---|
| `start_webui.py` | 启动脚本 |
| `webui/app.py` | FastAPI 路由 + SSE 日志流 |
| `webui/registrar.py` | 单任务 worker（线程 + 探针日志） |
| `webui/auto_loop.py` | 多 worker 自动跑号控制器（并发 / 熔断 / 自动补号） |
| `webui/environment.py` | 任务环境分配（出口 + 画像冻结、台账去重） |
| `webui/db.py` | SQLite：号池 / 注册结果 / 运行记录 / 环境台账 |
| `webui/checkout_capability.py` | 支付探测队列（多 worker / 限流退避 / 冷却补探） |
| `webui/frontend/` | Vue 3 + Element Plus 前端源码 |
| `webui/static/` | 构建好的前端产物（部署直接用，无需 npm） |

---

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `WEBUI_HUMANIZE` | `0` | `1` 开启步骤间拟人停顿（生产路径由 registrar 开启） |
| `OPENAI_SENTINEL_NODE_PATH` | 自动查找 | node 可执行文件路径（Sentinel PoW 用） |
| `OTP_TIMEOUT` | `180` | 等验证码超时（秒） |
| `WEBUI_ALLOW_LOGIN` | — | 允许走已有账号登录分支 |
| `AUTH_TRACE_DUMP` | — | `1` 时把每步 HTTP 往返打详细日志 |

---

## 测试

```bash
python -m pytest -q          # 563 项
```

测试用独立临时数据库与假网络边界（`tests/conftest.py` 会拦掉真实 socket 与 curl_cffi 请求），不会碰到你的号池数据、也不会发真实请求。

---

## License

AGPL-3.0（见 `LICENSE`）。

## 交流

QQ 群：2642235080
