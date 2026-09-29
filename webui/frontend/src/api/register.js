import http from './request'

// ──────────────── 单个注册 ────────────────
export const startRegister = (payload) => http.post('/api/register', payload)

// ──────────────── 运行记录 ────────────────
export const listRuns = (limit = 50) => http.get('/api/runs', { params: { limit } })
export const getRunEnvironment = (runId) =>
  http.get(`/api/runs/${encodeURIComponent(runId)}/environment`)
export const getRunProbes = (runId) =>
  http.get(`/api/runs/${encodeURIComponent(runId)}/probes`)
export const listEnvironments = (limit = 100) =>
  http.get('/api/environments', { params: { limit } })

// ──────────────── 注册结果 registered ────────────────
export const listRegistered = (params) =>
  http.get('/api/registered', { params }) // { limit, offset, filter }

// 注册结果页的轻量元数据：国家 / 指纹版本 / 流量 / AT 过期时间。
// 一次全量拉回（只含小字段），前端本地按 email 映射。
// 只取当前页那几行的元数据（全量返回会随历史任务涨到几百 KB，列表页很卡）
export const getRegisteredMeta = (emails = []) =>
  http.get('/api/registered/meta', {
    params: emails.length ? { emails: emails.join(',') } : {},
  })

// 重登选中的号，刷新 access/session token（AT 过期或 401 时用）。
// 顺序执行，一个号一次协议登录；超时给足，避免长批量被前端掐断。
export const refreshRegisteredTokens = (payload) =>
  http.post('/api/registered/refresh_tokens', payload, { timeout: 30 * 60 * 1000 })

// 检测 AT 状态：后端只解 JWT exp，过期的号会顺手走协议重登刷新（一次最多 50 个）
export const checkRegisteredAt = (payload) =>
  http.post('/api/registered/check_at', payload, { timeout: 30 * 60 * 1000 })

// 全库支付能力汇总：可 0 元领 / 无 UPI / 探测失败 / 未探测
export const getCheckoutSummary = () => http.get('/api/registered/checkout_summary')

export const getRegistered = (email) =>
  http.get(`/api/registered/${encodeURIComponent(email)}`)

export const deleteRegistered = (email) =>
  http.delete(`/api/registered/${encodeURIComponent(email)}`)

export const rebindEmail = (payload) =>
  http.post('/api/registered/rebind_email', payload, {
    timeout: 15 * 60 * 1000,
  })

// 手填凭证：不传的字段后端不动，传空串才是清空
export const updateCredentials = (payload) =>
  http.post('/api/registered/update_credentials', payload)

export const bulkDeleteRegistered = (payload) =>
  http.post('/api/registered/bulk_delete', payload) // { emails } 或 { all: true }

// 导出后清理用：把号池那一行也删掉。
// 从 accounts.js 转出来一份，省得 Registered.vue 同时 import 两个 api 模块。
export { bulkDeleteAccounts } from './accounts'

// 批量导出：格式清单由后端 export_formats.py 提供，加格式前端不用改
export const listExportFormats = () => http.get('/api/registered/export/formats')
export const exportRegistered = (payload) => http.post('/api/registered/export', payload)

export const checkPlus = (emails, proxy = '') =>
  http.post('/api/registered/check_plus', { emails, proxy })

// 支付能力探测（int31.space，只走印度静态出口）：返回真实 checkout 金额
export const checkoutCapability = (emails, proxy = '', waitSeconds = 180) =>
  http.post(
    '/api/registered/checkout_capability',
    { emails, proxy, wait_seconds: waitSeconds },
    { timeout: 30 * 60 * 1000 },
  )

// 自动探测队列状态 + 手动入队（注册完会自动入队）
export const checkoutCapabilityQueue = () =>
  http.get('/api/registered/checkout_capability/queue')
export const enqueueCheckoutCapability = (emails) =>
  http.post('/api/registered/checkout_capability/enqueue', { emails })

// ──────────────── Plus 开通（提炼 + UPI 支付，走 int31.space）────────────────
export const getPlusConfig = () => http.get('/api/plus/config')
export const savePlusConfig = (payload) => http.post('/api/plus/config', payload)
// 提交是逐个 token 调外部服务，给足超时
export const submitPlus = (emails) =>
  http.post('/api/plus/submit', { emails }, { timeout: 30 * 60 * 1000 })
export const syncPlus = () =>
  http.post('/api/plus/sync', {}, { timeout: 10 * 60 * 1000 })
export const listPlus = () => http.get('/api/plus/list')
// 可开通 Plus 的号必须先由主人授权，才允许提交提炼 + 支付
export const listPlusPending = () => http.get('/api/plus/pending')
export const approvePlus = (emails) =>
  http.post('/api/plus/approve', { emails }, { timeout: 30 * 60 * 1000 })
export const rejectPlus = (emails) => http.post('/api/plus/reject', { emails })

// ──────────────── 自动供号（ReMail：池空自动下单买邮箱）────────────────
export const mailSupplyStatus = () => http.get('/api/mail/supply')
export const saveMailSupply = (payload) => http.post('/api/mail/supply/config', payload)
export const refillMailSupply = (quantity) =>
  http.post('/api/mail/supply/refill', { quantity }, { timeout: 10 * 60 * 1000 })
export const importMailOrders = () =>
  http.post('/api/mail/supply/import_orders', {}, { timeout: 5 * 60 * 1000 })

export const exportToPanel = (email, targets) =>
  http.post('/api/registered/export_to_panel', { email, targets })

// ──────────────── 自动跑号 auto-loop ────────────────
export const autoStart = (payload) => http.post('/api/auto/start', payload)
export const autoPause = () => http.post('/api/auto/pause')
export const autoResume = () => http.post('/api/auto/resume')
export const autoStop = () => http.post('/api/auto/stop')
export const autoStatus = () => http.get('/api/auto/status')
