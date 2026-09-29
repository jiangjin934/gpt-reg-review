<script setup>
import { computed, onActivated, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  listRegistered, getRegistered, deleteRegistered,
  bulkDeleteRegistered, bulkDeleteAccounts,
  checkoutCapability,
  listExportFormats, exportRegistered, updateCredentials,
  getRegisteredMeta, refreshRegisteredTokens,
  checkRegisteredAt, getCheckoutSummary,
} from '@/api/register'
import { copyText, fmtTime } from '@/api/request'
import { useFormStore, proxyText } from '@/stores/form'
import { useProxyStore } from '@/stores/proxy'
import { useRuntimeStore } from '@/stores/runtime'
import StatusDot from '@/components/StatusDot.vue'

const { form } = storeToRefs(useFormStore())
// 检测用的代理必须能从代理池里挑：以前这页只在代码里读 form.proxy，页面上
// 连个输入框都没有，主人在代理池换了密码，这里还在用 localStorage 里的旧值，
// 结果是 curl:(97) 代理鉴权被拒 → 静默降级直连 → 拿真实 IP 打 chatgpt.com。
const { list: proxyList } = storeToRefs(useProxyStore())
// 代理池上万条是常态：el-select 会把每个选项都实例化成组件（实测 1 万个选项
// 让本页进场时主线程卡住 26 秒），所以这里改用虚拟滚动的 el-select-v2，
// 只渲染可视区那几行。筛选/手输（allow-create）行为保持不变。
const proxyOptions = computed(() => proxyList.value.map((p) => ({ label: p, value: p })))
const runtime = useRuntimeStore()
// dataVersion 要走 storeToRefs 才保持响应（watch 用）；bumpData 是 action，直接从
// store 实例上取 —— storeToRefs 只转 state/getter，把 action 解构出来会丢 this。
const { dataVersion } = storeToRefs(runtime)

// 每页条数可调（主人反馈：固定 20 一页不够用）。存 localStorage，
// 刷新页面后保持上次选择。
// 低内存机器（本机 8G，浏览器一多只剩 1~2G）渲染 200 行 × 15 列很吃力，
// 之前一次渲染进程崩溃就是这么来的。默认 50、上限 100。
const PAGE_SIZE_OPTIONS = [20, 50, 100]
const pageSize = ref(
  Math.min(100, Math.max(1, Number(localStorage.getItem('reg.pageSize')) || 50)),
)
const rows = ref([])
const total = ref(0)
const page = ref(1)
const filter = ref('all')
const selected = ref([])
const loading = ref(false)
const checkResult = ref('')

// ── 轻量元数据（国家 / 指纹版本 / 流量 / AT 过期）──
// 由 /api/registered/meta 一次全量返回，本地按 email 映射到表格行。
// 后端没重启（旧版本没有这个接口）时静默降级：列显示「—」，不影响其他功能。
const metaMap = ref({})
const metaReady = ref(false)
const refreshingTokens = ref(false)
let metaLoadedAt = 0
let metaLoadedKey = ''

async function loadMeta(force = false, emails = null) {
  // 只拉当前页需要的行；同一批邮箱 30 秒内不重复拉（翻回上一页也能命中缓存）
  const list = (emails || rows.value.map((r) => r.email) || []).filter(Boolean)
  const key = list.map((e) => String(e).toLowerCase()).sort().join(',')
  if (!force && key && key === metaLoadedKey && Date.now() - metaLoadedAt < 30000) return
  try {
    const { items } = await getRegisteredMeta(list)
    // 增量合并：翻页不会把已经拿到的元数据丢掉
    const map = { ...metaMap.value }
    for (const it of items || []) {
      if (it && it.email) map[String(it.email).toLowerCase()] = it
    }
    metaMap.value = map
    metaReady.value = true
    metaLoadedAt = Date.now()
    metaLoadedKey = key
  } catch (_) {
    // 404 = 后端还没重启到带 meta 接口的版本；保持 metaReady=false 显示占位。
    metaReady.value = false
  }
}

function metaOf(row) {
  return metaMap.value[String(row?.email || '').toLowerCase()] || null
}

function fmtBytes(n) {
  const v = Number(n || 0)
  if (!v) return ''
  if (v < 1024) return `${v} B`
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`
  return `${(v / 1024 / 1024).toFixed(2)} MB`
}

function trafficText(row) {
  const m = metaOf(row)
  if (!m) return ''
  const total = Number(m.traffic_rx || 0) + Number(m.traffic_tx || 0)
  return total ? fmtBytes(total) : ''
}

// AT 剩余有效期：秒级时间戳 → 「剩 3.2 天 / 已过期 1.5 天」。
// exp 缺失（0）说明 token 不是 JWT 或没取到，显示「—」。
function atLife(row) {
  const m = metaOf(row)
  const exp = Number(m?.at_exp || 0)
  if (!exp) return null
  const diff = exp - Date.now() / 1000
  const days = Math.abs(diff) / 86400
  return {
    expired: diff <= 0,
    text: diff <= 0
      ? `已过期 ${days < 1 ? '<1' : days.toFixed(1)} 天`
      : `剩 ${days < 1 ? '<1' : days.toFixed(1)} 天`,
  }
}

const PLUS_TYPE = {
  plus_eligible: 'success', plus_active: 'primary', free: 'warning',
  // token_invalid（401 且响应体没有封号措辞）仍与 banned 分开显示——判据不同，
  // 不能混成一个。但配色从橙改红：AT 未到期却 401 = 被吊销，实测多半就是封号，
  // 橙色（=号还在）会让主人以为重新登录就能救回来。
  token_invalid: 'danger',
  banned: 'danger', error: 'danger',
}
function plusOf(row) { return row.plus_check || null }

async function load(resetPage) {
  if (resetPage) page.value = 1
  loading.value = true
  try {
    const { items, total: t } = await listRegistered({
      limit: pageSize.value, offset: (page.value - 1) * pageSize.value, filter: filter.value,
    })
    rows.value = items
    total.value = t
    loadMeta(false, items.map((r) => r.email))   // 只拉当前页
    loadZeroSummary()   // 0 元可领汇总（支付能力探测的结论）
  } catch (e) { ElMessage.error(e.message) }
  finally { loading.value = false }
}

// 勾选了就用勾选的；没勾选就是「全部」——按当前筛选条件跨页把邮箱取全。
// 上限 500 防止手滑把几千个号一次性打出去（探测/重登都带外部请求）。
const BULK_SCOPE_CAP = 500

async function collectTargetEmails() {
  if (selected.value.length) {
    return { emails: selected.value.map((r) => r.email), scope: 'selected' }
  }
  return { emails: await collectFilteredEmails(BULK_SCOPE_CAP), scope: 'all' }
}

// ── 检测 AT 状态：过期的自动重新获取 ──
// 后端只解 access_token 的 JWT exp（不联网、瞬时完成），把已经过期的号直接走协议
// 重登换新凭证（本地密码 + 2FA）；没到期的只报告剩余时间，不碰任何凭证。
// 后端单次上限 50 个，所以这里按 50 一批循环。
async function doCheckAt() {
  let target
  try { target = await collectTargetEmails() }
  catch (e) { ElMessage.error('读取号列表失败: ' + e.message); return }
  const { emails, scope } = target
  if (!emails.length) { ElMessage.info('当前筛选下没有可检测的号'); return }
  const scopeText = scope === 'selected' ? `选中的 ${emails.length} 个` : `全部 ${emails.length} 个`
  if (!(await confirm(
    `检测 ${scopeText}号的 AT 状态？\n\n` +
    '已过期的号会用本地密码 + 2FA 重新登录换取新 AT；未过期的只报告剩余时间。\n' +
    '此操作不改密码、不动 2FA、不改注册时间。',
  ))) return

  refreshingTokens.value = true
  const CHUNK = 50
  let checked = 0, validN = 0, expiredN = 0, unknownN = 0, okN = 0, failN = 0
  const failures = []
  try {
    for (let i = 0; i < emails.length; i += CHUNK) {
      const batch = emails.slice(i, i + CHUNK)
      checkResult.value =
        `检测 AT 状态… ${Math.min(i + batch.length, emails.length)}/${emails.length}`
      const r = await checkRegisteredAt({
        emails: batch,
        proxy: proxyText(form.value),
        otp_timeout: Math.max(60, Math.min(600, Number(form.value.otpTimeout) || 180)),
        refresh_expired: true,
      })
      checked += r.checked || 0
      validN += (r.valid || []).length
      expiredN += (r.expired || []).length
      unknownN += (r.unknown || []).length
      okN += r.refresh?.succeeded || 0
      failN += r.refresh?.failed || 0
      for (const x of r.refresh?.results || []) if (!x.ok) failures.push(x)
    }
    const parts = [`检测 ${checked} 个：正常 ${validN}`]
    if (expiredN) parts.push(`过期 ${expiredN}（已刷新 ${okN}${failN ? `，失败 ${failN}` : ''}）`)
    if (unknownN) parts.push(`${unknownN} 个无法判断`)
    checkResult.value = parts.join(' · ')
    if (failN) {
      ElMessage.warning(
        `刷新完成：成功 ${okN}，失败 ${failN}` +
        (failures[0] ? `；首个失败 ${failures[0].email}: ${failures[0].error}` : ''),
      )
    } else if (expiredN) {
      ElMessage.success(`检测到 ${expiredN} 个已过期的号，已全部刷新`)
    } else if (unknownN && !validN) {
      ElMessage.warning(`这 ${unknownN} 个号的 AT 不是 JWT，无法本地判断是否过期`)
    } else {
      ElMessage.success('AT 状态正常，没有需要刷新的号')
    }
    await loadMeta(true)
    await load()
  } catch (e) {
    checkResult.value = ''
    const detail = e.response?.data?.detail
    ElMessage.error('AT 检测失败: ' + (typeof detail === 'string' ? detail : e.message))
  } finally { refreshingTokens.value = false }
}

// ── 0 元可领汇总 ──
// 全库口径来自后端（扫 extra_json 里的探测结论），本页口径直接数表格里那几行，
// 这样翻页/筛选时顶部提醒跟着变，不会拿全库数字骗人。
const zeroSummary = ref(null)
const pageZeroCount = computed(
  () => rows.value.filter((r) => checkoutLabel(r).text.includes('可领')).length,
)

async function loadZeroSummary() {
  try { zeroSummary.value = await getCheckoutSummary() }
  catch (_) { /* 后端还是旧版本时静默降级 */ }
}

// ── UPI 支付金额（来自 int31.space 支付能力探测）──
// 探测结论存在每个号的 plus_check.checkout 里：amount_minor 是最小货币单位
// （分），currency 是币种，payment_method_types 说明支持哪些支付方式。
// 0 元 = 真可领试用；有金额 = 该号发起 checkout 实际要付的钱。
const CHECKOUT_CURRENCY_SYMBOL = { inr: '₹', usd: '$', eur: '€' }

function checkoutOf(row) {
  return row?.plus_check?.checkout || null
}

function fmtCheckoutAmount(checkout) {
  const minor = Number(checkout?.amount_minor)
  if (!Number.isFinite(minor)) return '—'
  const symbol = CHECKOUT_CURRENCY_SYMBOL[String(checkout?.currency || '').toLowerCase()] || ''
  const amount = (minor / 100).toFixed(2)
  return `${symbol}${amount}`
}

function checkoutLabel(row) {
  const checkout = checkoutOf(row)
  if (!checkout) return { text: '未探测', type: 'info' }
  // 出口不通不是账号结论：探测侧连不上代理时金额根本没读到，
  // 显示「出口不通」而不是「探测失败」，免得被当成该号不能付款。
  if (checkout.failure_type === 'CheckoutTransportException') {
    return { text: '出口不通', type: 'warning' }
  }
  if (checkout.failure_type) return { text: '探测失败', type: 'danger' }
  const methods = (checkout.payment_methods || []).map((m) => String(m).toLowerCase())
  if (methods.length && !methods.includes('upi')) {
    return { text: `${fmtCheckoutAmount(checkout)} 无UPI`, type: 'warning' }
  }
  if (Number(checkout.amount_minor) === 0) {
    return { text: '₹0.00 可领', type: 'success' }
  }
  return { text: fmtCheckoutAmount(checkout), type: 'primary' }
}

// 0 元可领 = 探测成功 + 支持 UPI + 金额为 0（与顶部汇总、列高亮同一个口径）
function isZeroCheckout(row) {
  return checkoutLabel(row).text.includes('可领')
}

// 支付能力探测（印度静态出口）：拿真实 checkout 金额，判断是不是真 0 元可领
const capabilityBusy = ref(false)

async function doCheckoutCapability() {
  let target
  try { target = await collectTargetEmails() }
  catch (e) { ElMessage.error('读取号列表失败: ' + e.message); return }
  const { emails, scope } = target
  if (!emails.length) { ElMessage.info('当前筛选下没有可探测的号'); return }
  const scopeText = scope === 'selected' ? `选中的 ${emails.length} 个` : `全部 ${emails.length} 个`
  if (!(await confirm(
    `对${scopeText}号跑支付能力探测？\n\n` +
    '每个号会用印度静态出口实探一次 0 元 checkout，逐个执行、比较慢；\n' +
    '服务端限流时会自动停下，剩下的下次再探。',
  ))) return

  capabilityBusy.value = true
  const CHUNK = 20          // 后端单次上限 20 个
  let completed = 0, total = 0
  const lines = []
  const dead = []
  try {
    for (let i = 0; i < emails.length; i += CHUNK) {
      const batch = emails.slice(i, i + CHUNK)
      checkResult.value =
        `支付能力探测中… ${Math.min(i + batch.length, emails.length)}/${emails.length}`
      const r = await checkoutCapability(batch)
      total += r.total || 0
      completed += r.completed || 0
      for (const x of r.results || []) {
        if (x.transport_failed) dead.push(x.email)
        lines.push(
          `${x.email}: ${x.free_trial
            ? '₹0 可领'
            : (x.amount_minor != null
              ? `${(Number(x.amount_minor) / 100).toFixed(2)} ${x.currency || ''}`
              : (x.failure_type || x.error || x.status || '?'))}`,
        )
      }
    }
    checkResult.value = lines.join('；')
    if (completed === 0 && dead.length) {
      // 一个金额都没读到，而且原因都是出口不通 —— 问题在链路不在号
      ElMessage.error(`出口不通，未取得任何金额（${dead.length} 个号）。先确认印度出口可用再重试`)
    } else if (completed === 0 && total > 0) {
      const detail = lines.slice(0, 3).join('；')
      ElMessage.error(`探测失败：${detail.slice(0, 200)}`)
    } else {
      ElMessage.success(
        `探测完成：成功 ${completed} / ${total}` + (dead.length ? `，${dead.length} 个出口不通` : ''),
      )
    }
    await load()
  } catch (e) {
    checkResult.value = lines.join('；')
    const detail = e.response?.data?.detail
    const text = typeof detail === 'string'
      ? detail
      : (detail ? JSON.stringify(detail).slice(0, 200) : e.message)
    ElMessage.error('探测失败: ' + text)
  } finally { capabilityBusy.value = false }
}

// ── 导出勾选的号 ──
// 格式清单来自后端 export_formats.py（账号+密码、+2FA、+AT、+取件url…），
// 以后加格式只改后端那一个文件，前端一行都不用动。
async function doExportSelected(fmt) {
  const emails = selected.value.map((r) => r.email)
  if (!emails.length) { ElMessage.info('请先勾选要导出的号'); return }
  exporting.value = true
  try {
    const r = await exportRegistered({ format: fmt.id, emails })
    exportedEmails.value = (r.emails || []).filter(Boolean)
    if (r.mode === 'download') {
      saveBlob(b64ToBytes(r.b64), r.filename, r.mime)
      ElMessage.success(`已下载 ${r.filename}（${r.count} 个号）`)
      return
    }
    exportText.value = r.text || ''
    exportCount.value = r.count || 0
    exportFilename.value = r.filename || 'export.txt'
    exportLabel.value = r.label || fmt.label
    exportVisible.value = true
  } catch (e) { ElMessage.error('导出失败: ' + e.message) }
  finally { exporting.value = false }
}

// ── 按筛选 / 按数量导出 ──
// 原来的导出只有「选中」和「全部（跨页）」两个口子，主人要的是：
//   ① 按当前筛选条件导出（例如只导 token_invalid 的号）；
//   ② 只导前 N 条，不用把几千个号全拖下来。
// 实现：先按筛选分页把 email 列表拉全（只取 email，轻量），再交给
// 后端导出接口（它本来就支持按 emails 列表导出）。
const scopeVisible = ref(false)
const scopeFormatId = ref('')
const scopeRange = ref('filter')     // filter | selected
const scopeCountMode = ref('all')    // all | limit
const scopeCount = ref(100)
const scopeBusy = ref(false)

const FILTER_LABELS = {
  all: '全部', unchecked: '未检测', free: 'Free', plus: '可领Plus',
  banned: '已封号', token_invalid: '凭证失效',
}
const scopeFilterLabel = computed(() => FILTER_LABELS[filter.value] || filter.value)

function openScopeExport() {
  loadExportFormats()
  if (!scopeFormatId.value) scopeFormatId.value = exportFormats.value[0]?.id || ''
  if (!selected.value.length && scopeRange.value === 'selected') scopeRange.value = 'filter'
  scopeVisible.value = true
}

async function collectFilteredEmails(limit) {
  const out = []
  const pageLimit = 500
  let offset = 0
  for (let guard = 0; guard < 40 && out.length < limit; guard += 1) {
    const { items, total } = await listRegistered({
      limit: pageLimit, offset, filter: filter.value,
    })
    if (!items || !items.length) break
    for (const it of items) {
      if (it?.email) out.push(it.email)
      if (out.length >= limit) break
    }
    offset += items.length
    if (offset >= (total || 0)) break
  }
  return out.slice(0, limit)
}

async function doScopeExport() {
  const fmt = exportFormats.value.find((f) => f.id === scopeFormatId.value)
  if (!fmt) { ElMessage.warning('请选择导出格式'); return }
  scopeBusy.value = true
  try {
    let emails = []
    if (scopeRange.value === 'selected') {
      emails = selected.value.map((r) => r.email)
    } else {
      const want = scopeCountMode.value === 'limit'
        ? Math.max(1, Math.min(100000, Number(scopeCount.value) || 1))
        : 100000
      emails = await collectFilteredEmails(want)
    }
    if (!emails.length) { ElMessage.info('当前范围没有可导出的号'); return }
    exporting.value = true
    const r = await exportRegistered({ format: fmt.id, emails })
    exportedEmails.value = (r.emails || []).filter(Boolean)
    if (r.mode === 'download') {
      saveBlob(b64ToBytes(r.b64), r.filename, r.mime)
      ElMessage.success(`已下载 ${r.filename}（${r.count} 个号）`)
    } else {
      exportText.value = r.text || ''
      exportCount.value = r.count || 0
      exportFilename.value = r.filename || 'export.txt'
      exportLabel.value = r.label || fmt.label
      exportVisible.value = true
    }
    scopeVisible.value = false
  } catch (e) {
    ElMessage.error('导出失败: ' + e.message)
  } finally {
    scopeBusy.value = false
    exporting.value = false
  }
}

// customClass 里的 pre-line 让消息里的 \n 真的换行。
// 不用 dangerouslyUseHTMLString：消息里会拼邮箱、文件名这些数据，走 HTML 等于开 XSS 口子。
async function confirm(msg) {
  try {
    await ElMessageBox.confirm(msg, '确认', {
      type: 'warning', confirmButtonText: '确定', cancelButtonText: '取消',
      customClass: 'confirm-multiline',
    })
    return true
  }
  catch (_) { return false }
}
async function deleteOne(email) {
  if (!(await confirm(`删除 ${email} 的凭证？`))) return
  try { await deleteRegistered(email); ElMessage.success('已删除'); load() }
  catch (e) { ElMessage.error(e.message) }
}
async function deleteSelected() {
  const emails = selected.value.map((r) => r.email)
  if (!emails.length) return
  if (!(await confirm(`确定删除选中的 ${emails.length} 条凭证？(不可恢复)`))) return
  try { const r = await bulkDeleteRegistered({ emails }); ElMessage.success(`已删除 ${r.deleted} 条`); load() }
  catch (e) { ElMessage.error(e.message) }
}
async function deleteAll() {
  if (!(await confirm('这会清空注册结果表里的所有凭证！邮箱列表不受影响，确定？'))) return
  if (!(await confirm('再次确认：真的要删除全部凭证吗？此操作不可恢复！'))) return
  try { const r = await bulkDeleteRegistered({ all: true }); ElMessage.success(`已清空 ${r.deleted} 条`); load() }
  catch (e) { ElMessage.error(e.message) }
}

// ──────────── 批量导出 ────────────
// 格式清单来自后端 export_formats.py，下拉菜单是 v-for 出来的：
// 以后加格式只改后端那一个文件，这里一行都不用动。
const exportFormats = ref([])
const exporting = ref(false)
const exportVisible = ref(false)
const exportText = ref('')
const exportCount = ref(0)
const exportFilename = ref('')
const exportLabel = ref('')
// 这一批导出的到底是哪些号 —— 「下载并删除」照着它删，来自后端 r.emails。
// 为什么要后端给、为什么在导出那一刻就存下来：
//   · 「导出全部」是跨页的，前端手里只有当前页 20 行，自己凑必漏；
//   · 弹窗开着的时候主人可能改勾选、翻页，后台自动跑号还会插进新号进来，
//     那时再去读 selected/表格，删的就不是刚下载的那批了。
const exportedEmails = ref([])
const deletingExported = ref(false)

async function loadExportFormats() {
  if (exportFormats.value.length) return
  try {
    const { formats } = await listExportFormats()
    exportFormats.value = formats || []
  } catch (e) { ElMessage.error('加载导出格式失败: ' + e.message) }
}

function b64ToBytes(b64) {
  const bin = atob(b64 || '')
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

function saveBlob(data, filename, mime) {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime || 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function downloadExport() {
  saveBlob(exportText.value, exportFilename.value, 'text/plain;charset=utf-8')
}

// ──────────── 下载并删除 ────────────
// 主人的原话：「不然分不清楚越堆越多」。导出的 txt 里邮箱/密码/2FA/取件url 都齐了，
// 这两张表就没有留存价值了，一起清掉。
//
// ⚠️ 顺序**必须**是「先下载、再确认、最后删」：
//    删库是不可恢复的，而浏览器下载可能被拦（弹窗拦截 / 用户点了取消 / 磁盘满）。
//    先把文件落盘再问，主人是在**手里已经有 txt** 的前提下点的确认。
//    确认框里再报一遍将要删的两张表各多少条，删完之前还有最后一次反悔机会。
async function downloadAndDelete() {
  downloadExport()

  const emails = exportedEmails.value
  if (!emails.length) {
    ElMessage.warning('这批导出没有拿到 email 列表，只下载不删除')
    return
  }

  const ok = await confirm(
    `已下载 ${exportFilename.value}。\n\n` +
    `现在删除这 ${emails.length} 个号：\n` +
    `  · 注册结果（凭证、2FA secret）\n` +
    `  · 邮箱列表（号池那一行，含取件链接）\n\n` +
    `删掉后只剩刚下载的 txt 这一份，不可恢复。确定？`,
  )
  if (!ok) return

  deletingExported.value = true
  try {
    // 两张表分别删。先删注册结果：它是主人真正在看的那张表，
    // 万一号池那边报错（比如这批号根本不是号池导入的、压根没有对应行），
    // 至少结果表已经清干净了，不会出现"删了一半还看得见"。
    const r1 = await bulkDeleteRegistered({ emails })
    let poolDeleted = 0
    try {
      const r2 = await bulkDeleteAccounts({ emails })
      poolDeleted = r2.deleted || 0
    } catch (e) {
      // 号池删失败不算整体失败：凭证已经清掉了，主人该知道的是号池还剩着
      ElMessage.warning('注册结果已删，但邮箱列表删除失败: ' + e.message)
    }
    ElMessage.success(`已删除：注册结果 ${r1.deleted} 条 / 邮箱列表 ${poolDeleted} 条`)
    exportVisible.value = false
    exportedEmails.value = []
    selected.value = []
    load(true)          // 回第一页：这一批没了，停在旧页码多半是空页
    runtime.bumpData()  // 通知「邮箱列表」那一页也刷新，否则主人切过去还看得到已删的号
  } catch (e) {
    ElMessage.error('删除失败: ' + e.message)
  } finally {
    deletingExported.value = false
  }
}

// 凭证弹窗
const credVisible = ref(false)
const credEmail = ref('')
const credData = ref(null)
// totp_secret 放最前：它是唯一「服务端取不回」的字段，弹窗一打开就要能看到
const CRED_KEYS = ['totp_secret', 'totp_factor_id', 'access_token', 'session_token', 'id_token', 'device_id', 'csrf_token', 'cookie_header', 'password']
const credRows = computed(() => {
  if (!credData.value) return []
  return CRED_KEYS.filter((k) => credData.value[k]).map((k) => ({ key: k, val: credData.value[k] }))
})
async function viewCred(email) {
  try {
    const { data } = await getRegistered(email)
    credData.value = data
    credEmail.value = email
    credVisible.value = true
  } catch (e) { ElMessage.error('加载凭证失败: ' + e.message) }
}
async function copyCell(email, field) {
  try {
    const { data } = await getRegistered(email)
    const val = data[field] || ''
    if (!val) { ElMessage.warning(`${field} 为空`); return }
    await copyText(val)
  } catch (e) { ElMessage.error('加载凭证失败: ' + e.message) }
}
function copyAllJson() {
  if (credData.value) copyText(JSON.stringify(credData.value, null, 2))
}

// ── 手动编辑凭证 ──
// 只改本地库，不同步 OpenAI。改完的值会被登录流程直接用上
// （registrar 的 account_callback 走 db.get_registered，不区分数据来源）。
const editVisible = ref(false)
const editSaving = ref(false)
const editEmail = ref('')
const editPassword = ref('')
const editSecret = ref('')
// 打开弹窗时的原值，用来判断哪些字段真被改过（没改的不传，后端就不碰）
const editOrigPassword = ref('')
const editOrigSecret = ref('')

function openEdit(row) {
  editEmail.value = row.email
  editPassword.value = row.password || ''
  editSecret.value = row.totp_secret || ''
  editOrigPassword.value = row.password || ''
  editOrigSecret.value = row.totp_secret || ''
  editVisible.value = true
}

async function saveEdit() {
  const pw = editPassword.value
  const sec = editSecret.value.trim()
  const payload = { email: editEmail.value }
  // 只把真正改动过的字段传给后端 —— 没动的字段不传，后端就不会碰它
  if (pw !== editOrigPassword.value) payload.password = pw
  if (sec !== editOrigSecret.value) payload.totp_secret = sec
  if (payload.password === undefined && payload.totp_secret === undefined) {
    ElMessage.info('没有改动')
    editVisible.value = false
    return
  }
  // secret 是唯一「服务端取不回」的凭证：覆盖掉原值 = 该号 2FA 永久锁死。
  // 只在「原本就有 secret」且「确实要改」时拦一道，新填不打扰。
  if (payload.totp_secret !== undefined && editOrigSecret.value) {
    try {
      await ElMessageBox.confirm(
        `该账号已有 2FA secret：\n${editOrigSecret.value}\n\n` +
        '覆盖后原 secret 将永久丢失，服务端取不回。\n' +
        '若原 secret 仍是账号上生效的那个，覆盖会导致该号 2FA 永远登不上。',
        '确认覆盖 2FA secret？',
        { type: 'warning', confirmButtonText: '确认覆盖', cancelButtonText: '取消' },
      )
    } catch { return }
  }
  editSaving.value = true
  try {
    const r = await updateCredentials(payload)
    ElMessage.success(`已保存：${(r.changed || []).join(' + ') || '无改动'}`)
    editVisible.value = false
    await load()
  } catch (e) {
    // 后端 400 会带具体原因（如「TOTP secret 含非法字符」），原样透出
    ElMessage.error('保存失败: ' + (e.response?.data?.detail || e.message))
  } finally { editSaving.value = false }
}

watch(page, () => load())
watch(pageSize, (v) => {
  localStorage.setItem('reg.pageSize', String(v))
  page.value = 1
  load()
})
// 自动跑号期间 run_started/run_finished 事件很密（20 并发），每次都重拉整页
// 会让页面发卡 —— 这里节流到最多 5 秒一次。
let lastAutoReload = 0
watch(dataVersion, () => {
  const now = Date.now()
  if (now - lastAutoReload < 10000) return
  lastAutoReload = now
  load()
})
onActivated(() => load())
</script>
<template>
  <div class="page">
    <el-card shadow="never">
      <template #header><span class="section-title" style="margin: 0">注册结果</span></template>

      <!-- 0 元提醒：支付能力探测出来的「可 0 元领」号，顶部给个总数 -->
      <el-alert
        v-if="zeroSummary && zeroSummary.free"
        type="success" :closable="false" show-icon style="margin-bottom: 12px"
        :title="`0 元可领：全库 ${zeroSummary.free} 个 · 本页 ${pageZeroCount} 个`"
        :description="`已探测 ${zeroSummary.probed}｜无 UPI ${zeroSummary.no_upi}｜探测失败 ${zeroSummary.failed}｜未探测 ${zeroSummary.unchecked}`"
      />
      <el-alert
        v-else-if="zeroSummary"
        type="info" :closable="false" show-icon style="margin-bottom: 12px"
        title="0 元可领：暂无"
        :description="`已探测 ${zeroSummary.probed} 个｜未探测 ${zeroSummary.unchecked} 个 —— 勾选号点「支付能力探测」后会在这里汇总。`"
      />

      <el-space wrap style="margin-bottom: 12px">
        <el-button @click="load(false)"><el-icon><Refresh /></el-icon>刷新</el-button>
        <el-select v-model="filter" style="width: 130px" @change="load(true)">
          <el-option label="全部" value="all" />
          <el-option label="未检测" value="unchecked" />
          <el-option label="Free" value="free" />
          <el-option label="可领Plus" value="plus" />
          <el-option label="已开通Plus" value="plus_activated" />
          <el-option label="已封号" value="banned" />
          <el-option label="凭证失效" value="token_invalid" />
        </el-select>
        <el-select-v2
          v-model="form.proxy" :options="proxyOptions" filterable clearable allow-create
          default-first-option :reserve-keyword="false" placeholder="检测代理（留空直连）"
          style="width: 260px"
        />
        <el-button
          type="success" plain
          :loading="refreshingTokens"
          @click="doCheckAt"
        >
          <el-icon><Odometer /></el-icon>检测AT状态 ({{ selected.length || '全部' }})
        </el-button>
        <el-divider direction="vertical" />
        <el-button
          type="warning" plain
          :loading="capabilityBusy"
          @click="doCheckoutCapability"
        >
          <el-icon><ScanSearch /></el-icon>支付能力探测(印度) ({{ selected.length || '全部' }})
        </el-button>
        <el-dropdown
          trigger="click"
          :disabled="!selected.length"
          @command="doExportSelected"
          @visible-change="(v) => v && loadExportFormats()"
        >
          <el-button :loading="exporting" :disabled="!selected.length">
            <el-icon><Download /></el-icon>导出选中 ({{ selected.length }})
            <el-icon class="el-icon--right"><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item v-for="f in exportFormats" :key="f.id" :command="f">
                {{ f.label }}
                <span v-if="f.note" class="hint" style="margin-left: 6px">{{ f.note }}</span>
              </el-dropdown-item>
              <el-dropdown-item v-if="!exportFormats.length" disabled>加载中...</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-button @click="openScopeExport">
          <el-icon><Download /></el-icon>按筛选导出…
        </el-button>
        <el-divider direction="vertical" />
        <el-button type="danger" plain :disabled="!selected.length" @click="deleteSelected">
          删除选中 ({{ selected.length }})
        </el-button>
        <el-button type="danger" plain @click="deleteAll">清空全部</el-button>
        <span class="hint">{{ checkResult }}</span>
      </el-space>

      <el-skeleton v-if="loading && !rows.length" :rows="6" animated style="padding: 8px 0" />
      <el-table
        v-else
        v-loading="loading" :data="rows" size="small" stripe
        @selection-change="(v) => (selected = v)"
      >
        <el-table-column type="selection" width="44" />
        <el-table-column prop="email" label="邮箱" min-width="180" show-overflow-tooltip />
        <!-- 注册国家：来自该号最近一次任务的出口探测（runs.exit_country），
             悬浮显示出口 IP 和当时的指纹版本。旧号或元数据接口未就绪时显示「—」。 -->
        <el-table-column label="国家" width="72" align="center">
          <template #default="{ row }">
            <el-tooltip
              v-if="metaOf(row)?.country"
              :content="`出口 ${metaOf(row).exit_ip || '?'}${metaOf(row).version ? ' · ' + metaOf(row).version : ''}`"
              placement="top"
            >
              <el-tag size="small" effect="plain">{{ metaOf(row).country }}</el-tag>
            </el-tooltip>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <!-- 密码直接明文列出：随机 16 位，是登录账号的必需品，
             藏进「查看凭证」弹窗每次都要多点两下。列表接口本来就在返回它。
             图标放在文字**后面**：放前面会把值整体右推 27px（见 .cell-copy 注释）。 -->
        <el-table-column label="密码" min-width="160">
          <template #default="{ row }">
            <el-button
              v-if="row.password" size="small" text type="primary"
              class="cell-copy mono" @click="copyText(row.password)"
            >
              {{ row.password }}<el-icon class="ico"><CopyDocument /></el-icon>
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <!-- 2FA secret 同样明文列出：它是唯一「服务端取不回」的凭证，
             丢了这个号就永久锁死，必须一眼看见、一点就能复制。
             min-width 必须装得下 32 位 base32：.cell 带 overflow:hidden，
             宽度不够会**无声截断**，肉眼核对时看到的是残缺值。实测需 ~250px。 -->
        <el-table-column label="2FA" min-width="260">
          <template #default="{ row }">
            <el-button
              v-if="row.totp_secret" size="small" text type="warning"
              class="cell-copy mono" @click="copyText(row.totp_secret)"
            >
              {{ row.totp_secret }}<el-icon class="ico"><CopyDocument /></el-icon>
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="Plus状态" width="110">
          <template #default="{ row }">
            <StatusDot v-if="plusOf(row)" :type="PLUS_TYPE[plusOf(row).status] || 'info'" :text="plusOf(row).label" />
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <!-- UPI 支付金额：int31.space 支付能力探测的真实结论（印度出口实测），
             0 元 = 真可领试用；有数字 = 该号发起 checkout 实际要付的钱。
             0 元用深色实心标签 + 加粗，滚动列表时一眼能挑出来。 -->
        <el-table-column label="UPI 金额" width="116" align="center">
          <template #default="{ row }">
            <el-tooltip
              v-if="checkoutOf(row)"
              :content="`来源 ${checkoutOf(row).source || 'int31'} · 状态 ${checkoutOf(row).status || '-'} · ${checkoutOf(row).failure_type || 'OK'} · 支付方式 ${(checkoutOf(row).payment_methods || []).join('/') || '-'} · 实体 ${checkoutOf(row).processor_entity || '-'} · 出口 ${checkoutOf(row).provider_country || '-'}`"
              placement="top"
            >
              <el-tag
                size="small"
                :type="checkoutLabel(row).type"
                :effect="isZeroCheckout(row) ? 'dark' : 'plain'"
                :class="isZeroCheckout(row) ? 'zero-hit' : ''"
              >
                {{ checkoutLabel(row).text }}
              </el-tag>
            </el-tooltip>
            <span v-else class="hint">{{ checkoutLabel(row).text }}</span>
          </template>
        </el-table-column>
        <!-- AT 剩余有效期：直接解 access_token 的 JWT exp，不用逐个查凭证。
             已过期的标红 —— 这类号要么重登刷新（工具栏「重新获取 AT」），
             要么按 token_invalid 处理。 -->
        <el-table-column label="AT 有效期" width="104" align="center">
          <template #default="{ row }">
            <el-tag
              v-if="atLife(row)"
              size="small" effect="plain"
              :type="atLife(row).expired ? 'danger' : 'success'"
            >{{ atLife(row).text }}</el-tag>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="access" width="100" align="center">
          <template #default="{ row }">
            <el-button v-if="row.at_len > 0" size="small" text type="primary" @click="copyCell(row.email, 'access_token')">
              <el-icon><CopyDocument /></el-icon>{{ row.at_len }}
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="session" width="100" align="center">
          <template #default="{ row }">
            <el-button v-if="row.st_len > 0" size="small" text type="primary" @click="copyCell(row.email, 'session_token')">
              <el-icon><CopyDocument /></el-icon>{{ row.st_len }}
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <!-- 流量：该号最近一次任务经 HTTP 会话的收发字节合计（近似口径，
             不含请求头/连接开销）。悬浮看收发拆分。 -->
        <el-table-column label="流量" width="78" align="center">
          <template #default="{ row }">
            <el-tooltip
              v-if="trafficText(row)"
              :content="`收 ${fmtBytes(metaOf(row).traffic_rx) || '0 B'} / 发 ${fmtBytes(metaOf(row).traffic_tx) || '0 B'}（近似口径）`"
              placement="top"
            >
              <span class="mono" style="font-size: 12px">{{ trafficText(row) }}</span>
            </el-tooltip>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="时间" width="140">
          <template #default="{ row }">
            {{ fmtTime(row.created_at || row.plus_updated_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" text @click="viewCred(row.email)">查看凭证</el-button>
            <el-button size="small" text type="warning" @click="openEdit(row)">编辑</el-button>
            <el-button size="small" text type="danger" @click="deleteOne(row.email)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty description="暂无注册结果，去「单次注册」或「全自动批量」跑号" :image-size="70" />
        </template>
      </el-table>
      <div style="display: flex; justify-content: center; margin-top: 14px">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :page-sizes="PAGE_SIZE_OPTIONS"
          :total="total"
          layout="prev, pager, next, sizes, total, jumper" background
        />
      </div>

      <!-- 按筛选 / 按数量导出：原来的导出只有「选中 / 全部」两个口径，
           现在可以按当前筛选条件导出，也可以只取前 N 条。 -->
      <el-dialog v-model="scopeVisible" title="按筛选导出" width="560px" top="10vh">
        <el-form label-position="top">
          <el-form-item label="范围">
            <el-radio-group v-model="scopeRange">
              <el-radio value="filter">当前筛选（{{ scopeFilterLabel }}）</el-radio>
              <el-radio value="selected" :disabled="!selected.length">
                仅选中（{{ selected.length }}）
              </el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item v-if="scopeRange === 'filter'" label="数量">
            <el-radio-group v-model="scopeCountMode">
              <el-radio value="all">全部（跨页）</el-radio>
              <el-radio value="limit">前 N 条</el-radio>
            </el-radio-group>
            <el-input-number
              v-if="scopeCountMode === 'limit'"
              v-model="scopeCount" :min="1" :max="100000" :step="10"
              style="margin-left: 12px"
            />
          </el-form-item>
          <el-form-item label="导出格式">
            <el-select v-model="scopeFormatId" style="width: 100%">
              <el-option
                v-for="f in exportFormats" :key="f.id"
                :label="f.label + (f.note ? ' · ' + f.note : '')" :value="f.id"
              />
            </el-select>
          </el-form-item>
        </el-form>
        <div class="hint">导出只生成文件 / 预览，不会删除任何记录。</div>
        <template #footer>
          <el-button @click="scopeVisible = false">取消</el-button>
          <el-button type="primary" :loading="scopeBusy" @click="doScopeExport">导出</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="exportVisible" width="720px" top="8vh">
        <template #header>
          <div style="display: flex; align-items: center; gap: 12px">
            <span style="font-weight: 600">导出 · {{ exportLabel }}</span>
            <el-tag size="small" type="info">共 {{ exportCount }} 行</el-tag>
          </div>
        </template>
        <el-input
          :model-value="exportText" type="textarea" :rows="14" readonly
          class="mono export-area"
        />
        <template #footer>
          <el-button @click="copyText(exportText)">
            <el-icon><CopyDocument /></el-icon>复制全部
          </el-button>
          <el-button type="primary" @click="downloadExport">
            <el-icon><Download /></el-icon>下载 {{ exportFilename }}
          </el-button>
          <!-- 危险动作放最右、danger 色，和左边的纯下载拉开距离，避免手滑。
               先下载文件、再弹二次确认，确认框里会报清楚要删哪两张表各多少条。 -->
          <el-button
            type="danger" plain
            :loading="deletingExported"
            :disabled="!exportedEmails.length"
            @click="downloadAndDelete"
          >
            <el-icon><Delete /></el-icon>下载并删除这 {{ exportedEmails.length }} 个号
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="credVisible" :title="credEmail" width="760px" top="6vh">
        <template #header>
          <div style="display: flex; align-items: center; gap: 12px">
            <span class="mono" style="font-weight: 600">{{ credEmail }}</span>
            <el-button size="small" @click="copyAllJson">复制全部 JSON</el-button>
          </div>
        </template>
        <div v-for="r in credRows" :key="r.key" style="margin-bottom: 12px">
          <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px">
            <span class="mono" style="font-weight: 600; color: var(--dango-pink-dark)">{{ r.key }}</span>
            <el-tag size="small" type="info">len={{ r.val.length }}</el-tag>
            <el-button size="small" @click="copyText(r.val)">复制</el-button>
          </div>
          <el-input :model-value="r.val" type="textarea" :rows="2" readonly class="mono" />
        </div>
        <el-empty v-if="!credRows.length" description="无凭证字段" />
      </el-dialog>

      <!-- 手动编辑凭证：把外部已知的密码/2FA 补进来，或修正记录错误 -->
      <el-dialog v-model="editVisible" title="编辑凭证" width="560px" top="10vh">
        <el-alert
          type="warning" :closable="false" show-icon style="margin-bottom: 16px"
          title="仅修改本地记录，不会同步到 OpenAI"
          description="这里改密码不等于改了账号密码。填入的值会被登录流程直接使用。"
        />
        <el-form label-position="top">
          <el-form-item label="邮箱">
            <el-input :model-value="editEmail" class="mono" disabled />
          </el-form-item>
          <el-form-item label="密码">
            <el-input v-model="editPassword" class="mono" placeholder="留空表示该号无密码" />
          </el-form-item>
          <el-form-item label="2FA Secret">
            <el-input
              v-model="editSecret" class="mono"
              placeholder="base32，支持带空格/小写/otpauth:// 链接，会自动规范化"
            />
            <div class="hint" style="margin-top: 6px; line-height: 1.6">
              服务端取不回此值，覆盖后原 secret 永久丢失。清空则该号按无 2FA 处理。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="editVisible = false">取消</el-button>
          <el-button type="primary" :loading="editSaving" @click="saveEdit">保存</el-button>
        </template>
      </el-dialog>

    </el-card>
  </div>
</template>

<style scoped>
/* 表格里「点一下就复制」的明文单元格（密码 / 2FA secret）。
   :deep 是必需的：.el-button 由 Element Plus 渲染，scoped 的属性选择器打不到它。

   为什么要重置 padding —— Element Plus 有两个长得很像的类：
     .el-button--text  （旧版 type="text"）  padding 左右为 0
     .el-button.is-text（新版 text 属性）    继承 --small 的 5px 11px
   我们用的是后者，于是 11px padding + 12px 图标 + 4px 间隙 = 值被整体右推 27px，
   同列的表头和空值「—」都贴着 cell 左沿，一眼就看出错位。 */
:deep(.el-button.cell-copy.el-button--small) {
  padding: 0 6px 0 0;
  height: 20px;
  font-size: 12px;
}
/* 图标默认透明但**保留占位**：用 opacity 而不是 display:none，
   否则 hover 时图标撑开宽度会把文字挤得左右抖。 */
:deep(.cell-copy .ico) {
  margin-left: 5px;
  opacity: 0;
  transition: opacity 0.12s;
}
:deep(.cell-copy:hover .ico) { opacity: 0.65; }

/* 0 元可领：实心标签再加粗，滚动长列表时一眼能挑出来 */
.zero-hit {
  font-weight: 700;
  letter-spacing: 0.2px;
}
</style>

<!-- 非 scoped：ElMessageBox 是挂到 body 上的，不在本组件的 scope 属性范围内，
     scoped 样式打不到它。只作用在自家 customClass 上，不会污染别处的确认框。 -->
<style>
.confirm-multiline .el-message-box__message { white-space: pre-line; }
</style>
