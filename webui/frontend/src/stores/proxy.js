import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { getProxyPool, saveProxyPool } from '@/api/proxy'

const KEY = 'dango_proxy_pool_v1'
const OLD_FORM_KEY = 'gpt_outlook_register_form_v2'

function parseLines(s) {
  return String(s || '').split('\n').map((x) => normalizeProxy(x)).filter(Boolean)
}
function dedup(arr) {
  return [...new Set(arr)]
}

// 1024Proxy and similar vendors export host:port:user:pass.  Normalize that
// form at import time so the UI, the API probe, and the task allocator all
// operate on the same explicit SOCKS5H URL.
function normalizeProxy(value) {
  const text = String(value || '').trim()
  if (!text) return ''
  const scheme = text.match(/^([a-z][a-z0-9+.-]*):\/\//i)
  if (scheme) {
    const normalized = scheme[1].toLowerCase() === 'socks5'
      ? 'socks5h'
      : scheme[1].toLowerCase()
    return `${normalized}://${text.slice(scheme[0].length)}`
  }
  const parts = text.split(':')
  if (parts.length >= 4 && /^\d+$/.test(parts[1]) && parts[0] && parts[2]) {
    const host = parts[0]
    const port = parts[1]
    const user = encodeURIComponent(parts[2])
    const pass = encodeURIComponent(parts.slice(3).join(':'))
    return `socks5h://${user}:${pass}@${host}:${port}`
  }
  return text
}

// 代理池：独立管理的代理列表，localStorage 持久化。
// 自动跑号时按 worker 顺序轮流取用（后端 /api/auto/start 的 proxy_pool 字段）。
export const useProxyStore = defineStore('proxy', () => {
  let saved = []
  try { saved = JSON.parse(localStorage.getItem(KEY) || '[]') } catch (_) { saved = [] }
  // 从旧版「全自动批量」页的 autoProxyPool textarea 迁移一次
  if (!saved.length) {
    try {
      const old = JSON.parse(localStorage.getItem(OLD_FORM_KEY) || '{}')
      if (old.autoProxyPool) saved = dedup(parseLines(old.autoProxyPool))
    } catch (_) { /* ignore */ }
  }

  const list = ref(saved)
  const text = computed(() => list.value.join('\n'))
  const count = computed(() => list.value.length)

  // 服务端池子才是自动跑号读取的那份；localStorage 只当缓存。
  const serverReady = ref(false)
  let dirty = false
  let saveTimer = null

  async function persist() {
    try {
      await saveProxyPool(list.value.join('\n'), 'replace')
    } catch (_) { /* 服务端不可用时保留本地缓存 */ }
  }

  function schedulePersist() {
    dirty = true
    if (!serverReady.value) return
    if (saveTimer) clearTimeout(saveTimer)
    saveTimer = setTimeout(() => { persist() }, 400)
  }

  async function loadFromServer() {
    try {
      const r = await getProxyPool()
      const remote = dedup(parseLines(r.text || ''))
      if (!dirty && remote.length) {
        list.value = remote
      } else if (!remote.length && r.cleared) {
        // 服务端被明确清空过 → 本地缓存也跟着清，别把旧池子又迁回去
        list.value = []
      } else if (!remote.length && list.value.length) {
        // 服务端还没有池子：把本地缓存迁移上去
        await persist()
      }
      serverReady.value = true
      if (dirty) schedulePersist()
    } catch (_) { /* 拿不到服务端池子就继续用本地缓存 */ }
  }

  watch(list, (v) => {
    try { localStorage.setItem(KEY, JSON.stringify(v)) } catch (_) {}
  }, { deep: true })

  /** 用整段文本覆盖代理池（自动去重）。返回 { added, duplicated } 供提示。 */
  function setFromText(s) {
    const parsed = parseLines(s)
    const unique = dedup(parsed)
    list.value = unique
    schedulePersist()
    return { total: parsed.length, kept: unique.length, duplicated: parsed.length - unique.length }
  }

  /** 追加一批（去重合并）。 */
  function append(s) {
    const merged = dedup([...list.value, ...parseLines(s)])
    const added = merged.length - list.value.length
    list.value = merged
    schedulePersist()
    return { added }
  }

  function remove(proxy) {
    list.value = list.value.filter((x) => x !== proxy)
    schedulePersist()
  }
  function clear() {
    list.value = []
    schedulePersist()
  }

  loadFromServer()

  return { list, text, count, serverReady, setFromText, append, remove, clear, loadFromServer }
})

/**
 * 判断代理格式是否合法：[scheme://][user:pass@]host:port
 * 协议可省略——省略时 curl 按 HTTP 代理处理，所以裸写 host:port 也算合法。
 */
export function isValidProxy(p) {
  return /^((socks5h?|socks4|https?):\/\/)?\S+:\d+$/i.test(normalizeProxy(p))
}

/** 该代理生效的协议类型（用于提示：未写协议默认 http）。 */
export function proxyScheme(p) {
  const m = /^(socks5h?|socks4|https?):\/\//i.exec(normalizeProxy(p))
  return m ? m[1].toLowerCase() : 'http(默认)'
}
