import http from './request'

// 代理连通性测试（后端并发测试，可能耗时，单独放宽超时到 3 分钟）
export const testProxies = (proxies, timeout = 20) =>
  http.post('/api/proxy/test', { proxies, timeout }, { timeout: 180000 })

// 代理池服务端存储：页面和自动跑号共用同一份，避免 localStorage 与后端脱节。
export const getProxyPool = () => http.get('/api/proxy/pool')
export const saveProxyPool = (text, mode = 'replace') =>
  http.post('/api/proxy/pool', { text, mode })
