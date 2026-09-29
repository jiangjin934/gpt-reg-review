import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

// 构建产物直接输出到 ../static，交给 FastAPI（未来换 Go 的 Gin 同样一行伺服）。
// dev 模式下把 /api 代理到本地 FastAPI，方便热更新开发。
// 按需引入 Element Plus 组件/指令（importStyle:false → 保留全量 CSS，仅 tree-shake JS）。
export default defineConfig({
  plugins: [
    vue(),
    AutoImport({ resolvers: [ElementPlusResolver({ importStyle: false })] }),
    Components({ resolvers: [ElementPlusResolver({ importStyle: false })] }),
  ],
  // FastAPI 在 /static 挂载静态资源，index.html 在 / 返回，故 base 用 /static/
  base: '/static/',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: '../static',
    // 保留旧构建产物：前端是单页应用，用户浏览器里可能还挂着上一版页面，
    // 它的路由分块是按内容哈希懒加载的。构建时清空输出目录会让旧页面
    // 加载不到自己的分块 → 白屏（实测踩过）。保留旧文件后，老页面在新版本
    // 构建后仍能正常工作，直到用户自己刷新。
    emptyOutDir: false,
    chunkSizeWarningLimit: 1500,
  },
  server: {
    port: 5666,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8765',
        changeOrigin: true,
      },
    },
  },
})
