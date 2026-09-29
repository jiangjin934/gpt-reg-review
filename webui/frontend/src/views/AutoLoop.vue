<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { ElMessage } from 'element-plus'
import { autoStart, autoPause, autoResume, autoStop } from '@/api/register'
import {
  mailSupplyStatus, saveMailSupply, refillMailSupply, importMailOrders,
} from '@/api/register'
import { useFormStore, proxyText } from '@/stores/form'
import { useProxyStore } from '@/stores/proxy'
import { useRuntimeStore } from '@/stores/runtime'
import LogPanel from '@/components/LogPanel.vue'
import StatusDot from '@/components/StatusDot.vue'

const router = useRouter()
const { form } = storeToRefs(useFormStore())
const proxyStore = useProxyStore()
const { count: proxyCount } = storeToRefs(proxyStore)
const runtime = useRuntimeStore()
const { autoStatus } = storeToRefs(runtime)

// ── 自动供号（ReMail）：池子低于阈值时自动下单买新邮箱 ──
const supply = ref({ config: {}, available: 0, balance: '', active_orders: 0, usable_orders: 0 })
const supplyBusy = ref(false)

async function loadSupply() {
  try {
    supply.value = await mailSupplyStatus()
  } catch (_) { /* 后端没起或没配置时静默 */ }
}

async function saveSupply() {
  supplyBusy.value = true
  try {
    const cfg = supply.value.config || {}
    supply.value = await saveMailSupply({
      api_key: cfg.api_key,
      project_id: cfg.project_id,
      email_suffix: cfg.email_suffix,
      auto_buy: cfg.auto_buy,
      batch_size: cfg.batch_size,
      min_available: cfg.min_available,
    })
    ElMessage.success('自动供号配置已保存')
  } catch (e) {
    ElMessage.error('保存失败: ' + (e.response?.data?.detail || e.message))
  } finally { supplyBusy.value = false }
}

async function doRefill() {
  supplyBusy.value = true
  try {
    const r = await refillMailSupply()
    ElMessage.success(`补货完成：买入 ${r.bought || 0} 个，可用 ${r.available}`)
    await loadSupply()
  } catch (e) {
    ElMessage.error('补货失败: ' + (e.response?.data?.detail || e.message))
  } finally { supplyBusy.value = false }
}

async function doImportOrders() {
  supplyBusy.value = true
  try {
    const r = await importMailOrders()
    ElMessage.success(`已购订单导入：新增 ${r.inserted || 0} 个，可用 ${r.stats?.available ?? '?'}`)
    await loadSupply()
  } catch (e) {
    ElMessage.error('导入失败: ' + (e.response?.data?.detail || e.message))
  } finally { supplyBusy.value = false }
}

onMounted(loadSupply)

const st = computed(() => autoStatus.value.state || 'stopped')
const canStart = computed(() => st.value === 'stopped')
const canPause = computed(() => st.value === 'running')
const canResume = computed(() => st.value === 'paused')
const canStop = computed(() => st.value !== 'stopped')

const stateLabel = computed(() => ({
  stopped: '未运行', running: '运行中', paused: '已暂停',
}[st.value] || st.value))
const stateType = computed(() => ({
  stopped: 'info', running: 'success', paused: 'warning',
}[st.value] || 'info'))

const workers = computed(() => Array.isArray(autoStatus.value.workers) ? autoStatus.value.workers : [])

async function start() {
  try {
    await autoStart({
      proxy: proxyText(form.value),
      proxy_pool: proxyStore.text,
      concurrency: parseInt(form.value.autoConcurrency, 10) || 1,
      otp_timeout: Math.max(180, parseInt(form.value.otpTimeout, 10) || 180),
      want_access_token: true,
      want_session_token: true,
      want_refresh_token: form.value.wantRefreshToken,
      cool_down_seconds: parseFloat(form.value.autoCoolDown) || 0,
      target_count: parseInt(form.value.autoTargetCount, 10) || 0,
      // 批量默认绑 2FA（后端默认是 false，这个字段以前压根没传，
      // 所以批量跑出来的号一个都没 2FA）。留开关是因为绑定不可逆。
      want_2fa: form.value.autoWant2fa,
      engine: form.value.autoEngine,
    })
    ElMessage.success('自动跑号已启动')
  } catch (e) { ElMessage.error('启动失败: ' + e.message) }
}
async function call(fn, name) {
  try { await fn(); ElMessage.success(name + ' 成功') }
  catch (e) { ElMessage.error(name + ' 失败: ' + e.message) }
}
</script>

<template>
  <div class="page">
    <el-card shadow="never" style="margin-bottom: 16px">
      <template #header><span class="section-title" style="margin: 0">全自动批量注册</span></template>

      <el-form-item label="注册引擎" style="margin-bottom: 12px">
        <el-radio-group v-model="form.autoEngine">
          <el-radio value="protocol">协议模式（快速，~30s/个）</el-radio>
          <el-radio value="browser">浏览器模式（高存活，~2-3min/个）</el-radio>
        </el-radio-group>
        <el-alert
          v-if="form.autoEngine === 'browser'"
          type="warning" :closable="false"
          style="margin-top: 8px"
          title="浏览器模式每个 worker 占用 150-300MB 内存，批量模式强制无头运行。建议并发数 ≤ 5。"
        />
      </el-form-item>

      <el-space wrap :size="16" style="margin-bottom: 12px">
        <el-form-item label="并发" style="margin: 0">
          <el-input-number v-model="form.autoConcurrency" :min="1" :max="20" />
        </el-form-item>
        <el-form-item label="冷却(秒)" style="margin: 0">
          <el-input-number v-model="form.autoCoolDown" :min="0" :max="120" />
        </el-form-item>
        <el-form-item label="目标数(0=不限)" style="margin: 0">
          <el-input-number v-model="form.autoTargetCount" :min="0" :max="100000" />
        </el-form-item>
        <el-form-item label="OTP 等待(秒)" style="margin: 0">
          <el-input-number v-model="form.otpTimeout" :min="180" :max="600" />
        </el-form-item>
      </el-space>

      <el-form-item label="2FA">
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap">
          <el-switch v-model="form.autoWant2fa" />
          <span>每个号注册成功后自动绑定 2FA（TOTP）</span>
        </div>
        <div class="hint" style="margin-top: 6px; line-height: 1.5">
          默认开。绑定不可逆：之后该号所有登录都需 6 位动态码；
          secret 仅下发<b>一次</b>、服务端取不回，跑完请到「注册结果」页<b>导出备份</b>。
          2FA 必须绑定并通过服务端复核才会记为完成；
          已有账号须在本地保存密码后才可继续绑定。
        </div>
      </el-form-item>
      <el-form-item label="Refresh token">
        <el-switch v-model="form.wantRefreshToken" />
        <span class="hint" style="margin-left: 8px">开启后作为完成必需项</span>
      </el-form-item>

      <el-form-item label="代理池">
        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap">
          <el-tag :type="proxyCount ? 'success' : 'info'" effect="light">
            当前 {{ proxyCount }} 个代理
          </el-tag>
          <span class="hint">
            {{ proxyCount ? '每个任务重新分配并校验唯一出口' : '为空：所有 worker 用「单次注册」页填的单代理' }}
          </span>
          <el-button size="small" @click="router.push('/proxy')">管理代理池</el-button>
        </div>
      </el-form-item>

      <el-space wrap style="margin-top: 8px">
        <el-button type="primary" :disabled="!canStart" @click="start">开始</el-button>
        <el-button :disabled="!canPause" @click="call(autoPause, '暂停')">暂停</el-button>
        <el-button :disabled="!canResume" @click="call(autoResume, '恢复')">恢复</el-button>
        <el-button type="danger" :disabled="!canStop" @click="call(autoStop, '停止')">停止</el-button>
      </el-space>

      <el-descriptions :column="4" border size="small" style="margin-top: 16px">
        <el-descriptions-item label="状态"><StatusDot :type="stateType" :text="stateLabel" /></el-descriptions-item>
        <el-descriptions-item label="成功">
          <b style="color: var(--el-color-success)">{{ autoStatus.registered_ok || 0 }}</b>
          <span v-if="autoStatus.target_count"> / {{ autoStatus.target_count }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="失败">
          <b style="color: var(--el-color-danger)">{{ autoStatus.registered_fail || 0 }}</b>
        </el-descriptions-item>
        <el-descriptions-item label="并发">{{ autoStatus.concurrency || 1 }}</el-descriptions-item>
      </el-descriptions>

      <div v-if="workers.length" style="margin-top: 12px">
        <el-tag v-for="w in workers" :key="w.id" type="warning" effect="plain" style="margin: 0 6px 6px 0">
          worker-{{ w.id }} · {{ w.email }}
        </el-tag>
      </div>
      <p v-if="autoStatus.last_message" class="hint" style="margin-top: 8px">{{ autoStatus.last_message }}</p>
    </el-card>

    <el-card shadow="never" style="margin-bottom: 16px">
      <template #header>
        <span class="section-title" style="margin: 0">自动供号（ReMail）</span>
        <el-tag
          :type="supply.config?.auto_buy ? 'success' : 'info'"
          size="small" style="margin-left: 8px"
        >
          {{ supply.config?.auto_buy ? '池空自动下单已开' : '自动下单已关' }}
        </el-tag>
      </template>

      <el-form label-width="130px" size="small">
        <el-form-item label="API Key">
          <el-input v-model="supply.config.api_key" class="mono" placeholder="rk-..." />
        </el-form-item>
        <el-space wrap>
          <el-form-item label="每批买入">
            <el-input-number v-model="supply.config.batch_size" :min="2" :max="100" />
          </el-form-item>
          <el-form-item label="低于多少补货">
            <el-input-number v-model="supply.config.min_available" :min="0" :max="1000" />
          </el-form-item>
          <el-form-item label="自动下单">
            <el-switch v-model="supply.config.auto_buy" />
          </el-form-item>
        </el-space>

        <el-descriptions :column="3" border size="small" style="margin-top: 4px">
          <el-descriptions-item label="余额">{{ supply.balance ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="可用邮箱">{{ supply.available ?? 0 }}</el-descriptions-item>
          <el-descriptions-item label="已购可用订单">
            {{ supply.usable_orders ?? 0 }} / {{ supply.active_orders ?? 0 }}
          </el-descriptions-item>
        </el-descriptions>

        <el-space wrap style="margin-top: 10px">
          <el-button type="primary" :loading="supplyBusy" @click="saveSupply">保存</el-button>
          <el-button :loading="supplyBusy" @click="doImportOrders">导入已购订单（免费）</el-button>
          <el-button type="warning" :loading="supplyBusy" @click="doRefill">
            立即补货（会扣余额）
          </el-button>
          <el-button @click="loadSupply">刷新</el-button>
        </el-space>
        <p class="hint" style="margin-top: 8px">
          邮箱池低于阈值时程序会自动下单买新邮箱（{{ supply.config?.email_suffix || 'icloud.com' }}，
          单价约 60）；买来的邮箱收件窗口只有 1 小时，会立刻投入注册，不会放着过期。
        </p>
      </el-form>
    </el-card>

    <el-card shadow="never">
      <LogPanel />
    </el-card>
  </div>
</template>
