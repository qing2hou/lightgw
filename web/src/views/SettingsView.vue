<template>
  <el-row :gutter="16">
    <!-- 修改密码 -->
    <el-col :span="12">
      <el-card>
        <template #header>修改密码</template>
        <el-alert
          v-if="auth.mustChangePassword"
          title="当前仍在使用默认密码 admin123，存在安全风险，请立即修改"
          type="warning"
          show-icon
          :closable="false"
          class="alert"
        />
        <el-form :model="form" label-width="90px">
          <el-form-item label="原密码">
            <el-input v-model="form.old" type="password" show-password placeholder="当前登录密码" />
          </el-form-item>
          <el-form-item label="新密码">
            <el-input v-model="form.new" type="password" show-password placeholder="至少 8 位" />
          </el-form-item>
          <el-form-item label="确认新密码">
            <el-input v-model="form.confirm" type="password" show-password @keyup.enter="submit" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" @click="submit">保存修改</el-button>
          </el-form-item>
        </el-form>
      </el-card>
    </el-col>

    <!-- 两步验证 -->
    <el-col :span="12">
      <el-card>
        <template #header>
          <div class="card-header">
            <span>两步验证（TOTP）</span>
            <el-tag v-if="tfa.enabled" type="success" size="small">已开启</el-tag>
            <el-tag v-else-if="tfa.pending" type="warning" size="small">待确认</el-tag>
            <el-tag v-else type="info" size="small">未开启</el-tag>
          </div>
        </template>

        <template v-if="!tfa.enabled">
          <el-alert
            type="info"
            :closable="false"
            class="alert"
            title="开启后登录需密码 + 验证器动态码双重验证"
            description="支持 Google Authenticator / Microsoft Authenticator 等验证器 App；开启时会生成 10 个一次性恢复码，请妥善保存"
            show-icon
          />
          <!-- 待确认：扫码 + 输入验证码 -->
          <div v-if="tfa.pending && setup.qr" class="setup">
            <div class="qr-wrap">
              <img :src="setup.qr" alt="两步验证二维码" />
            </div>
            <p class="hint">用验证器 App 扫码，或手动输入密钥：<code>{{ setup.secret }}</code></p>
            <el-input v-model="setup.code" placeholder="输入验证器显示的 6 位验证码" maxlength="6" @keyup.enter="confirm2fa">
              <template #append>
                <el-button :loading="setup.loading" @click="confirm2fa">确认开启</el-button>
              </template>
            </el-input>
            <el-alert
              v-if="setup.codes.length"
              type="warning"
              :closable="false"
              class="alert codes"
              title="一次性恢复码（仅此一次展示，请保存到安全的地方）"
            >
              <div class="codes-grid">
                <code v-for="c in setup.codes" :key="c">{{ c }}</code>
              </div>
            </el-alert>
          </div>
          <el-button v-else type="primary" :loading="tfa.loading" @click="begin2fa">
            {{ tfa.pending ? '重新生成密钥' : '开启两步验证' }}
          </el-button>
        </template>

        <template v-else>
          <el-alert type="success" :closable="false" class="alert" :title="`登录需验证器动态码，剩余恢复码 ${tfa.backup_remaining} 个`" />
          <el-divider />
          <el-form label-width="90px">
            <el-form-item label="密码">
              <el-input v-model="disableForm.password" type="password" show-password placeholder="确认身份" />
            </el-form-item>
            <el-form-item label="验证码">
              <el-input v-model="disableForm.code" placeholder="6 位验证码或恢复码" maxlength="9" />
            </el-form-item>
            <el-form-item>
              <el-button type="danger" :loading="tfa.loading" @click="disable2fa">关闭两步验证</el-button>
            </el-form-item>
          </el-form>
        </template>
      </el-card>
    </el-col>

    <!-- 监控采集令牌 -->
    <el-col :span="24">
      <el-card class="mt16">
        <template #header>
          <div class="card-header">
            <span>监控采集令牌</span>
            <el-tag type="info" size="small">仅限 /api/metrics · 有效期一年</el-tag>
          </div>
        </template>
        <el-alert
          type="info"
          :closable="false"
          class="alert"
          title="给 Prometheus 等无人值守采集用，不会随登录会话过期"
          description="改密码后令牌自动失效，需重新签发。命令行的会话令牌 24 小时过期，不适合无人值守抓取。"
          show-icon
        />
        <div class="token-row">
          <el-button type="primary" :loading="mt.loading" @click="issue">签发新令牌</el-button>
          <template v-if="mt.token">
            <el-input :model-value="mt.token" readonly class="token-input">
              <template #append>
                <el-button @click="copy(mt.token)">复制</el-button>
              </template>
            </el-input>
          </template>
        </div>
        <p v-if="mt.token" class="hint">Prometheus 抓取配置：</p>
        <pre v-if="mt.token" class="snippet">scrape_configs:
  - job_name: haproxyweb
    scheme: https
    authorization:
      credentials: {{ mt.token }}
    static_configs:
      - targets: ["your-host:8443"]</pre>
      </el-card>
    </el-col>
  </el-row>
</template>

<script setup>
import { reactive, ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import api, { errMsg } from '../api'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const saving = ref(false)
const form = reactive({ old: '', new: '', confirm: '' })

async function submit() {
  if (!form.old || !form.new) return ElMessage.warning('请填写完整')
  if (form.new.length < 8) return ElMessage.warning('新密码长度至少 8 位')
  if (form.new !== form.confirm) return ElMessage.warning('两次输入的新密码不一致')
  saving.value = true
  try {
    const { data } = await api.put('/password', { old_password: form.old, new_password: form.new })
    // 服务端改密后递增令牌版本，换发的新令牌供当前会话无缝续期
    if (data.token) localStorage.setItem('haweb_token', data.token)
    auth.passwordChanged()
    ElMessage.success('密码已修改')
    form.old = form.new = form.confirm = ''
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    saving.value = false
  }
}

// ---------- 两步验证 ----------
const tfa = reactive({ enabled: false, pending: false, backup_remaining: 0, loading: false })
const setup = reactive({ qr: '', secret: '', code: '', codes: [], loading: false })
const disableForm = reactive({ password: '', code: '' })

async function loadStatus() {
  try {
    const { data } = await api.get('/2fa/status')
    tfa.enabled = data.enabled
    tfa.pending = data.pending
    tfa.backup_remaining = data.backup_remaining
  } catch (e) { /* 静默 */ }
}

async function begin2fa() {
  tfa.loading = true
  try {
    const { data } = await api.post('/2fa/begin')
    setup.qr = data.qr_png_base64
    setup.secret = data.secret
    setup.codes = data.backup_codes || []
    setup.code = ''
    tfa.pending = true
    ElMessage.success('已生成密钥，请扫码并输入验证码确认')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    tfa.loading = false
  }
}

async function confirm2fa() {
  if (!setup.code) return ElMessage.warning('请输入验证码')
  setup.loading = true
  try {
    await api.post('/2fa/confirm', { code: setup.code.trim() })
    tfa.enabled = true
    tfa.pending = false
    // 恢复码在确认开启后仍显示在页面上方一次性提示框，直到刷新
    ElMessage.success('两步验证已开启')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    setup.loading = false
  }
}

async function disable2fa() {
  if (!disableForm.password || !disableForm.code) return ElMessage.warning('请填写密码与验证码')
  tfa.loading = true
  try {
    await api.post('/2fa/disable', { password: disableForm.password, code: disableForm.code.trim() })
    tfa.enabled = false
    tfa.pending = false
    disableForm.password = disableForm.code = ''
    setup.qr = setup.secret = ''
    setup.codes = []
    ElMessage.success('两步验证已关闭')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    tfa.loading = false
  }
}

// ---------- 监控令牌 ----------
const mt = reactive({ token: '', loading: false })

async function issue() {
  mt.loading = true
  try {
    const { data } = await api.post('/metrics-token')
    mt.token = data.token
    ElMessage.success('监控令牌已签发，旧令牌随本令牌一并失效于改密时')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    mt.loading = false
  }
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch (e) {
    ElMessage.warning('复制失败，请手动选择复制')
  }
}

onMounted(loadStatus)
</script>

<style scoped>
.alert {
  margin-bottom: 16px;
}
.mt16 {
  margin-top: 16px;
}
.card-header {
  display: flex;
  align-items: center;
  gap: 8px;
}
.setup .qr-wrap {
  display: flex;
  justify-content: center;
  margin-bottom: 12px;
}
.setup .qr-wrap img {
  width: 200px;
  height: 200px;
  border: 1px solid #ebeef5;
  border-radius: 6px;
}
.hint {
  color: #909399;
  font-size: 13px;
  margin: 8px 0;
  word-break: break-all;
}
.codes {
  margin-top: 12px;
}
.codes-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 4px 16px;
  margin-top: 4px;
  font-size: 14px;
}
.token-row {
  display: flex;
  gap: 12px;
  align-items: center;
}
.token-input {
  flex: 1;
}
.snippet {
  background: #1d2939;
  color: #d6f0ff;
  padding: 12px;
  border-radius: 6px;
  font-size: 13px;
  overflow-x: auto;
}
</style>
