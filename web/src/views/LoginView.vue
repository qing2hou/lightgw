<template>
  <div class="login-bg">
    <el-card class="login-card">
      <div class="login-title">
        <span class="mark">⇄</span>
        轻量专线网关
      </div>
      <div class="login-sub">专线接入 · 端口映射 · 带宽管控 · 审计</div>

      <!-- 第一步：账号密码 -->
      <el-form v-if="!pendingToken" :model="form" @keyup.enter="submit" size="large">
        <el-form-item>
          <el-input v-model="form.username" placeholder="用户名" :prefix-icon="User" autofocus />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.password" type="password" placeholder="密码" show-password :prefix-icon="Lock" />
        </el-form-item>
        <el-button type="primary" class="login-btn" size="large" :loading="loading" @click="submit">
          登 录
        </el-button>
      </el-form>

      <!-- 第二步：两步验证码 -->
      <el-form v-else :model="tfa" @keyup.enter="submit2fa" size="large">
        <el-alert type="info" :closable="false" class="tfa-tip" title="已开启两步验证" description="请输入验证器 App 显示的 6 位验证码；丢失验证器时可用一次性恢复码" show-icon />
        <el-form-item>
          <el-input v-model="tfa.code" placeholder="6 位验证码或恢复码" :prefix-icon="Key" autofocus maxlength="9" />
        </el-form-item>
        <el-button type="primary" class="login-btn" size="large" :loading="loading" @click="submit2fa">
          验证并登录
        </el-button>
        <el-button text class="login-btn back-btn" @click="backToStep1">返回重新输入密码</el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock, Key } from '@element-plus/icons-vue'
import { useAuthStore } from '../stores/auth'
import { errMsg } from '../api'
import api from '../api'

const router = useRouter()
const auth = useAuthStore()
const loading = ref(false)
const form = reactive({ username: '', password: '' })
const tfa = reactive({ code: '' })
// 两步验证第一步返回的短时凭据
const pendingToken = ref('')

async function submit() {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  loading.value = true
  try {
    const { data } = await api.post('/login', { username: form.username, password: form.password })
    finishLogin(data)
  } catch (e) {
    // 第一步通过：进入两步验证第二步
    if (e.response?.status === 401 && e.response.data?.code === 'totp_required') {
      pendingToken.value = e.response.data.pending_token
      ElMessage.info('请输入两步验证码')
    } else {
      ElMessage.error(errMsg(e))
    }
  } finally {
    loading.value = false
  }
}

async function submit2fa() {
  if (!tfa.code) return ElMessage.warning('请输入验证码')
  loading.value = true
  try {
    const { data } = await api.post('/login/2fa', {
      pending_token: pendingToken.value,
      code: tfa.code.trim(),
    })
    pendingToken.value = ''
    finishLogin(data)
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

function backToStep1() {
  pendingToken.value = ''
  tfa.code = ''
}

function finishLogin(data) {
  auth.applyLogin(data)
  if (auth.mustChangePassword) {
    ElMessage.warning('首次登录请先修改默认密码')
    router.push('/settings')
  } else {
    ElMessage.success('登录成功')
    router.push('/')
  }
}
</script>

<style scoped>
.login-bg {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #1d2939 0%, #273a52 60%, #1f3a5f 100%);
}
.login-card {
  width: 380px;
  padding: 12px 8px;
  border-radius: 10px;
}
.login-title {
  text-align: center;
  font-size: 24px;
  font-weight: 700;
  color: #1d2939;
}
.mark {
  color: #409eff;
  margin-right: 6px;
}
.login-sub {
  text-align: center;
  color: #909399;
  font-size: 13px;
  margin: 8px 0 24px;
}
.login-btn {
  width: 100%;
  margin-left: 0;
}
.back-btn {
  margin-top: 8px;
}
.tfa-tip {
  margin-bottom: 16px;
}
</style>
