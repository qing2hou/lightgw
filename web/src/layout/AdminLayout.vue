<template>
  <el-container class="layout">
    <el-aside width="220px" class="aside">
      <div class="logo">
        <span class="logo-mark">⇄</span>
        <span>轻量专线网关</span>
      </div>
      <el-menu :default-active="activeMenu" router class="menu">
        <el-menu-item index="/dashboard">
          <el-icon><Odometer /></el-icon><span>总览</span>
        </el-menu-item>
        <el-menu-item index="/rules">
          <el-icon><Connection /></el-icon><span>端口映射</span>
        </el-menu-item>
        <el-menu-item index="/snat-rules">
          <el-icon><Position /></el-icon><span>SNAT 穿越</span>
        </el-menu-item>
        <el-menu-item index="/egresses">
          <el-icon><Grid /></el-icon><span>出口管理</span>
        </el-menu-item>
        <el-menu-item index="/dnat-rules">
          <el-icon><Upload /></el-icon><span>端口发布</span>
        </el-menu-item>
        <el-menu-item index="/fw-policies">
          <el-icon><Lock /></el-icon><span>防火墙策略</span>
        </el-menu-item>
        <el-menu-item index="/sessions">
          <el-icon><Connection /></el-icon><span>会话表</span>
        </el-menu-item>
        <el-menu-item index="/bw-groups">
          <el-icon><Histogram /></el-icon><span>带宽包</span>
        </el-menu-item>
        <el-menu-item index="/acl-groups">
          <el-icon><FolderOpened /></el-icon><span>名单组</span>
        </el-menu-item>
        <el-menu-item index="/traffic-logs">
          <el-icon><Document /></el-icon><span>流量日志</span>
        </el-menu-item>
        <el-menu-item index="/audit-logs">
          <el-icon><List /></el-icon><span>操作审计</span>
        </el-menu-item>
        <el-menu-item index="/observability">
          <el-icon><Monitor /></el-icon><span>运行监控</span>
        </el-menu-item>
        <el-menu-item index="/backup">
          <el-icon><Box /></el-icon><span>备份恢复</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon><span>设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="header-title">{{ route.meta.title }}</div>
        <div class="header-right">
          <el-tag v-if="auth.mustChangePassword" type="warning" effect="dark" class="pwd-tip">
            正在使用默认密码，
            <router-link to="/settings" class="pwd-link">请修改</router-link>
          </el-tag>
          <el-dropdown @command="onCommand">
            <span class="user-box">
              <el-icon><User /></el-icon>
              {{ auth.username }}
              <el-icon><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Odometer, Connection, Document, List, Monitor, Box, Setting, User, ArrowDown, FolderOpened, Position, Histogram, Upload, Lock, Grid } from '@element-plus/icons-vue'
import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const activeMenu = computed(() => route.path)

onMounted(() => {
  auth.refresh()
})

async function onCommand(cmd) {
  if (cmd === 'logout') {
    await auth.logout()
    router.push('/login')
  }
}
</script>

<style scoped>
.layout {
  height: 100%;
}
.aside {
  background: #1d2939;
  display: flex;
  flex-direction: column;
}
.logo {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: #fff;
  font-size: 18px;
  font-weight: 600;
  letter-spacing: 1px;
}
.logo-mark {
  color: #409eff;
  font-size: 22px;
}
.menu {
  border-right: none;
  background: transparent;
  flex: 1;
}
:deep(.el-menu) {
  background-color: #1d2939;
}
:deep(.el-menu-item) {
  color: #cbd5e1;
}
:deep(.el-menu-item.is-active) {
  color: #409eff;
  background: #111827;
}
:deep(.el-menu-item:hover) {
  background: #263449;
}
.header {
  background: #fff;
  display: flex;
  align-items: center;
  justify-content: space-between;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.06);
}
.header-title {
  font-size: 16px;
  font-weight: 600;
}
.header-right {
  display: flex;
  align-items: center;
  gap: 16px;
}
.pwd-tip :deep(.el-tag__content) {
  display: inline-flex;
  align-items: center;
}
.pwd-link {
  color: #fff;
  text-decoration: underline;
  margin-left: 2px;
}
.user-box {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  color: #303133;
}
.main {
  padding: 16px;
}
</style>
