<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <span class="tip">内核转发会话表（conntrack）——穿越（snat）与发布（dnat）的活跃会话；可单条掐断</span>
        </div>
        <div class="toolbar-right">
          <el-select v-model="proto" clearable placeholder="协议" style="width: 90px" @change="load">
            <el-option label="TCP" value="tcp" />
            <el-option label="UDP" value="udp" />
          </el-select>
          <el-input v-model="q" placeholder="搜索 IP/端口" clearable style="width: 200px; margin-left: 8px" @keyup.enter="load" />
          <el-button :icon="Refresh" circle style="margin-left: 8px" @click="load" />
        </div>
      </div>

      <el-table :data="items" stripe v-loading="loading">
        <el-table-column prop="proto" label="协议" width="70">
          <template #default="{ row }"><el-tag size="small" type="info">{{ row.proto.toUpperCase() }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="src" label="客户端" min-width="180">
          <template #default="{ row }"><code>{{ row.src }}</code></template>
        </el-table-column>
        <el-table-column prop="dst" label="目标（NAT 前）" min-width="180">
          <template #default="{ row }"><code>{{ row.dst }}</code></template>
        </el-table-column>
        <el-table-column label="NAT 后源" min-width="160">
          <template #default="{ row }">
            <code v-if="row.src_after && !srcIsSame(row)">{{ row.src_after }}</code>
            <span v-else class="sub">—</span>
          </template>
        </el-table-column>
        <el-table-column label="归属" width="180" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tag v-if="row.router && row.router !== 'other'" size="small" type="success">{{ row.router }}</el-tag>
            <span v-else class="sub">其他流量</span>
          </template>
        </el-table-column>
        <el-table-column prop="state" label="状态" width="120">
          <template #default="{ row }">
            <el-tag size="small" :type="row.state === 'ESTABLISHED' ? 'success' : 'info'">{{ row.state }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-button link type="danger" size="small" @click="kill(row)">掐断</el-button>
          </template>
        </el-table-column>
        <template #empty>当前无匹配会话</template>
      </el-table>
      <div class="pager">
        <span class="sub">共 {{ items.length }} 条（最多显示 500，5 秒内新建/结束可能未反映）</span>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import api from '../api'

const items = ref([])
const loading = ref(false)
const proto = ref('')
const q = ref('')
let timer = null

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/sessions', { params: { proto: proto.value || undefined, q: q.value || undefined } })
    items.value = data.items || []
  } catch (e) {
    ElMessage.error(e.error || '加载失败')
  } finally {
    loading.value = false
  }
}

function srcIsSame(row) {
  // dnat 会话：src_after 是后端回程视角源（=客户端不变）；只有 snat 会话该值有展示意义
  return row.router.startsWith('dnat') || row.router === 'other'
}

async function kill(row) {
  try {
    await ElMessageBox.confirm(`掐断会话 ${row.src} → ${row.dst}？对端将立即断连`, '确认掐断', { type: 'warning' })
  } catch { return }
  try {
    await api.post('/sessions/kill', { id: row.id })
    ElMessage.success('已掐断')
    load()
  } catch (e) {
    ElMessage.error(e.error || '掐断失败')
  }
}

onMounted(() => { load(); timer = setInterval(load, 5000) })
onUnmounted(() => timer && clearInterval(timer))
</script>

<style scoped>
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.toolbar-left { display: flex; align-items: center; gap: 12px; }
.toolbar-right { display: flex; align-items: center; }
.tip { color: var(--el-text-color-secondary); font-size: 12px; }
.sub { color: var(--el-text-color-secondary); font-size: 12px; }
.pager { margin-top: 12px; display: flex; justify-content: flex-end; }
</style>
