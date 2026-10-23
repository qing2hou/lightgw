<template>
  <div>
    <el-row :gutter="16">
      <el-col :span="6" v-for="card in cards" :key="card.label">
        <el-card class="stat-card">
          <div class="stat-label">{{ card.label }}</div>
          <div class="stat-value" :style="{ color: card.color }">{{ card.value }}</div>
          <div class="stat-sub">{{ card.sub }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-card class="section">
      <template #header>
        <div class="section-header">
          <span>实时速率（全部规则合计，最近 10 秒平均）</span>
          <el-tag size="small" type="info">每 5 秒自动刷新</el-tag>
        </div>
      </template>
      <div class="rate-row">
        <div class="rate-item">
          <div class="stat-label">上传 ↑</div>
          <div class="stat-value" style="color: #e6a23c">{{ fmtBps(rate.up) }}</div>
        </div>
        <div class="rate-item">
          <div class="stat-label">下载 ↓</div>
          <div class="stat-value" style="color: #409eff">{{ fmtBps(rate.down) }}</div>
        </div>
      </div>
    </el-card>

    <el-card class="section">
      <template #header>
        <div class="section-header">
          <span>当前活跃会话</span>
          <el-tag size="small" type="info">每 5 秒自动刷新</el-tag>
        </div>
      </template>
      <el-table :data="sessions" size="default" stripe>
        <el-table-column prop="id" label="会话" width="80" />
        <el-table-column label="规则" min-width="140">
          <template #default="{ row }">{{ row.rule_name }} (#{{ row.rule_id }})</template>
        </el-table-column>
        <el-table-column label="协议" width="80">
          <template #default="{ row }">
            <el-tag :type="protoTag(row.protocol)" size="small">{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="源地址" width="160">
          <template #default="{ row }">{{ row.source_ip }}:{{ row.source_port }}</template>
        </el-table-column>
        <el-table-column label="访问本机 IP" width="150">
          <template #default="{ row }">{{ row.listen_ip }}:{{ row.listen_port }}</template>
        </el-table-column>
        <el-table-column prop="target_addr" label="目标" min-width="160" show-overflow-tooltip />
        <el-table-column label="上传" width="110">
          <template #default="{ row }">
            <span class="up">↑ {{ fmtBytes(row.upload_bytes) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="下载" width="110">
          <template #default="{ row }">
            <span class="down">↓ {{ fmtBytes(row.download_bytes) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="开始时间" width="170">
          <template #default="{ row }">{{ fmtTime(row.started_at) }}</template>
        </el-table-column>
        <template #empty>暂无活跃会话</template>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import api, { errMsg } from '../api'
import { formatBytes, formatTime } from '../utils/format'
import { ElMessage } from 'element-plus'

const stats = ref({})
const sessions = ref([])
const rate = ref({ up: 0, down: 0 })
let timer = null

const cards = computed(() => [
  { label: '转发规则', value: `${stats.value.enabled_count ?? 0} / ${stats.value.rule_count ?? 0}`, sub: '启用 / 总数', color: '#409eff' },
  { label: '活跃会话', value: stats.value.active_sessions ?? 0, sub: '当前进行中的连接/请求', color: '#67c23a' },
  {
    label: '今日流量',
    value: fmtBytes((stats.value.today_upload_bytes || 0) + (stats.value.today_download_bytes || 0)),
    sub: `↑${fmtBytes(stats.value.today_upload_bytes)} ↓${fmtBytes(stats.value.today_download_bytes)} · 进行中 ↑${fmtBytes(stats.value.live_upload_bytes || 0)} ↓${fmtBytes(stats.value.live_download_bytes || 0)}`,
    color: '#e6a23c',
  },
  {
    label: '累计流量',
    value: fmtBytes((stats.value.total_upload_bytes || 0) + (stats.value.total_download_bytes || 0)),
    sub: `↑${fmtBytes(stats.value.total_upload_bytes)} ↓${fmtBytes(stats.value.total_download_bytes)}`,
    color: '#909399',
  },
])

const fmtBytes = formatBytes
const fmtTime = formatTime
// B/s 展示
const fmtBps = (bps) => {
  if (bps >= 1024 * 1024) return (bps / 1024 / 1024).toFixed(2) + ' MB/s'
  if (bps >= 1024) return (bps / 1024).toFixed(1) + ' KB/s'
  return bps + ' B/s'
}

function protoTag(p) {
  return { tcp: 'primary', udp: 'warning' }[p] || 'info'
}

async function refresh() {
  try {
    const [s, st, obs] = await Promise.all([api.get('/streams'), api.get('/stats'), api.get('/observability')])
    sessions.value = s.data.items || []
    stats.value = st.data
    // 全局实时速率：各规则当前窗口速率求和（observability 的 rule_metrics）
    let up = 0
    let down = 0
    for (const rm of obs.data.rule_metrics || []) {
      up += rm.rate_up_bps || 0
      down += rm.rate_down_bps || 0
    }
    rate.value = { up, down }
  } catch (e) {
    ElMessage.error(errMsg(e))
  }
}

onMounted(() => {
  refresh()
  timer = setInterval(refresh, 5000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.stat-card {
  text-align: center;
}
.stat-label {
  color: #909399;
  font-size: 13px;
}
.stat-value {
  font-size: 26px;
  font-weight: 700;
  margin: 8px 0 4px;
}
.stat-sub {
  color: #c0c4cc;
  font-size: 12px;
}
.rate-row {
  display: flex;
  gap: 48px;
}
.rate-item {
  text-align: center;
  flex: 1;
}
.section {
  margin-top: 16px;
}
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.up {
  color: #e6a23c;
}
.down {
  color: #409eff;
}
</style>
