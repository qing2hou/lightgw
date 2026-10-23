<template>
  <div>
    <el-card>
      <div class="toolbar-live">
        <span class="live-title">当前活跃会话</span>
        <el-tag size="small" :type="streams.length ? 'success' : 'info'">{{ streams.length }} 条进行中</el-tag>
        <span class="live-hint">会话结束时才会写入下方流量日志；此面板每 5 秒刷新</span>
      </div>
      <el-table :data="streams" size="small" v-loading="streamsLoading" max-height="320">
        <el-table-column label="规则" min-width="140" show-overflow-tooltip>
          <template #default="{ row }">{{ row.rule_name }} (#{{ row.rule_id }})</template>
        </el-table-column>
        <el-table-column label="协议" width="70">
          <template #default="{ row }">
            <el-tag :type="protoTag(row.protocol)" size="small">{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="源地址" width="160">
          <template #default="{ row }"><span class="mono">{{ row.source_ip }}:{{ row.source_port }}</span></template>
        </el-table-column>
        <el-table-column label="访问本机 IP" width="150">
          <template #default="{ row }"><span class="mono">{{ row.listen_ip }}:{{ row.listen_port }}</span></template>
        </el-table-column>
        <el-table-column label="目标" min-width="140" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.target_addr }}</span></template>
        </el-table-column>
        <el-table-column label="↑ 已传" width="95">
          <template #default="{ row }"><span class="mono">{{ fmtBytes(row.upload_bytes) }}</span></template>
        </el-table-column>
        <el-table-column label="↓ 已传" width="95">
          <template #default="{ row }"><span class="mono">{{ fmtBytes(row.download_bytes) }}</span></template>
        </el-table-column>
        <el-table-column label="开始时间" width="165">
          <template #default="{ row }">{{ fmtTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column label="已持续" width="95">
          <template #default="{ row }">{{ liveDuration(row.started_at) }}</template>
        </el-table-column>
        <template #empty>当前没有活跃会话</template>
      </el-table>
    </el-card>

    <el-card>
      <div class="filters">
        <el-select v-model="filters.rule_id" placeholder="全部规则" clearable filterable style="width: 200px">
          <el-option v-for="r in rules" :key="r.id" :value="r.id" :label="`${r.name} (${r.protocol.toUpperCase()} ${r.listen_addr})`" />
        </el-select>
        <el-select v-model="filters.protocol" placeholder="全部协议" clearable style="width: 120px">
          <el-option value="tcp" label="TCP" />
          <el-option value="udp" label="UDP" />
        </el-select>
        <el-select v-model="filters.status" placeholder="全部状态" clearable style="width: 120px">
          <el-option value="closed" label="正常完成" />
          <el-option value="error" label="出错" />
          <el-option value="denied" label="被拒绝" />
        </el-select>
        <el-input v-model="filters.source_ip" placeholder="来源 IP 筛选" clearable style="width: 160px" class="mono-input" />
        <el-date-picker v-model="timeRange" type="datetimerange" range-separator="至" start-placeholder="开始时间" end-placeholder="结束时间" style="width: 360px" />
        <el-button type="primary" :icon="Search" @click="search">查询</el-button>
        <el-button :icon="Refresh" @click="reset">重置</el-button>
      </div>

      <el-table :data="items" stripe v-loading="loading">
        <el-table-column prop="id" label="#" width="70" />
        <el-table-column label="规则" min-width="130" show-overflow-tooltip>
          <template #default="{ row }">{{ row.rule_name }} (#{{ row.rule_id }})</template>
        </el-table-column>
        <el-table-column label="协议" width="75">
          <template #default="{ row }">
            <el-tag :type="protoTag(row.protocol)" size="small">{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="源地址" width="160">
          <template #default="{ row }">
            <span class="mono">{{ row.source_ip }}:{{ row.source_port }}</span>
          </template>
        </el-table-column>
        <el-table-column label="访问本机 IP" width="150">
          <template #default="{ row }">
            <span class="mono">{{ row.listen_ip }}:{{ row.listen_port }}</span>
          </template>
        </el-table-column>
        <el-table-column label="目标" min-width="140" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.target_addr }}</span></template>
        </el-table-column>
        <el-table-column label="上传" width="100">
          <template #default="{ row }"><span class="mono">↑ {{ fmtBytes(row.upload_bytes) }}</span></template>
        </el-table-column>
        <el-table-column label="下载" width="100">
          <template #default="{ row }"><span class="mono">↓ {{ fmtBytes(row.download_bytes) }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="statusTag(row.status)" size="small">{{ statusText(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="说明" min-width="140" show-overflow-tooltip>
          <template #default="{ row }">{{ row.error_msg || '-' }}</template>
        </el-table-column>
        <el-table-column label="开始时间" width="165">
          <template #default="{ row }">{{ fmtTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column label="耗时" width="90">
          <template #default="{ row }">{{ fmtDuration(row.duration_ms) }}</template>
        </el-table-column>
        <template #empty>暂无流量日志</template>
      </el-table>

      <div class="pager">
        <el-pagination
          v-model:current-page="page"
          :page-size="pageSize"
          :total="total"
          layout="total, prev, pager, next, sizes"
          :page-sizes="[20, 50, 100]"
          @current-change="load"
          @size-change="onSizeChange"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Search, Refresh } from '@element-plus/icons-vue'
import api, { errMsg } from '../api'
import { formatBytes, formatDuration, formatTime } from '../utils/format'

const rules = ref([])
const items = ref([])
const streams = ref([])
const streamsLoading = ref(false)
let streamTimer = null
const loading = ref(false)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const timeRange = ref(null)
const filters = reactive({ rule_id: null, protocol: '', status: '', source_ip: '' })

const fmtBytes = formatBytes
const fmtDuration = formatDuration
const fmtTime = formatTime

function protoTag(p) {
  return { tcp: 'primary', udp: 'warning' }[p] || 'info'
}
function statusTag(s) {
  return { closed: 'success', error: 'danger', denied: 'warning', active: 'info' }[s] || 'info'
}
function statusText(s) {
  return { closed: '正常', error: '出错', denied: '拒绝', active: '进行中' }[s] || s
}

// 活跃会话：实时接口，结束的会话进入下方流量日志
async function loadStreams() {
  streamsLoading.value = true
  try {
    const { data } = await api.get('/streams')
    streams.value = data.items || []
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    streamsLoading.value = false
  }
}

function liveDuration(startedAt) {
  if (!startedAt) return '-'
  return fmtDuration(Date.now() - new Date(startedAt).getTime())
}

function fmtDate(d) {
  if (!d) return ''
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

async function load() {
  loading.value = true
  try {
    const params = { page: page.value, page_size: pageSize.value }
    if (filters.rule_id) params.rule_id = filters.rule_id
    if (filters.protocol) params.protocol = filters.protocol
    if (filters.status) params.status = filters.status
    if (filters.source_ip.trim()) params.source_ip = filters.source_ip.trim()
    if (timeRange.value && timeRange.value[0]) {
      params.start = fmtDate(new Date(timeRange.value[0]))
      params.end = fmtDate(new Date(timeRange.value[1]))
    }
    const { data } = await api.get('/traffic-logs', { params })
    items.value = data.items || []
    total.value = data.total || 0
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

function search() {
  page.value = 1
  load()
}

function reset() {
  filters.rule_id = null
  filters.protocol = ''
  filters.status = ''
  filters.source_ip = ''
  timeRange.value = null
  search()
}

function onSizeChange(size) {
  pageSize.value = size
  page.value = 1
  load()
}

onUnmounted(() => clearInterval(streamTimer))

onMounted(async () => {
  load()
  loadStreams()
  streamTimer = setInterval(loadStreams, 5000)
  try {
    const { data } = await api.get('/rules')
    rules.value = data.items || []
  } catch (e) {
    /* 忽略 */
  }
})
</script>

<style scoped>
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 12px;
}
.lp {
  color: #e6a23c;
  font-weight: 600;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.mono-input :deep(input) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.pager {
  margin-top: 12px;
  display: flex;
  justify-content: flex-end;
}
.toolbar-live {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}
.live-title {
  font-weight: 600;
}
.live-hint {
  color: #909399;
  font-size: 12px;
}
</style>
