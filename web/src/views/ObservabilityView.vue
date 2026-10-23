<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <span class="title">进程运行状态</span>
          <el-tag size="small" type="info">每 5 秒自动刷新</el-tag>
        </div>
        <div class="toolbar-right">
          <el-button link type="primary" @click="openPprof">性能分析 (pprof)</el-button>
          <el-button :icon="Refresh" circle @click="load" />
        </div>
      </div>
      <el-descriptions :column="4" border size="small">
        <el-descriptions-item label="版本">{{ info.version }}</el-descriptions-item>
        <el-descriptions-item label="运行时长">{{ fmtUptime(info.uptime_seconds) }}</el-descriptions-item>
        <el-descriptions-item label="goroutine">{{ info.runtime?.goroutines ?? '-' }}</el-descriptions-item>
        <el-descriptions-item label="堆内存">{{ fmtBytes(info.runtime?.mem_alloc_bytes) }}</el-descriptions-item>
        <el-descriptions-item label="文件描述符">{{ info.runtime?.fd_count ?? '-' }}</el-descriptions-item>
        <el-descriptions-item label="数据库体积">{{ fmtBytes(info.db_size_bytes) }}</el-descriptions-item>
        <el-descriptions-item label="规则（启用/失败）">
          {{ info.rules?.enabled ?? '-' }} / {{ info.rules?.total ?? '-' }} 启用，
          <span :class="{ warn: (info.rules?.failed || 0) > 0 }">{{ info.rules?.failed ?? '-' }} 失败</span>
        </el-descriptions-item>
        <el-descriptions-item label="后端异常">
          <span :class="{ warn: (info.backends_down || 0) > 0 }">{{ info.backends_down ?? '-' }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="活跃会话">{{ info.engine?.sessions_active ?? '-' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card>
      <div class="toolbar"><span class="title">引擎防护与异常</span></div>
      <div class="tag-row">
        <el-tag :type="(info.engine?.rejected_global || 0) > 0 ? 'warning' : 'info'">
          全局上限拒绝 {{ info.engine?.rejected_global ?? 0 }}
        </el-tag>
        <el-tag :type="(info.engine?.rejected_rule || 0) > 0 ? 'warning' : 'info'">
          规则上限拒绝 {{ info.engine?.rejected_rule ?? 0 }}
        </el-tag>
        <el-tag :type="(info.engine?.accept_errors || 0) > 0 ? 'danger' : 'info'">
          accept 错误 {{ info.engine?.accept_errors ?? 0 }}
        </el-tag>
        <el-tag :type="(info.engine?.panics || 0) > 0 ? 'danger' : 'info'">
          已隔离 panic {{ info.engine?.panics ?? 0 }}
        </el-tag>
      </div>
      <div class="hint">拒绝/panic 计数非零说明发生过资源防护或异常隔离，可结合 journalctl 日志定位原因。</div>
    </el-card>

    <el-card>
      <div class="toolbar">
        <span class="title">后端状态总览</span>
        <el-link type="primary" @click="router.push('/rules')">前往规则管理</el-link>
      </div>
      <div v-if="backendChips.length" class="chips">
        <el-tooltip v-for="c in backendChips" :key="c.id" :content="c.tip" placement="top">
          <el-tag :type="c.up ? 'success' : 'danger'" effect="plain" class="chip" @click="router.push('/rules')">
            {{ c.name }}<span class="chip-proto">{{ c.protocol.toUpperCase() }}</span>
          </el-tag>
        </el-tooltip>
      </div>
      <div v-else class="sub-hint">暂无启用检测的 TCP 规则</div>
      <div class="hint">异常规则排在最前；点击标签进入规则管理查看检测历史</div>
    </el-card>

    <el-card>
      <div class="toolbar"><span class="title">日志写入器水位</span></div>
      <el-table :data="logRows" size="small" border>
        <el-table-column prop="kind" label="类型" width="100" />
        <el-table-column label="待落库" width="110">
          <template #default="{ row }">{{ row.queued }}</template>
        </el-table-column>
        <el-table-column label="已丢弃（队列打满）" width="170">
          <template #default="{ row }">
            <span :class="{ warn: row.dropped > 0 }">{{ row.dropped }}</span>
          </template>
        </el-table-column>
        <el-table-column label="清理失败次数">
          <template #default="{ row }">
            <span :class="{ warn: row.cleanup_failed > 0 }">{{ row.cleanup_failed }}</span>
          </template>
        </el-table-column>
      </el-table>
      <div class="hint">丢弃数非零说明日志产生速度超过落库速度（队列 4096/256 打满）；清理失败非零需查服务端日志。</div>
    </el-card>

    <el-card>
      <div class="toolbar">
        <span class="title">逐规则指标</span>
        <span class="hint-inline">字节数为进程内实时累计（含未落库会话），与流量日志落库口径略有差异</span>
      </div>
      <el-table :data="info.rule_metrics || []" size="small" border>
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="name" label="规则" min-width="140" show-overflow-tooltip />
        <el-table-column label="协议" width="80">
          <template #default="{ row }">
            <el-tag size="small" :type="row.protocol === 'tcp' ? 'primary' : 'warning'">{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="conn_current" label="当前连接" width="100" />
        <el-table-column prop="conn_total" label="累计连接" width="100" />
        <el-table-column label="↑ 上行" width="110">
          <template #default="{ row }">{{ fmtBytes(row.bytes_up) }}</template>
        </el-table-column>
        <el-table-column label="↓ 下行" width="110">
          <template #default="{ row }">{{ fmtBytes(row.bytes_down) }}</template>
        </el-table-column>
        <el-table-column label="后端" width="80">
          <template #default="{ row }">
            <span v-if="!row.backend_checked" class="sub">未检测</span>
            <span v-else :class="row.backend_up ? 'ok' : 'bad'">{{ row.backend_up ? '正常' : '异常' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="错误" width="80">
          <template #default="{ row }">
            <span :class="{ warn: row.errors > 0 }">{{ row.errors }}</span>
          </template>
        </el-table-column>
        <el-table-column label="ACL 拒绝" width="100">
          <template #default="{ row }">
            <span :class="{ warn: row.denied > 0 }">{{ row.denied }}</span>
          </template>
        </el-table-column>
        <template #empty>暂无规则指标</template>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import api, { errMsg } from '../api'
import { formatBytes, formatDuration } from '../utils/format'

const info = ref({})
let timer = null

const fmtBytes = formatBytes
const fmtUptime = (sec) => (sec == null ? '-' : formatDuration(sec * 1000))

// 后端状态总览：异常置顶，正常随后（仅统计开启检测的 TCP 规则）
const backendChips = computed(() => {
  const rules = info.value.rule_metrics || []
  return rules
    .filter((r) => r.protocol === 'tcp' && r.backend_checked)
    .map((r) => ({
      id: r.id,
      name: r.name,
      protocol: r.protocol,
      up: r.backend_up,
      tip: `${r.name}：${r.backend_up ? '后端正常' : r.backend_error || '后端异常'}`,
    }))
    .sort((a, b) => a.up - b.up || a.name.localeCompare(b.name))
})

const logRows = computed(() => {
  const l = info.value.logs || {}
  return [
    { kind: '流量日志', queued: l.traffic_queued ?? 0, dropped: l.traffic_dropped ?? 0, cleanup_failed: l.traffic_cleanup_failed ?? 0 },
    { kind: '操作审计', queued: l.audit_queued ?? 0, dropped: l.audit_dropped ?? 0, cleanup_failed: l.audit_cleanup_failed ?? 0 },
  ]
})

async function load() {
  try {
    const { data } = await api.get('/observability')
    info.value = data
  } catch (e) {
    ElMessage.error(errMsg(e))
  }
}

// openPprof 先签发短时专用令牌（10 分钟、仅限 pprof 路径）再打开新标签页，
// 浏览器新标签页无法携带 Authorization 头
async function openPprof() {
  try {
    const { data } = await api.get('/pprof-token')
    window.open(data.url, '_blank')
  } catch (e) {
    ElMessage.error(errMsg(e))
  }
}

onMounted(() => {
  load()
  timer = setInterval(load, 5000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.toolbar-left {
  display: flex;
  align-items: center;
  gap: 10px;
}
.toolbar-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
.title {
  font-weight: 600;
}
.tag-row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
.hint {
  margin-top: 10px;
  color: #909399;
  font-size: 12px;
  line-height: 1.6;
}
.hint-inline {
  color: #909399;
  font-size: 12px;
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.chip {
  cursor: pointer;
}
.chip-proto {
  margin-left: 4px;
  font-size: 10px;
  opacity: 0.7;
}
.sub-hint {
  color: #909399;
  font-size: 13px;
}
.warn {
  color: #e6a23c;
  font-weight: 600;
}
.ok {
  color: #67c23a;
}
.bad {
  color: #f56c6c;
}
.el-card {
  margin-bottom: 16px;
}
</style>
