<template>
  <div>
    <el-card>
      <div class="filters">
        <el-input v-model="filters.username" placeholder="用户名筛选" clearable style="width: 160px" />
        <el-select v-model="filters.action" placeholder="全部操作" clearable filterable style="width: 200px">
          <el-option v-for="a in actions" :key="a.value" :value="a.value" :label="a.label" />
        </el-select>
        <el-date-picker v-model="timeRange" type="datetimerange" range-separator="至" start-placeholder="开始时间" end-placeholder="结束时间" style="width: 360px" />
        <el-button type="primary" :icon="Search" @click="search">查询</el-button>
        <el-button :icon="Refresh" @click="reset">重置</el-button>
      </div>

      <el-table :data="items" stripe v-loading="loading">
        <el-table-column prop="id" label="#" width="70" />
        <el-table-column label="用户" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="row.username === 'admin' ? 'primary' : 'info'">{{ row.username }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="130">
          <template #default="{ row }">
            {{ actionText(row.action) }}
          </template>
        </el-table-column>
        <el-table-column label="详情" min-width="320" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono">{{ row.detail || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="来源 IP" width="140">
          <template #default="{ row }"><span class="mono">{{ row.ip || '-' }}</span></template>
        </el-table-column>
        <el-table-column label="时间" width="170">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <template #empty>暂无操作记录</template>
      </el-table>

      <div class="pager">
        <el-pagination
          v-model:current-page="page"
          :page-size="pageSize"
          :total="total"
          layout="total, prev, pager, next"
          @current-change="load"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Search, Refresh } from '@element-plus/icons-vue'
import api, { errMsg } from '../api'
import { formatTime } from '../utils/format'

const items = ref([])
const loading = ref(false)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const timeRange = ref(null)
const filters = reactive({ username: '', action: '' })

const fmtTime = formatTime

const actions = [
  { value: 'login', label: '登录' },
  { value: 'login_failed', label: '登录失败' },
  { value: 'logout', label: '退出登录' },
  { value: 'password_change', label: '修改密码' },
  { value: 'rule_create', label: '新建规则' },
  { value: 'rule_update', label: '更新规则' },
  { value: 'rule_delete', label: '删除规则' },
  { value: 'rule_enable', label: '启用规则' },
  { value: 'rule_disable', label: '停用规则' },
]

function actionText(a) {
  const hit = actions.find((x) => x.value === a)
  if (hit) return hit.label
  return a
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
    if (filters.username.trim()) params.username = filters.username.trim()
    if (filters.action) params.action = filters.action
    if (timeRange.value && timeRange.value[0]) {
      params.start = fmtDate(new Date(timeRange.value[0]))
      params.end = fmtDate(new Date(timeRange.value[1]))
    }
    const { data } = await api.get('/audit-logs', { params })
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
  filters.username = ''
  filters.action = ''
  timeRange.value = null
  search()
}

onMounted(load)
</script>

<style scoped>
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 12px;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.pager {
  margin-top: 12px;
  display: flex;
  justify-content: flex-end;
}
</style>
