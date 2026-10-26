<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建出口</el-button>
          <span class="tip">多出口上行：优先级分主备层（小者优先），同层按权重分担；探测自动切换，恢复回切</span>
        </div>
        <el-button :icon="Refresh" circle @click="load" />
      </div>

      <el-table :data="egresses" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="name" label="名称" min-width="120" show-overflow-tooltip />
        <el-table-column label="网卡" width="110">
          <template #default="{ row }"><code>{{ row.iface }}</code></template>
        </el-table-column>
        <el-table-column label="网关 v4" width="130">
          <template #default="{ row }"><code>{{ row.gateway_v4 || '—' }}</code></template>
        </el-table-column>
        <el-table-column label="网关 v6" width="150">
          <template #default="{ row }"><code>{{ row.gateway_v6 || '—' }}</code></template>
        </el-table-column>
        <el-table-column label="优先级/权重" width="100">
          <template #default="{ row }"><span class="mono">{{ row.priority }} / {{ row.weight }}</span></template>
        </el-table-column>
        <el-table-column label="探测" width="140" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono sub">{{ row.probe_mode === 'none' ? '不探测（常开）' : row.probe_mode + (row.probe_target ? '→' + shortTarget(row.probe_target) : '') }}</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tooltip :disabled="!row.status_detail.down_reason" :content="row.status_detail.down_reason" placement="top">
              <el-tag size="small" :type="row.status === 'up' ? 'success' : 'danger'">
                {{ row.status === 'up' ? '可用' : '不可用' }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="时延" width="80">
          <template #default="{ row }">
            <span v-if="row.probe_mode !== 'none' && row.status_detail.probe_latency_ms >= 0" class="mono sub">{{ row.status_detail.probe_latency_ms }}ms</span>
            <span v-else class="sub">—</span>
          </template>
        </el-table-column>
        <el-table-column label="启用" width="80">
          <template #default="{ row }">
            <el-switch :model-value="row.enabled" @change="(v) => toggle(row, v)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="probe(row)">探测</el-button>
            <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>还没有出口；无出口时规则用配置的出口网关（旧形态）</template>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑出口' : '新建出口'" width="560px" destroy-on-close>
      <el-form :model="form" label-width="100px">
        <el-form-item label="出口名称" required>
          <el-input v-model="form.name" placeholder="例如：电信出口" maxlength="64" />
        </el-form-item>
        <el-form-item label="出口网卡" required>
          <el-select v-model="form.iface" filterable placeholder="流量从哪块网卡出去" style="width: 100%" class="mono-input" :disabled="!!editing">
            <el-option v-for="i in ifaces" :key="i.name" :value="i.name"
              :label="`${i.name}（${i.ips && i.ips.length ? i.ips.join(', ') : '无 IPv4'}，${i.status}）`" />
          </el-select>
          <div class="form-tip">出口身份即网卡——创建后不可变更（需变更请新建出口）</div>
        </el-form-item>
        <el-form-item label="网关 v4">
          <el-input v-model="form.gateway_v4" placeholder="如 172.16.40.1（v4 上行网关）" class="mono-input" />
        </el-form-item>
        <el-form-item label="网关 v6">
          <el-input v-model="form.gateway_v6" placeholder="如 fd00::1（可选）" class="mono-input" />
        </el-form-item>
        <el-form-item label="优先级" required>
          <el-input-number v-model="form.priority" :min="0" :max="1000" />
          <div class="form-tip">层：小者优先（主出口小、备出口大）；同层按权重分担</div>
        </el-form-item>
        <el-form-item label="层内权重" required>
          <el-input-number v-model="form.weight" :min="1" :max="100" />
        </el-form-item>
        <el-form-item label="探测方式">
          <el-select v-model="form.probe_mode" style="width: 100%">
            <el-option label="ICMP 网关（icmp-gw）" value="icmp-gw" />
            <el-option label="ICMP 目标（icmp-target）" value="icmp-target" />
            <el-option label="TCP 端口（tcp-target）" value="tcp-target" />
            <el-option label="不探测（常开）" value="none" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.probe_mode === 'icmp-target' || form.probe_mode === 'tcp-target'" label="探测目标" required>
          <el-input v-model="form.probe_target" :placeholder="form.probe_mode === 'tcp-target' ? 'IP:端口（如 8.8.8.8:53）' : 'IP（如 8.8.8.8）'" class="mono-input" />
        </el-form-item>
        <el-form-item label="探测周期">
          <el-input-number v-model="form.interval_sec" :min="1" :max="60" /> 秒
          <span class="form-tip-inline">连续失败 {{ form.fail_count }} 次判不可用 / 连续成功 {{ form.up_count }} 次判恢复</span>
        </el-form-item>
        <el-form-item label="失败/成功阈值">
          <el-input-number v-model="form.fail_count" :min="1" :max="10" /> /
          <el-input-number v-model="form.up_count" :min="1" :max="10" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh } from '@element-plus/icons-vue'
import api from '../api'

const egresses = ref([])
const ifaces = ref([])
const loading = ref(false)
const dialogVisible = ref(false)
const editing = ref(null)
const saving = ref(false)

const emptyForm = () => ({
  name: '', iface: '', gateway_v4: '', gateway_v6: '',
  priority: 10, weight: 1, probe_mode: 'icmp-gw', probe_target: '',
  interval_sec: 3, fail_count: 2, up_count: 2,
})
const form = ref(emptyForm())

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/egresses')
    egresses.value = data.items || []
  } catch (e) {
    ElMessage.error(e.error || '加载失败')
  } finally {
    loading.value = false
  }
}

async function loadIfaces() {
  try {
    const { data } = await api.get('/interfaces')
    ifaces.value = data.items || []
  } catch { /* 静默 */ }
}

function shortTarget(t) { return t && t.length > 18 ? t.slice(0, 16) + '…' : t }

function openCreate() { editing.value = null; form.value = emptyForm(); dialogVisible.value = true }
function openEdit(row) {
  editing.value = row
  form.value = {
    name: row.name, iface: row.iface, gateway_v4: row.gateway_v4, gateway_v6: row.gateway_v6,
    priority: row.priority, weight: row.weight, probe_mode: row.probe_mode, probe_target: row.probe_target,
    interval_sec: row.interval_sec, fail_count: row.fail_count, up_count: row.up_count,
  }
  dialogVisible.value = true
}

async function save() {
  const f = form.value
  if (!f.name) return ElMessage.error('出口名称不能为空')
  if (!f.iface) return ElMessage.error('出口网卡必选')
  if (!f.gateway_v4 && !f.gateway_v6) return ElMessage.error('至少配置一个网关')
  if ((f.probe_mode === 'icmp-target' || f.probe_mode === 'tcp-target') && !f.probe_target.trim())
    return ElMessage.error('当前探测方式需要填写探测目标')
  saving.value = true
  try {
    if (editing.value) await api.put(`/egresses/${editing.value.id}`, f)
    else await api.post('/egresses', f)
    ElMessage.success('已保存')
    dialogVisible.value = false
    load()
  } catch (e) {
    ElMessage.error(e.error || '保存失败')
  } finally {
    saving.value = false
  }
}

async function toggle(row, v) {
  try {
    await api.put(`/egresses/${row.id}`, { ...row, enabled: v })
    row.enabled = v
    load()
  } catch (e) {
    ElMessage.error(e.error || '操作失败')
  }
}

async function probe(row) {
  try {
    const res = await api.post(`/egresses/${row.id}/probe`)
    ElMessage({
      message: res.up ? `可达（${res.latency_ms}ms）` : `不可达：${res.reason || '未知原因'}`,
      type: res.up ? 'success' : 'warning',
    })
  } catch (e) {
    ElMessage.error(e.error || '探测失败')
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`删除出口「${row.name}」？绑定它的规则需先解绑`, '确认删除', { type: 'warning' })
  } catch { return }
  try {
    await api.delete(`/egresses/${row.id}`)
    ElMessage.success('已删除')
    load()
  } catch (e) {
    ElMessage.error(e.error || '删除失败')
  }
}

onMounted(() => { load(); loadIfaces() })
</script>

<style scoped>
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.toolbar-left { display: flex; align-items: center; gap: 12px; }
.tip { color: var(--el-text-color-secondary); font-size: 12px; }
.sub { color: var(--el-text-color-secondary); font-size: 12px; }
.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.form-tip { color: var(--el-text-color-secondary); font-size: 12px; line-height: 1.4; margin-top: 4px; width: 100%; }
.form-tip-inline { color: var(--el-text-color-secondary); font-size: 12px; margin-left: 12px; }
</style>
