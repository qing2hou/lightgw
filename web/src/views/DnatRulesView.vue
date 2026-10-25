<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建端口发布</el-button>
          <span class="tip">把内网服务发布到本机公网 IP:端口（内核 DNAT 线速转发，受源白名单管控）</span>
        </div>
        <el-button :icon="Refresh" circle @click="load" />
      </div>

      <el-table :data="rules" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="name" label="名称" min-width="130" show-overflow-tooltip>
          <template #default="{ row }">
            <span>{{ row.name }}</span>
            <el-tooltip v-if="row.last_error" :content="row.last_error" placement="top">
              <el-tag size="small" type="danger" class="err-tag">异常</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="发布地址" width="180">
          <template #default="{ row }"><code>{{ row.listen_addr }}</code></template>
        </el-table-column>
        <el-table-column label="内网后端" width="180">
          <template #default="{ row }"><code>{{ row.target_addr }}</code></template>
        </el-table-column>
        <el-table-column label="后端状态" width="90">
          <template #default="{ row }">
            <el-tag v-if="row.health && row.health.checked" size="small" :type="row.health.up ? 'success' : 'danger'">
              {{ row.health.up ? '正常' : '异常' }}
            </el-tag>
            <span v-else class="sub">未检</span>
          </template>
        </el-table-column>
        <el-table-column label="来源白名单" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tooltip v-if="row.acl_mode === 'whitelist'" placement="top">
              <template #content>
                <div>仅这些来源可访问：</div>
                <div v-for="s in parseList(row.allow_list)" :key="s">{{ s }}</div>
              </template>
              <span class="mono">{{ srcPreview(row) }}</span>
            </el-tooltip>
            <span v-else class="sub">全放行</span>
          </template>
        </el-table-column>
        <el-table-column label="不可达行为" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.dnat_reject_mode === 'timeout' ? 'warning' : 'info'">
              {{ row.dnat_reject_mode === 'timeout' ? '超时' : '拒绝' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="访问统计" width="110">
          <template #default="{ row }">
            <span v-if="row.snat" class="mono sub">{{ row.snat.packets }} 包</span>
            <span v-else class="sub">-</span>
          </template>
        </el-table-column>
        <el-table-column label="启用" width="80">
          <template #default="{ row }">
            <el-switch :model-value="row.enabled" @change="(v) => toggle(row, v)" :loading="row._toggling" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="130" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>还没有端口发布规则，点击左上角新建</template>
      </el-table>

      <div class="pager">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :total="total"
          layout="total, prev, pager, next"
          @current-change="onPageChange"
        />
      </div>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑端口发布' : '新建端口发布'" width="600px" top="6vh" destroy-on-close>
      <el-form :model="form" label-width="100px" class="rule-form-scroll">
        <el-form-item label="规则名称" required>
          <el-input v-model="form.name" placeholder="例如：官网 443 发布" maxlength="64" />
        </el-form-item>
        <el-form-item label="发布地址" required>
          <el-select v-model="form.listen_ip" filterable placeholder="公网 IP（本机网卡上的地址）" style="width: 55%" class="mono-input">
            <el-option v-for="ip in allIPs" :key="ip.ip" :value="ip.ip" :label="`${ip.ip}（${ip.iface}）`" />
          </el-select>
          <el-input-number v-model="form.listen_port" :min="1" :max="65535" placeholder="端口" style="width: 40%; margin-left: 5%" />
        </el-form-item>
        <el-form-item label="内网后端" required>
          <el-input v-model="form.target_ip" placeholder="内网 IP（如 10.0.1.5）" style="width: 55%" class="mono-input" />
          <el-input-number v-model="form.target_port" :min="1" :max="65535" placeholder="端口" style="width: 40%; margin-left: 5%" />
        </el-form-item>
        <el-form-item label="来源白名单">
          <el-select v-model="form.acl_mode" style="width: 40%">
            <el-option label="白名单（仅名单内可访问）" value="whitelist" />
            <el-option label="不限来源" value="off" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.acl_mode === 'whitelist'" label="白名单条目">
          <el-input v-model="form.allow_list" type="textarea" :rows="3" placeholder='JSON 数组：["58.66.1.0/24", "203.0.113.5"]' class="mono-input" />
        </el-form-item>
        <el-form-item label="不可达行为">
          <el-radio-group v-model="form.dnat_reject_mode">
            <el-radio value="reject">即时拒绝（reset/admin-prohibited）</el-radio>
            <el-radio value="timeout">静默丢弃（客户端超时）</el-radio>
          </el-radio-group>
          <div class="form-tip">后端健康检查失败时发布卸载，客户端看到的行为由该项决定</div>
        </el-form-item>
        <el-form-item label="健康检查">
          <el-switch v-model="form.health_check" />
          <div class="form-tip">TCP 探测后端；不可达自动卸载发布、恢复自动重挂</div>
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

const rules = ref([])
const ifaces = ref([])
const allIPs = ref([])
const loading = ref(false)
const page = ref(1)
const pageSize = 20
const total = ref(0)
const dialogVisible = ref(false)
const editing = ref(null)
const saving = ref(false)

const emptyForm = () => ({
  name: '', listen_ip: '', listen_port: 443, target_ip: '', target_port: 80,
  acl_mode: 'whitelist', allow_list: '', dnat_reject_mode: 'reject', health_check: true,
})
const form = ref(emptyForm())

async function load() {
  loading.value = true
  try {
    const res = await api.get('/rules', { params: { protocol: 'dnat', page: page.value, page_size: pageSize } })
    rules.value = res.items || []
    total.value = res.total || 0
  } catch (e) {
    ElMessage.error(e.error || '加载失败')
  } finally {
    loading.value = false
  }
}

async function loadIfaces() {
  try {
    const res = await api.get('/interfaces')
    ifaces.value = res.items || res || []
    const ips = []
    for (const i of ifaces.value) {
      for (const ip of i.ips || []) ips.push({ ip, iface: i.name })
    }
    allIPs.value = ips
  } catch { /* 静默 */ }
}

function parseList(s) {
  try { return JSON.parse(s || '[]') } catch { return [] }
}
function srcPreview(row) {
  const l = parseList(row.allow_list)
  return l.length ? (l.length > 2 ? l.slice(0, 2).join('、') + `…（${l.length}）` : l.join('、')) : '（空）'
}

function openCreate() {
  editing.value = null
  form.value = emptyForm()
  dialogVisible.value = true
}
function openEdit(row) {
  editing.value = row
  const [lip, lport] = (row.listen_addr || '').split(':')
  const [tip, tport] = (row.target_addr || '').split(':')
  form.value = {
    name: row.name, listen_ip: lip, listen_port: Number(lport) || 443,
    target_ip: tip, target_port: Number(tport) || 80,
    acl_mode: row.acl_mode || 'off', allow_list: row.allow_list || '',
    dnat_reject_mode: row.dnat_reject_mode || 'reject',
    health_check: row.health_check !== false,
  }
  dialogVisible.value = true
}

async function save() {
  const f = form.value
  if (!f.name) return ElMessage.error('规则名称不能为空')
  if (!f.listen_ip || !f.listen_port) return ElMessage.error('发布地址（IP 与端口）必填')
  if (!f.target_ip || !f.target_port) return ElMessage.error('内网后端（IP 与端口）必填')
  if (f.acl_mode === 'whitelist' && !f.allow_list.trim()) return ElMessage.error('白名单模式需填写名单条目')
  const body = {
    name: f.name, protocol: 'dnat',
    listen_addr: `${f.listen_ip}:${f.listen_port}`,
    target_addr: `${f.target_ip}:${f.target_port}`,
    acl_mode: f.acl_mode, allow_list: f.acl_mode === 'whitelist' ? f.allow_list.trim() : '',
    dnat_reject_mode: f.dnat_reject_mode,
    health_check: f.health_check, enabled: true,
  }
  saving.value = true
  try {
    if (editing.value) await api.put(`/rules/${editing.value.id}`, body)
    else await api.post('/rules', body)
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
  row._toggling = true
  try {
    await api.post(`/rules/${row.id}/${v ? 'enable' : 'disable'}`)
    row.enabled = v
  } catch (e) {
    ElMessage.error(e.error || '操作失败')
  } finally {
    row._toggling = false
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`删除端口发布「${row.name}」？存量会话将立即掐断`, '确认删除', { type: 'warning' })
  } catch { return }
  try {
    await api.delete(`/rules/${row.id}`)
    ElMessage.success('已删除')
    load()
  } catch (e) {
    ElMessage.error(e.error || '删除失败')
  }
}

function onPageChange(p) {
  page.value = p
  load()
}

onMounted(() => { load(); loadIfaces() })
</script>

<style scoped>
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.toolbar-left { display: flex; align-items: center; gap: 12px; }
.tip { color: var(--el-text-color-secondary); font-size: 12px; }
.sub { color: var(--el-text-color-secondary); font-size: 12px; }
.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.err-tag { margin-left: 6px; }
.pager { margin-top: 12px; display: flex; justify-content: flex-end; }
.form-tip { color: var(--el-text-color-secondary); font-size: 12px; line-height: 1.4; margin-top: 4px; width: 100%; }
</style>
