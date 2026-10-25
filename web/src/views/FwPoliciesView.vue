<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建策略</el-button>
          <span class="tip">有序访问策略（先命中先适用）：drop 终结拒绝，accept 放行打标——已建会话不受影响</span>
        </div>
        <el-button :icon="Refresh" circle @click="load" />
      </div>

      <el-table :data="policies" stripe v-loading="loading" row-key="id">
        <el-table-column prop="order" label="序" width="60" />
        <el-table-column prop="name" label="名称" min-width="120" show-overflow-tooltip />
        <el-table-column label="动作" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.action === 'drop' ? 'danger' : 'success'">
              {{ row.action === 'drop' ? '拒绝' : '放行' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="来源" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.src_list && row.src_list.length" class="mono">{{ joinN(row.src_list) }}</span>
            <span v-else class="sub">任意</span>
          </template>
        </el-table-column>
        <el-table-column label="目标" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.dst_list && row.dst_list.length" class="mono">{{ joinN(row.dst_list) }}</span>
            <span v-else class="sub">任意</span>
          </template>
        </el-table-column>
        <el-table-column label="协议" width="80">
          <template #default="{ row }"><el-tag size="small" type="info">{{ (row.proto || 'any').toUpperCase() }}</el-tag></template>
        </el-table-column>
        <el-table-column label="端口" min-width="110">
          <template #default="{ row }">
            <span v-if="row.port_range" class="mono">{{ row.port_range }}</span>
            <span v-else class="sub">全部</span>
          </template>
        </el-table-column>
        <el-table-column label="命中" width="130">
          <template #default="{ row }">
            <span v-if="row.stats" class="mono sub">{{ row.stats.pkts }} 包 / {{ fmtBytes(row.stats.bytes) }}</span>
            <span v-else class="sub">-</span>
          </template>
        </el-table-column>
        <el-table-column label="启用" width="80">
          <template #default="{ row }">
            <el-switch :model-value="row.enabled" @change="(v) => toggle(row, v)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" :disabled="row.order <= 1" @click="move(row, -1)">上移</el-button>
            <el-button link type="primary" size="small" :disabled="row.order >= policies.length" @click="move(row, 1)">下移</el-button>
            <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>还没有策略；无策略时穿越/发布仅受规则自身名单管控</template>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑策略' : '新建策略'" width="560px" destroy-on-close>
      <el-form :model="form" label-width="90px">
        <el-form-item label="策略名称" required>
          <el-input v-model="form.name" placeholder="例如：禁止办公网访问外部 25 端口" maxlength="64" />
        </el-form-item>
        <el-form-item label="动作" required>
          <el-radio-group v-model="form.action">
            <el-radio value="accept">放行（accept）</el-radio>
            <el-radio value="drop">拒绝（drop）</el-radio>
          </el-radio-group>
          <div v-if="form.action === 'drop'" class="form-tip">拒绝策略创建时可选择立即掐断匹配的存量会话</div>
        </el-form-item>
        <el-form-item label="协议">
          <el-select v-model="form.proto" style="width: 100%">
            <el-option label="TCP" value="tcp" />
            <el-option label="UDP" value="udp" />
            <el-option label="ICMP" value="icmp" />
            <el-option label="任意" value="any" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.proto === 'tcp' || form.proto === 'udp'" label="端口">
          <el-input v-model="form.port_range" placeholder="如 80 或 80,443,1000-2000（空=全部）" class="mono-input" />
        </el-form-item>
        <el-form-item label="来源">
          <el-input v-model="form.src_list" type="textarea" :rows="2" placeholder='JSON 数组，空 = 任意：["192.168.1.0/24"]' class="mono-input" />
        </el-form-item>
        <el-form-item label="目标">
          <el-input v-model="form.dst_list" type="textarea" :rows="2" placeholder='JSON 数组，空 = 任意：["10.0.0.0/8", "8.8.8.8"]' class="mono-input" />
        </el-form-item>
        <el-form-item v-if="form.action === 'drop'" label="掐断存量">
          <el-switch v-model="form.kill_established" />
          <div class="form-tip">开启后保存时立即掐断匹配该策略的已建会话</div>
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

const policies = ref([])
const loading = ref(false)
const dialogVisible = ref(false)
const editing = ref(null)
const saving = ref(false)

const emptyForm = () => ({ name: '', action: 'drop', proto: 'tcp', port_range: '', src_list: '', dst_list: '', kill_established: false })
const form = ref(emptyForm())

async function load() {
  loading.value = true
  try {
    const res = await api.get('/fw-policies')
    policies.value = res.items || []
  } catch (e) {
    ElMessage.error(e.error || '加载失败')
  } finally {
    loading.value = false
  }
}

function joinN(list) {
  return list.length > 2 ? list.slice(0, 2).join('、') + `…（${list.length}）` : list.join('、')
}
function fmtBytes(b) {
  if (b > 1024 * 1024 * 1024) return (b / 1024 / 1024 / 1024).toFixed(1) + 'G'
  if (b > 1024 * 1024) return (b / 1024 / 1024).toFixed(1) + 'M'
  if (b > 1024) return (b / 1024).toFixed(1) + 'K'
  return b + ''
}

function openCreate() { editing.value = null; form.value = emptyForm(); dialogVisible.value = true }
function openEdit(row) {
  editing.value = row
  form.value = {
    name: row.name, action: row.action, proto: row.proto || 'tcp', port_range: row.port_range || '',
    src_list: row.src_list && row.src_list.length ? JSON.stringify(row.src_list) : '',
    dst_list: row.dst_list && row.dst_list.length ? JSON.stringify(row.dst_list) : '',
    kill_established: false,
  }
  dialogVisible.value = true
}

async function save() {
  const f = form.value
  if (!f.name) return ElMessage.error('策略名称不能为空')
  const body = { name: f.name, action: f.action, proto: f.proto, port_range: f.port_range.trim(), kill_established: f.kill_established }
  body.src_list = f.src_list.trim()
  body.dst_list = f.dst_list.trim()
  saving.value = true
  try {
    if (editing.value) await api.put(`/fw-policies/${editing.value.id}`, body)
    else await api.post('/fw-policies', body)
    ElMessage.success('已保存并生效')
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
    await api.put(`/fw-policies/${row.id}`, { enabled: v, name: row.name, action: row.action, proto: row.proto, port_range: row.port_range, comment: row.comment || '', src_list: JSON.stringify(row.src_list || []), dst_list: JSON.stringify(row.dst_list || []) })
    row.enabled = v
    load()
  } catch (e) {
    ElMessage.error(e.error || '操作失败')
  }
}

async function move(row, dir) {
  const idx = policies.value.findIndex(p => p.id === row.id)
  const n = idx + dir
  if (idx < 0 || n < 0 || n >= policies.value.length) return
  const ids = policies.value.map(p => p.id)
  ;[ids[idx], ids[n]] = [ids[n], ids[idx]]
  try {
    await api.put('/fw-policies/reorder', { ordered_ids: ids })
    load()
  } catch (e) {
    ElMessage.error(e.error || '调整顺序失败')
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`删除策略「${row.name}」？`, '确认删除', { type: 'warning' })
  } catch { return }
  try {
    await api.delete(`/fw-policies/${row.id}`)
    ElMessage.success('已删除并生效')
    load()
  } catch (e) {
    ElMessage.error(e.error || '删除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.toolbar-left { display: flex; align-items: center; gap: 12px; }
.tip { color: var(--el-text-color-secondary); font-size: 12px; }
.sub { color: var(--el-text-color-secondary); font-size: 12px; }
.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.form-tip { color: var(--el-text-color-secondary); font-size: 12px; line-height: 1.4; margin-top: 4px; width: 100%; }
</style>
