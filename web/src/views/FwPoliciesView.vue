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
          <div class="list-editor">
            <div class="tags" v-if="form.src.length">
              <el-tag v-for="t in form.src" :key="t" closable @close="removeTag('src', t)" class="tag">{{ t }}</el-tag>
            </div>
            <div class="input-line">
              <el-input v-model="srcInput" placeholder="例如 192.168.1.10 或 10.0.0.0/24" size="small"
                        @keyup.enter="addTag('src')" class="mono-input" />
              <el-button size="small" @click="addTag('src')">添加</el-button>
            </div>
            <div class="form-tip">留空 = 任意来源</div>
          </div>
        </el-form-item>
        <el-form-item label="目标">
          <div class="list-editor">
            <div class="tags" v-if="form.dst.length">
              <el-tag v-for="t in form.dst" :key="t" closable @close="removeTag('dst', t)" class="tag">{{ t }}</el-tag>
            </div>
            <div class="input-line">
              <el-input v-model="dstInput" placeholder="例如 8.8.8.8 或 10.0.0.0/8" size="small"
                        @keyup.enter="addTag('dst')" class="mono-input" />
              <el-button size="small" @click="addTag('dst')">添加</el-button>
            </div>
            <div class="form-tip">留空 = 任意目标</div>
          </div>
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
const srcInput = ref('')
const dstInput = ref('')

// 来源/目标用标签输入而不是手写 JSON 数组。
//
// 改造前是两个 textarea，要求用户自己写 `["192.168.1.0/24"]`——
// 手写 JSON 极易出错（少引号、少逗号、直接写裸 IP），而报错信息
// `src_list 必须是 JSON 字符串数组: invalid character '.' ...`
// 对普通用户完全是天书。与规则页白名单输入保持同一套交互。
const emptyForm = () => ({
  name: '', action: 'drop', proto: 'tcp', port_range: '',
  src: [], dst: [], kill_established: false,
})
const form = ref(emptyForm())

// IP / CIDR 格式（与规则页白名单同一判据）
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-fA-F:]{2,45}(\/\d{1,3})?$/

function addTag(kind) {
  const input = kind === 'src' ? srcInput : dstInput
  const v = input.value.trim()
  if (!v) return
  if (!IP_RE.test(v)) {
    ElMessage.warning('格式应为 IP（1.2.3.4）或 CIDR 网段（192.168.1.0/24）')
    return
  }
  if (!form.value[kind].includes(v)) form.value[kind].push(v)
  input.value = ''
}

function removeTag(kind, tag) {
  form.value[kind] = form.value[kind].filter((t) => t !== tag)
}

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/fw-policies')
    policies.value = data.items || []
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

function openCreate() {
  editing.value = null
  form.value = emptyForm()
  srcInput.value = ''
  dstInput.value = ''
  dialogVisible.value = true
}
function openEdit(row) {
  editing.value = row
  form.value = {
    name: row.name, action: row.action, proto: row.proto || 'tcp', port_range: row.port_range || '',
    // 后端返回的 src_list 已由 API 层解析成数组；兼容旧数据的 JSON 字符串形态
    src: toList(row.src_list),
    dst: toList(row.dst_list),
    kill_established: false,
  }
  srcInput.value = ''
  dstInput.value = ''
  dialogVisible.value = true
}

// toList 归一化：数组直接用，JSON 字符串解析，其它（null/空）→ 空数组。
// 宁可返回空也不要抛错——编辑一条旧数据时不该让整个弹窗打不开。
function toList(v) {
  if (Array.isArray(v)) return v.slice()
  if (typeof v === 'string' && v.trim()) {
    try {
      const a = JSON.parse(v)
      return Array.isArray(a) ? a : []
    } catch {
      return []
    }
  }
  return []
}

async function save() {
  const f = form.value
  if (!f.name.trim()) return ElMessage.error('策略名称不能为空')
  // 输入框里还有没点"添加"的内容时，先追加进去，避免用户以为已生效
  if (srcInput.value.trim()) addTag('src')
  if (dstInput.value.trim()) addTag('dst')
  const body = {
    name: f.name.trim(),
    action: f.action,
    proto: f.proto,
    port_range: f.port_range.trim(),
    // 空列表传空串（后端"未配置=任意"的判据），非空才编码成 JSON 数组。
    // 注意不要传 "[]"——虽然 API 层的 isEmptyJSONList 能识别，但空串语义更明确。
    src_list: f.src.length ? JSON.stringify(f.src) : '',
    dst_list: f.dst.length ? JSON.stringify(f.dst) : '',
    kill_established: f.kill_established,
  }
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
    // 列表接口返回的 src_list/dst_list 是数组（parseListOrNull），
    // 提交时按后端契约编码成 JSON 字符串；空列表传空串（= 任意）。
    const src = toList(row.src_list)
    const dst = toList(row.dst_list)
    await api.put(`/fw-policies/${row.id}`, {
      enabled: v, name: row.name, action: row.action, proto: row.proto,
      port_range: row.port_range || '', comment: row.comment || '',
      src_list: src.length ? JSON.stringify(src) : '',
      dst_list: dst.length ? JSON.stringify(dst) : '',
    })
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
.list-editor { width: 100%; }
.tags { margin-bottom: 6px; display: flex; flex-wrap: wrap; gap: 6px; }
.input-line { display: flex; gap: 8px; }
</style>
