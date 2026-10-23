<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建名单组</el-button>
          <span class="tip">规则在「转发规则」页编辑时可直接引用名单组，组条目变更即时热生效（联动重应用引用中的规则）</span>
        </div>
        <el-button :icon="Refresh" circle @click="load" />
      </div>

      <el-table :data="groups" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="name" label="组名" min-width="140" />
        <el-table-column label="类型" width="110">
          <template #default="{ row }">
            <el-tag :type="row.mode === 'whitelist' ? 'success' : 'danger'" size="small">
              {{ row.mode === 'whitelist' ? '白名单组' : '黑名单组' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="条目数" width="90">
          <template #default="{ row }">
            <span class="mono">{{ row.entry_count }}</span>
          </template>
        </el-table-column>
        <el-table-column label="条目预览" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono sub">{{ preview(row.entries) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="被引用" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.ref_count > 0" size="small" type="primary">{{ row.ref_count }} 条规则</el-tag>
            <span v-else class="sub">未引用</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="130" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>还没有名单组，点击左上角新建</template>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑名单组' : '新建名单组'" width="560px" destroy-on-close>
      <el-form :model="form" label-width="90px">
        <el-form-item label="组名" required>
          <el-input v-model="form.name" placeholder="例如：内网放行 / 办公网段" maxlength="64" />
        </el-form-item>
        <el-form-item label="类型" required>
          <el-radio-group v-model="form.mode" :disabled="!!editing && editing.ref_count > 0">
            <el-radio-button value="whitelist">白名单组</el-radio-button>
            <el-radio-button value="blacklist">黑名单组</el-radio-button>
          </el-radio-group>
          <div class="form-tip" v-if="editing && editing.ref_count > 0">已被规则引用的组不能变更类型，请先在规则中解除引用</div>
        </el-form-item>
        <el-form-item :label="form.mode === 'whitelist' ? '白名单' : '黑名单'">
          <div class="list-editor">
            <div class="tags" v-if="form.entries.length">
              <el-tag
                v-for="e in form.entries" :key="e" closable
                :type="form.mode === 'whitelist' ? 'success' : 'danger'"
                class="tag" @close="removeEntry(e)"
              >{{ e }}</el-tag>
            </div>
            <div class="input-line">
              <el-input v-model="entryInput" placeholder="例如 192.168.1.10 或 10.0.0.0/8" size="small" @keyup.enter="addEntry" class="mono-input" />
              <el-button size="small" @click="addEntry">添加</el-button>
            </div>
            <div class="form-tip">{{ form.mode === 'whitelist' ? '仅名单内 IP 可访问，其余全部拒绝' : '命中名单的 IP 直接拒绝，其余放行' }}</div>
          </div>
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
import { reactive, ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh } from '@element-plus/icons-vue'
import api, { errMsg } from '../api'

const groups = ref([])
const loading = ref(false)
const dialogVisible = ref(false)
const editing = ref(null)
const saving = ref(false)
const entryInput = ref('')
const form = reactive({ name: '', mode: 'whitelist', entries: [] })

function preview(entries) {
  try {
    const list = JSON.parse(entries || '[]')
    return list.length > 6 ? list.slice(0, 6).join(', ') + ` …（共 ${list.length} 条）` : list.join(', ')
  } catch (e) {
    return entries
  }
}

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/acl-groups')
    groups.value = data.items || []
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  Object.assign(form, { name: '', mode: 'whitelist', entries: [] })
  entryInput.value = ''
  dialogVisible.value = true
}

function openEdit(row) {
  editing.value = row
  let entries = []
  try {
    entries = JSON.parse(row.entries || '[]')
  } catch (e) { /* 保留空 */ }
  Object.assign(form, { name: row.name, mode: row.mode, entries })
  entryInput.value = ''
  dialogVisible.value = true
}

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-fA-F:]{2,45}(\/\d{1,3})?$/

function addEntry() {
  const v = entryInput.value.trim()
  if (!v) return
  if (!IP_RE.test(v)) {
    ElMessage.warning('格式应为 IP（1.2.3.4）或 CIDR 网段（192.168.1.0/24）')
    return
  }
  if (!form.entries.includes(v)) form.entries.push(v)
  entryInput.value = ''
}

function removeEntry(e) {
  form.entries = form.entries.filter((x) => x !== e)
}

async function save() {
  if (!form.name.trim()) return ElMessage.warning('请填写组名')
  if (!form.entries.length) return ElMessage.warning('至少添加一条名单条目')
  saving.value = true
  try {
    const payload = { name: form.name.trim(), mode: form.mode, entries: form.entries }
    if (editing.value) {
      await api.put(`/acl-groups/${editing.value.id}`, payload)
      ElMessage.success('已保存，引用中的规则已联动更新')
    } else {
      await api.post('/acl-groups', payload)
      ElMessage.success('名单组已创建')
    }
    dialogVisible.value = false
    await load()
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    saving.value = false
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(
      row.ref_count > 0
        ? `名单组「${row.name}」仍被 ${row.ref_count} 条规则引用，无法删除。请先在规则中解除引用。`
        : `确定删除名单组「${row.name}」？`,
      '删除确认',
      { type: 'warning', showCancelButton: row.ref_count === 0, confirmButtonText: row.ref_count > 0 ? '知道了' : '删除' }
    )
  } catch (e) {
    return
  }
  try {
    await api.delete(`/acl-groups/${row.id}`)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    ElMessage.error(errMsg(e))
  }
}

onMounted(load)
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
  gap: 10px;
  align-items: center;
}
.tip {
  color: #909399;
  font-size: 12px;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.sub {
  color: #909399;
  font-size: 12px;
}
.form-tip {
  color: #909399;
  font-size: 12px;
  line-height: 1.5;
  margin-top: 4px;
}
.list-editor {
  width: 100%;
}
.tags {
  margin-bottom: 6px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.input-line {
  display: flex;
  gap: 8px;
}
.mono-input :deep(input) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
</style>
