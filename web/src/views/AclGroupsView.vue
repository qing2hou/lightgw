<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建{{ typeLabel }}</el-button>
          <span class="tip">{{ typeTip }}</span>
        </div>
        <el-button :icon="Refresh" circle @click="load" />
      </div>

      <el-table :data="groups" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="name" label="组名" min-width="140" />
        <el-table-column v-if="modeFilter === 'ip'" label="条目数" width="90">
          <template #default="{ row }">
            <span class="mono">{{ row.entry_count }}</span>
          </template>
        </el-table-column>
        <el-table-column label="条目预览" min-width="240" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono sub">{{ preview(row.entries) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="被引用" width="110">
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
        <template #empty>还没有{{ typeLabel }}，点击左上角新建</template>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="(editing ? '编辑' : '新建') + typeLabel" width="560px" destroy-on-close>
      <el-form :model="form" label-width="90px">
        <el-form-item label="组名" required>
          <el-input v-model="form.name" :placeholder="namePlaceholder" maxlength="64" />
        </el-form-item>
        <el-form-item :label="modeFilter === 'ip' ? '条目' : (form.mode === 'whitelist' ? '白名单' : '黑名单')">
          <div class="list-editor">
            <div class="tags" v-if="form.entries.length">
              <el-tag
                v-for="e in form.entries" :key="e" closable
                :type="modeFilter === 'blacklist' ? 'danger' : modeFilter === 'ip' ? 'info' : 'success'"
                class="tag" @close="removeEntry(e)"
              >{{ e }}</el-tag>
            </div>
            <div class="input-line">
              <el-input v-model="entryInput" placeholder="例如 192.168.1.10 或 10.0.0.0/8" size="small" @keyup.enter="addEntry" class="mono-input" />
              <el-button size="small" @click="addEntry">添加</el-button>
            </div>
            <div class="form-tip">{{ entryTip }}</div>
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
import { reactive, ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh } from '@element-plus/icons-vue'
import api, { errMsg } from '../api'

// 三个菜单共用本视图，按路由 meta.groupMode 区分类型：
// whitelist=白名单组（源放行集合）、blacklist=黑名单组（源拒绝集合）、
// ip=IP 组（中性地址集合，可被白/黑名单或 SNAT 目标限制任意引用）
const route = useRoute()
const modeFilter = computed(() => route.meta.groupMode || 'whitelist')

const typeLabel = computed(() => ({
  whitelist: '白名单组', blacklist: '黑名单组', ip: 'IP 组',
}[modeFilter.value] || '名单组'))

const typeTip = computed(() => ({
  whitelist: '白名单组只能被「白名单」模式引用：仅组内来源/目标可通过',
  blacklist: '黑名单组只能被「黑名单」模式引用：命中组内条目即拒绝',
  ip: 'IP 组不带方向语义，可被白名单、黑名单或 SNAT 目标限制任意引用，条目按引用方的语义生效',
}[modeFilter.value] || ''))

const entryTip = computed(() => ({
  whitelist: '仅名单内 IP 可访问，其余全部拒绝',
  blacklist: '命中名单的 IP 直接拒绝，其余放行',
  ip: '中性地址集合：被引用时按引用方的模式（白名单/黑名单/目标限制）生效',
}[modeFilter.value] || ''))

const namePlaceholder = computed(() => ({
  whitelist: '例如：办公网段放行',
  blacklist: '例如：恶意来源封禁',
  ip: '例如：内网全部网段 / 云厂商地址',
}[modeFilter.value] || '例如：内网网段'))

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
    // 接口返回全部组，本页只显示当前菜单对应的类型
    groups.value = (data.items || []).filter((g) => g.mode === modeFilter.value)
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  Object.assign(form, { name: '', mode: modeFilter.value, entries: [] })
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
  if (!form.entries.length) return ElMessage.warning('至少添加一条条目')
  saving.value = true
  try {
    // 类型固定为当前菜单的类型（跨菜单改类型需先解除引用，故不在本页提供）
    const payload = { name: form.name.trim(), mode: modeFilter.value, entries: form.entries }
    if (editing.value) {
      await api.put(`/acl-groups/${editing.value.id}`, payload)
      ElMessage.success('已保存，引用中的规则已联动更新')
    } else {
      await api.post('/acl-groups', payload)
      ElMessage.success(typeLabel.value + '已创建')
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
        ? `${typeLabel.value}「${row.name}」仍被 ${row.ref_count} 条规则引用，无法删除。请先在规则中解除引用。`
        : `确定删除${typeLabel.value}「${row.name}」？`,
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
