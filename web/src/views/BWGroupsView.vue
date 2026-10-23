<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建带宽包</el-button>
          <span class="tip">多条转发规则共用一个下载（出向）带宽额度——成员流量合计不超额；规则入包后自身限速不再生效</span>
        </div>
        <el-button :icon="Refresh" circle @click="load" />
      </div>

      <el-table :data="groups" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="name" label="名称" min-width="130" />
        <el-table-column label="合计额度" width="130">
          <template #default="{ row }">
            <el-tag type="warning" size="small">{{ formatRate(row.total_kbps) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="每源保底" width="110">
          <template #default="{ row }">
            <span class="mono">{{ formatRate(row.min_kbps || 1024) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="成员规则" min-width="260">
          <template #default="{ row }">
            <template v-if="row.members.length">
              <el-tag v-for="m in row.members" :key="m.id" size="small" class="m-tag"
                :type="protoType(m.protocol)">{{ m.name }}</el-tag>
            </template>
            <span v-else class="sub">（空——尚未绑定规则）</span>
          </template>
        </el-table-column>
        <el-table-column label="成员数" width="80">
          <template #default="{ row }"><span class="mono">{{ row.members.length }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="130" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>还没有带宽包，点击左上角新建</template>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑带宽包' : '新建带宽包'" width="560px" destroy-on-close>
      <el-form :model="form" label-width="100px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="例如：办公网段出口" maxlength="64" />
        </el-form-item>
        <el-form-item label="合计额度" required>
          <el-input-number v-model="form.total_kbps" :min="1" :max="1048576" :step="1024" />
          <span class="unit">KB/s</span>
          <span class="form-tip-inline">上下行合计单额度——成员规则流量共享</span>
        </el-form-item>
        <el-form-item label="每源保底" required>
          <el-input-number v-model="form.min_kbps" :min="0" :max="1048576" :step="256" />
          <span class="unit">KB/s</span>
          <span class="form-tip-inline">拥塞时每个源 IP 至少可用；闲时各源可借用至合计额度。0 = 默认 1024（1M）</span>
        </el-form-item>
        <el-form-item label="成员规则">
          <el-select v-model="form.member_rule_ids" multiple filterable placeholder="选择规则（可多选）" style="width: 100%">
            <el-option v-for="r in availableRules" :key="r.id" :value="r.id"
              :label="`${r.name}（${r.protocol.toUpperCase()} #${r.id}）`"
              :disabled="!!r.bandwidth_group && r.bandwidth_group.id !== (editing && editing.id)" />
          </el-select>
          <div class="form-tip">
            成员规则自身限速将不再生效（由本包额度管控）；仅支持 SNAT 规则（tcp/udp 暂不支持共享）；灰色选项已属于其他带宽包
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
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh } from '@element-plus/icons-vue'
import api, { errMsg } from '../api'

const groups = ref([])
const rules = ref([])
const loading = ref(false)
const dialogVisible = ref(false)
const editing = ref(null)
const saving = ref(false)
const form = reactive({ name: '', total_kbps: 4096, min_kbps: 1024, member_rule_ids: [] })

const availableRules = computed(() => rules.value.filter((r) => r.enabled))
const formatRate = (kbps) => (kbps >= 1024 ? (kbps / 1024).toFixed(kbps % 1024 ? 1 : 0) + ' MB/s' : kbps + ' KB/s')
const protoType = (p) => ({ tcp: 'primary', udp: 'warning', snat: 'success' }[p] || 'info')

async function load() {
  loading.value = true
  try {
    const [g, r] = await Promise.all([api.get('/bandwidth-groups'), api.get('/rules', { params: { page: 1, page_size: 200 } })])
    groups.value = g.data.items || []
    rules.value = r.data.items || []
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  Object.assign(form, { name: '', total_kbps: 4096, min_kbps: 1024, member_rule_ids: [] })
  dialogVisible.value = true
}

function openEdit(row) {
  editing.value = row
  Object.assign(form, {
    name: row.name,
    total_kbps: row.total_kbps,
    min_kbps: row.min_kbps || 1024,
    member_rule_ids: (row.members || []).map((m) => m.id),
  })
  dialogVisible.value = true
}

async function save() {
  if (!form.name.trim()) return ElMessage.warning('请填写名称')
  if (!form.total_kbps || form.total_kbps <= 0) return ElMessage.warning('合计额度必须大于 0')
  saving.value = true
  try {
    const payload = { name: form.name.trim(), total_kbps: form.total_kbps, min_kbps: form.min_kbps || 0, member_rule_ids: form.member_rule_ids }
    if (editing.value) {
      await api.put(`/bandwidth-groups/${editing.value.id}`, payload)
      ElMessage.success('已保存（额度与成员实时生效）')
    } else {
      await api.post('/bandwidth-groups', payload)
      ElMessage.success('带宽包已创建')
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
  if (row.members.length) {
    ElMessage.warning(`带宽包「${row.name}」仍有 ${row.members.length} 条成员规则，请先在编辑中解除全部成员`)
    return
  }
  try {
    await ElMessageBox.confirm(`确定删除带宽包「${row.name}」？`, '删除确认', { type: 'warning' })
  } catch (e) {
    return
  }
  try {
    await api.delete(`/bandwidth-groups/${row.id}`)
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
}
.sub {
  color: #909399;
  font-size: 12px;
}
.m-tag {
  margin: 0 6px 6px 0;
}
.unit {
  margin-left: 8px;
  color: #606266;
}
.form-tip {
  color: #909399;
  font-size: 12px;
  line-height: 1.5;
  margin-top: 4px;
}
.form-tip-inline {
  color: #909399;
  font-size: 12px;
  margin-left: 6px;
}
</style>
