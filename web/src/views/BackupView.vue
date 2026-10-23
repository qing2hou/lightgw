<template>
  <div>
    <el-card>
      <div class="card-header">
        <span class="card-title">规则导出</span>
        <el-button type="primary" :loading="exporting" @click="exportRules">导出规则 JSON</el-button>
      </div>
      <div class="desc">
        导出全部转发规则（含访问控制名单、限速、空闲超时）为 JSON 文件，可用于备份或迁移到其他实例。
      </div>
    </el-card>

    <el-card>
      <div class="card-header">
        <span class="card-title">规则导入</span>
        <el-radio-group v-model="mode" :disabled="importing">
          <el-radio-button value="merge">合并（冲突跳过）</el-radio-button>
          <el-radio-button value="replace">全量替换</el-radio-button>
        </el-radio-group>
      </div>
      <el-upload
        drag
        accept=".json,application/json"
        :auto-upload="false"
        :limit="1"
        :on-change="onFileChange"
        :on-remove="onFileRemove"
      >
        <div class="upload-tip">拖拽 JSON 文件到此处，或点击选择（导出的规则文件）</div>
      </el-upload>
      <div class="btns">
        <el-button :disabled="!file" :loading="previewing" @click="preview">预览（不改动）</el-button>
        <el-button type="primary" :disabled="!file" :loading="importing" @click="doImport">执行导入</el-button>
      </div>
      <div v-if="summary" class="summary">
        <el-tag>共 {{ summary.total }} 条</el-tag>
        <el-tag type="success">导入 {{ summary.imported }}</el-tag>
        <el-tag type="warning">跳过 {{ summary.skipped }}</el-tag>
        <el-tag type="danger">失败 {{ summary.failed }}</el-tag>
        <el-tag v-if="summary.dry_run" type="info">预览模式，未做任何改动</el-tag>
      </div>
      <el-table v-if="items.length" :data="items" size="small" max-height="360">
        <el-table-column prop="index" label="#" width="60" />
        <el-table-column prop="name" label="规则" min-width="140" show-overflow-tooltip />
        <el-table-column label="结果" width="110">
          <template #default="{ row }">
            <el-tag :type="statusType[row.status] || 'info'" size="small">{{ statusText[row.status] || row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="reason" label="说明" min-width="180" show-overflow-tooltip />
      </el-table>
    </el-card>

    <el-card>
      <div class="card-header">
        <span class="card-title">全库快照</span>
        <el-button type="primary" :loading="backing" @click="downloadSnapshot">下载快照（.db）</el-button>
      </div>
      <div class="desc">
        完整数据库一致性快照（含用户账号、规则、流量与审计日志）。恢复方式：停止服务后用快照替换数据目录中的
        <code>haproxyweb.db</code> 再启动；恢复时需一并还原 <code>secret.key</code>，否则所有登录会话失效。详见 README「备份与恢复」。
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api, { errMsg } from '../api'

const exporting = ref(false)
const previewing = ref(false)
const importing = ref(false)
const backing = ref(false)
const file = ref(null)
const mode = ref('merge')
const summary = ref(null)
const items = ref([])

const statusText = { imported: '已导入', would_import: '可导入', skipped: '跳过', invalid: '格式错误', error: '失败' }
const statusType = { imported: 'success', would_import: 'primary', skipped: 'warning', invalid: 'danger', error: 'danger' }

function onFileChange(uploadFile) {
  file.value = uploadFile.raw
  summary.value = null
  items.value = []
}

function onFileRemove() {
  file.value = null
  summary.value = null
  items.value = []
}

// download 走 blob 下载并用响应头里的文件名保存
async function download(url, fallbackName) {
  const resp = await api.get(url, { responseType: 'blob' })
  const cd = resp.headers['content-disposition'] || ''
  const m = cd.match(/filename="?([^";]+)"?/)
  const name = m ? m[1] : fallbackName
  const objURL = URL.createObjectURL(resp.data)
  const a = document.createElement('a')
  a.href = objURL
  a.download = name
  a.click()
  URL.revokeObjectURL(objURL)
}

async function exportRules() {
  exporting.value = true
  try {
    await download('/rules/export', 'haproxyweb-rules.json')
    ElMessage.success('已导出')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    exporting.value = false
  }
}

async function downloadSnapshot() {
  backing.value = true
  try {
    await download('/backup/db', 'haproxyweb-backup.db')
    ElMessage.success('快照已下载')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    backing.value = false
  }
}

async function readPayload(f) {
  const text = await f.text()
  return JSON.parse(text)
}

function applyResult(data) {
  summary.value = data
  items.value = data.items || []
}

async function preview() {
  previewing.value = true
  try {
    const payload = await readPayload(file.value)
    const { data } = await api.post(`/rules/import?mode=${mode.value}&dry_run=true`, payload)
    applyResult(data)
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    previewing.value = false
  }
}

async function doImport() {
  if (mode.value === 'replace') {
    try {
      await ElMessageBox.confirm(
        '全量替换将删除服务器上全部现有规则，然后导入文件中的规则。此操作不可恢复，确定继续？',
        '危险操作确认',
        { type: 'warning', confirmButtonText: '确认替换', cancelButtonText: '取消' }
      )
    } catch (e) {
      return
    }
  }
  importing.value = true
  try {
    const payload = await readPayload(file.value)
    const { data } = await api.post(`/rules/import?mode=${mode.value}`, payload)
    applyResult(data)
    ElMessage.success(`导入完成：成功 ${data.imported}，跳过 ${data.skipped}，失败 ${data.failed}`)
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    importing.value = false
  }
}
</script>

<style scoped>
.el-card {
  margin-bottom: 16px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}
.card-title {
  font-weight: 600;
}
.desc {
  color: #909399;
  font-size: 13px;
  line-height: 1.7;
}
.upload-tip {
  color: #909399;
  font-size: 13px;
  padding: 12px 0;
}
.btns {
  margin-top: 12px;
  display: flex;
  gap: 10px;
}
.summary {
  margin-top: 12px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
</style>
