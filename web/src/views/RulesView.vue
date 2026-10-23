<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建规则</el-button>
          <el-input
            v-model="search"
            placeholder="搜索名称 / 监听地址 / 目标"
            clearable
            style="width: 260px"
            @keyup.enter="onSearch"
            @clear="onSearch"
          >
            <template #append><el-button :icon="Search" @click="onSearch" /></template>
          </el-input>
        </div>
        <div class="toolbar-right">
          <el-tag size="small" type="info">实时数据每 5 秒刷新</el-tag>
          <el-button :icon="Refresh" circle @click="load" />
        </div>
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
        <el-table-column label="协议" width="80">
          <template #default="{ row }">
            <el-tag :type="protoTag(row.protocol)" size="small">{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column  label="监听地址" width="130">
          <template #default="{ row }"><code>{{ row.listen_addr }}</code></template>
        </el-table-column>
        <el-table-column  label="目标" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">
            <code>{{ row.target_addr }}</code>
            <el-tooltip v-if="row.protocol === 'snat' && row.snat" :content="`SNAT 源地址 → ${row.snat.snat_ip}；已穿越 ${row.snat.packets} 包`" placement="top">
              <el-tag size="small" type="success" class="err-tag">→ {{ row.snat.snat_ip }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="后端" width="90">
          <template #default="{ row }">
            <template v-if="row.protocol === 'tcp'">
              <span v-if="!row.enabled" class="sub">未运行</span>
              <span v-else-if="row.health_check === false" class="sub">已关闭</span>
              <el-tooltip v-else-if="row.health && row.health.checked" placement="top">
                <template #content>
                  <div>{{ row.health.up ? '后端可达' : '后端不可达' }}</div>
                  <div v-if="!row.health.up">{{ row.health.error }}</div>
                  <div>检测时间：{{ fmtCheckTime(row.health.last_check) }}</div>
                  <div>点击查看检测历史</div>
                </template>
                <el-tag :type="row.health.up ? 'success' : 'danger'" size="small" class="be-link" @click="openHealth(row)">
                  {{ row.health.up ? '正常' : '异常' }}
                </el-tag>
              </el-tooltip>
              <span v-else class="sub">检测中…</span>
            </template>
            <span v-else class="sub">-</span>
          </template>
        </el-table-column>
        <el-table-column label="限速 ↑/↓" width="170">
          <template #default="{ row }">
            <el-tooltip v-if="row.bandwidth_group" :content="`共享额度 ${row.bandwidth_group.total_kbps} KB/s（自身限速不生效）`" placement="top">
              <el-tag size="small" type="warning">包·{{ row.bandwidth_group.name }}</el-tag>
            </el-tooltip>
            <span v-else class="mono">{{ speed(row.upload_limit_kbps) }} / {{ speed(row.download_limit_kbps) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="连接上限" width="90">
          <template #default="{ row }">
            <span class="mono">{{ row.max_conns > 0 ? row.max_conns : '不限' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="空闲超时" width="90">
          <template #default="{ row }">
            <span class="mono">{{ row.idle_timeout_sec > 0 ? row.idle_timeout_sec + ' s' : '全局' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="访问控制" width="120">
          <template #default="{ row }">
            <el-tooltip v-if="aclLabel(row)" placement="top">
              <template #content>
                <div>模式：{{ modeLabel(row.acl_mode) }}</div>
                <div v-if="row.acl_group_id">引用名单组：{{ groupNameOf(row.acl_group_id) }}</div>
                <div v-if="!row.acl_group_id">白名单：{{ listLen(row.allow_list) ? row.allow_list : '无' }}</div>
                <div v-if="!row.acl_group_id">黑名单：{{ listLen(row.deny_list) ? row.deny_list : '无' }}</div>
              </template>
              <span class="mono">
                <template v-if="row.acl_group_id">组·{{ groupNameOf(row.acl_group_id) }}</template>
                <template v-else>{{ aclLabel(row) }}</template>
              </span>
            </el-tooltip>
            <span v-else class="sub">不限制</span>
          </template>
        </el-table-column>
        <el-table-column label="实时" width="200">
          <template #default="{ row }">
            <span v-if="row.live.active_conns > 0">
              <el-tag size="small" type="success">{{ row.live.active_conns }} 连接</el-tag>
              <span class="mono sub"> ↑{{ fmtBytes(row.live.upload_bytes) }} ↓{{ fmtBytes(row.live.download_bytes) }}</span>
              <div v-if="row.live.rate_up_bps > 0 || row.live.rate_down_bps > 0" class="mono rate">
                ↑{{ fmtBps(row.live.rate_up_bps) }}/s ↓{{ fmtBps(row.live.rate_down_bps) }}/s
              </div>
            </span>
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
        <template #empty>还没有转发规则，点击右上角新建</template>
      </el-table>

      <div class="pager">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100, 200]"
          layout="total, sizes, prev, pager, next"
          @current-change="onPageChange"
          @size-change="onSizeChange"
        />
      </div>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑规则' : '新建规则'" width="640px" destroy-on-close>
      <el-form :model="form" label-width="110px" label-position="right">
        <el-form-item label="规则名称" required>
          <el-input v-model="form.name" placeholder="例如：MySQL 端口映射" maxlength="64" />
        </el-form-item>
        <el-form-item label="协议" required>
          <el-radio-group v-model="form.protocol">
            <el-radio-button value="tcp">TCP 转发</el-radio-button>
            <el-radio-button value="udp">UDP 转发</el-radio-button>
          </el-radio-group>
        </el-form-item>

        <el-form-item label="监听 IP" required>
          <el-select v-model="form.listen_ip" filterable placeholder="全部网卡（0.0.0.0）" style="width: 100%" class="mono-input">
            <el-option value="" label="全部网卡（0.0.0.0）" />
            <el-option v-for="ip in localIPs" :key="ip.value" :value="ip.value" :label="ip.label" />
          </el-select>
        </el-form-item>
        <el-form-item label="监听端口" required>
          <el-input-number v-model="form.listen_port" :min="1" :max="65535" :step="1" controls-position="right" style="width: 160px" />
          <span class="form-tip-inline">1-65535；与监听 IP 组合成本规则监听地址</span>
        </el-form-item>
        <el-form-item label="目标地址" required>
          <el-input v-model="form.target_addr" placeholder="10.0.0.5:3306" class="mono-input" />
        </el-form-item>
        <el-form-item label="后端连接源 IP">
          <el-select v-model="form.source_ip" clearable filterable allow-create placeholder="自动（路由选择）" style="width: 100%" class="mono-input">
            <el-option value="" label="自动（路由选择）" />
            <el-option v-for="ip in localIPs" :key="ip.value" :value="ip.value" :label="ip.label" />
          </el-select>
          <div class="form-tip">连后端时绑定的本机源 IP（后端服务看到的连接来源）；留空 = 跟随路由自动选择</div>
        </el-form-item>

        <el-divider content-position="left">访问控制（{{ form.protocol === 'snat' ? '源网段白名单：仅名单内的上游网段允许穿越' : 'IP 名单，支持单 IP 与 CIDR 网段' }}）</el-divider>
        <el-form-item label="控制模式">
          <el-radio-group v-model="form.acl_mode">
            <el-radio-button value="off">{{ form.protocol === 'snat' ? '全放行' : '不限制' }}</el-radio-button>
            <el-radio-button value="whitelist">白名单</el-radio-button>
            <el-radio-button v-if="form.protocol !== 'snat'" value="blacklist">黑名单</el-radio-button>
          </el-radio-group>
          <div class="form-tip" v-if="form.acl_mode === 'off'">
            {{ form.protocol === 'snat' ? '该入口网卡进入的全部穿越流量均放行（注意暴露面）' : '所有来源 IP 均可访问' }}
          </div>
          <template v-else>
            <div class="form-tip" v-if="!form.acl_group_id">可直配名单条目，或选择一个名单组直接引用</div>
            <div class="form-tip" v-else>已引用名单组{{ groupRefName ? `「${groupRefName}」` : '' }}：条目来自组（在「名单组」页维护，变更即时生效），无需在此直配</div>
          </template>
        </el-form-item>
        <el-form-item v-if="form.acl_mode !== 'off'" label="名单组">
          <el-select
            v-model="form.acl_group_id"
            clearable
            placeholder="不引用（使用下方直配名单）"
            style="width: 100%"
          >
            <el-option
              v-for="g in matchedGroups" :key="g.id" :value="g.id"
              :label="`${g.name}（${g.mode === 'whitelist' ? '白名单' : '黑名单'}组 · ${g.entry_count} 条）`"
            />
          </el-select>
          <div class="form-tip">只能选择与控制模式同类型的组；保存后组条目变更会自动热应用到本规则</div>
        </el-form-item>
        <el-form-item v-if="form.acl_mode === 'whitelist' && !form.acl_group_id" label="白名单">
          <div class="list-editor">
            <div class="tags" v-if="form.allow.length">
              <el-tag v-for="t in form.allow" :key="t" closable @close="removeTag('allow', t)" class="tag">{{ t }}</el-tag>
            </div>
            <div class="input-line">
              <el-input v-model="allowInput" placeholder="例如 192.168.1.10 或 10.0.0.0/24" size="small" @keyup.enter="addTag('allow')" class="mono-input" />
              <el-button size="small" @click="addTag('allow')">添加</el-button>
            </div>
            <div class="form-tip">仅名单内 IP 可访问，其余全部拒绝</div>
          </div>
        </el-form-item>
        <el-form-item v-if="form.acl_mode === 'blacklist' && !form.acl_group_id" label="黑名单">
          <div class="list-editor">
            <div class="tags" v-if="form.deny.length">
              <el-tag v-for="t in form.deny" :key="t" type="danger" closable @close="removeTag('deny', t)" class="tag">{{ t }}</el-tag>
            </div>
            <div class="input-line">
              <el-input v-model="denyInput" placeholder="例如 172.16.5.9 或 172.16.0.0/12" size="small" @keyup.enter="addTag('deny')" class="mono-input" />
              <el-button size="small" @click="addTag('deny')">添加</el-button>
            </div>
            <div class="form-tip">命中名单的 IP 直接拒绝，其余放行</div>
          </div>
        </el-form-item>

        <el-divider content-position="left">限速</el-divider>
        <el-form-item label="限速方式">
          <span class="sub">本规则不限速——加入带宽包后由包统一配置（合计额度与每源保底在「带宽包」编辑中设置）</span>
        </el-form-item>
        <el-form-item v-if="form.protocol !== 'snat'" label="连接上限">
          <el-input-number v-model="form.max_conns" :min="0" :max="100000" :step="100" />
          <span class="form-tip-inline">并发连接/请求数上限，0 表示不限；超出直接断开，防止资源耗尽</span>
        </el-form-item>
        <el-form-item v-if="form.protocol !== 'snat'" label="空闲超时">
          <el-input-number v-model="form.idle_timeout_sec" :min="0" :max="86400" :step="60" />
          <span class="form-tip-inline">秒；TCP 连接持续无数据超过该时长后断开，防止僵死连接占用资源，0 表示跟随全局配置</span>
        </el-form-item>
        <el-form-item v-if="form.protocol === 'tcp'" label="健康检测">
          <el-switch v-model="form.health_check" />
          <span class="form-tip-inline">每分钟探测一次后端端口；异常标红、正常标绿，并记录检测历史（点击规则列表「后端」状态查看）</span>
        </el-form-item>
        <el-form-item label="立即启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="healthVisible" :title="`后端检测历史 · ${healthRule ? healthRule.name : ''}`" size="46%">
      <div v-loading="healthLoading">
        <div class="hc-toolbar">
          <el-date-picker
            v-model="healthRange"
            type="datetimerange"
            range-separator="至"
            start-placeholder="开始时间"
            end-placeholder="结束时间"
            :shortcuts="healthShortcuts"
            style="width: 340px"
          />
          <el-button type="primary" :icon="Search" @click="loadHealthHistory">查询</el-button>
        </div>
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="当前状态">
            <el-tag v-if="healthDetail.checked" :type="healthDetail.up ? 'success' : 'danger'" size="small">
              {{ healthDetail.up ? '正常' : '异常' }}
            </el-tag>
            <span v-else class="sub">暂无检测</span>
          </el-descriptions-item>
          <el-descriptions-item label="窗口可用率">
            {{ healthDetail.points && healthDetail.points.length ? (healthDetail.availability * 100).toFixed(1) + '%' : '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="检测次数">{{ (healthDetail.points || []).length }}</el-descriptions-item>
          <el-descriptions-item label="目标地址" :span="2"><code>{{ healthRule ? healthRule.target_addr : '' }}</code></el-descriptions-item>
          <el-descriptions-item label="最近检测">{{ fmtCheckTime(healthDetail.last_check) }}</el-descriptions-item>
          <el-descriptions-item label="失败原因" :span="3">
            <span v-if="healthDetail.error" class="be-down">{{ healthDetail.error }}</span>
            <span v-else>-</span>
          </el-descriptions-item>
        </el-descriptions>

        <div ref="chartWrap" class="chart-wrap">
          <svg v-if="chart" :viewBox="`0 0 ${chart.w} ${chart.h}`" class="chart" role="img">
            <!-- 时间轴刻度 -->
            <text v-for="t in chart.ticks" :key="'t' + t.ts" :x="t.x" :y="chart.h - 6" class="tick" text-anchor="middle">{{ t.label }}</text>
            <!-- 基线 -->
            <line :x1="chart.padL" :y1="chart.yUp" :x2="chart.w - chart.padR" :y2="chart.yUp" class="axis" />
            <line :x1="chart.padL" :y1="chart.yDown" :x2="chart.w - chart.padR" :y2="chart.yDown" class="axis" />
            <!-- 状态阶梯线：水平段 + 跳变垂直段 -->
            <line
              v-for="(s, i) in chart.segs"
              :key="'s' + i"
              :x1="s.x1" :y1="s.y" :x2="s.x2" :y2="s.y"
              :class="s.up ? 'seg-up' : 'seg-down'"
            />
            <line
              v-for="(j, i) in chart.jumps"
              :key="'j' + i"
              :x1="j.x" :y1="j.y1" :x2="j.x" :y2="j.y2"
              class="seg-jump"
            />
            <!-- 检测点（点少时才画，悬停显示时间与结果） -->
            <circle v-for="(p, i) in chart.dots" :key="'d' + i" :cx="p.x" :cy="p.y" r="3" :class="p.up ? 'dot-up' : 'dot-down'">
              <title>{{ p.title }}</title>
            </circle>
          </svg>
          <div v-else class="sub" style="margin-top: 12px">
            {{ healthDetail.checked ? '所选时间段内无检测记录' : '暂无检测记录' }}
          </div>
          <div v-if="chart" class="legend">
            <span><i class="lg lg-up" />正常（后端可达）</span>
            <span><i class="lg lg-down" />异常（不可达）</span>
            <span class="sub">纵轴：上=正常 / 下=异常；横轴：检测时间{{ chart.sampled ? '（已按时间均匀降采样）' : '' }}</span>
          </div>
        </div>
        <div class="form-tip" style="margin-top: 8px">
          检测结果已落库（保留 {{ retentionDays }} 天），重启后历史不丢；线条左旧右新，跳变处即状态翻转时刻
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import api, { errMsg } from '../api'
import { formatBytes, parseListJSON } from '../utils/format'

const rules = ref([])
const loading = ref(false)
const page = ref(1)
const pageSize = ref(50)
const total = ref(0)
const search = ref('')
const dialogVisible = ref(false)
const editing = ref(null)
const saving = ref(false)
const allowInput = ref('')
const denyInput = ref('')
let timer = null

const emptyForm = () => ({
  name: '',
  protocol: 'tcp',
  listen_ip: '',
  listen_port: undefined,
  listen_addr: '',
  target_addr: '',
  acl_mode: 'off',
  allow: [],
  deny: [],
  acl_group_id: 0,
  upload_limit_kbps: 0,
  download_limit_kbps: 0,
  max_conns: 0,
  idle_timeout_sec: 0,
  source_ip: '',
  health_check: true,
  enabled: true,
})
const form = reactive(emptyForm())

// ---------- 名单组 ----------
const aclGroups = ref([])
const matchedGroups = computed(() => aclGroups.value.filter((g) => g.mode === form.acl_mode))
const groupRefName = computed(() => {
  const g = aclGroups.value.find((x) => x.id === form.acl_group_id)
  return g ? g.name : ''
})

// ---------- 网卡（snat 表单 + 后端连接源 IP） ----------
const ifaces = ref([])
// 全部本机 IPv4（指定后端连接源 IP 下拉）
const localIPs = computed(() => {
  const out = []
  for (const i of ifaces.value) {
    for (const ip of i.ips || []) out.push({ value: ip, label: `${ip}（${i.name}）` })
  }
  return out
})
const snatOutIP = computed(() => {
  const i = ifaces.value.find((x) => x.name === form.target_addr)
  return i && i.ip ? i.ip : ''
})

async function loadIfaces() {
  try {
    const { data } = await api.get('/interfaces')
    ifaces.value = data.items || []
  } catch (e) { /* 网卡加载失败不阻塞 */ }
}

async function loadGroups() {
  try {
    const { data } = await api.get('/acl-groups')
    aclGroups.value = data.items || []
  } catch (e) { /* 名单组加载失败不阻塞规则页 */ }
}

const fmtBytes = formatBytes
const speed = (kbps) => (kbps ? `${kbps} KB/s` : '不限')
const listLen = (s) => parseListJSON(s).length
// B/s 实时速率展示：B/KB/MB 自适应
const fmtBps = (bps) => {
  if (bps >= 1024 * 1024) return (bps / 1024 / 1024).toFixed(2) + ' MB'
  if (bps >= 1024) return (bps / 1024).toFixed(1) + ' KB'
  return bps + ' B'
}
// 规则列表展示引用的组名（组列表懒加载，首帧可能空——不影响 tooltip 刷新）
const groupNameOf = (id) => {
  const g = aclGroups.value.find((x) => x.id === id)
  return g ? g.name : `#${id}`
}
// 后端检测时间是 unix 秒，转本地时间字符串
const fmtCheckTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '-')

const modeLabel = (m) => ({ off: '不限制', whitelist: '白名单', blacklist: '黑名单' }[m] || '旧版黑白并存')

// aclLabel 列表显示：显式模式只显示对应名单；旧数据（空模式）仍显示黑白计数
function aclLabel(row) {
  const allowN = listLen(row.allow_list)
  const denyN = listLen(row.deny_list)
  if (row.acl_mode === 'whitelist') return allowN ? `白${allowN}` : ''
  if (row.acl_mode === 'blacklist') return denyN ? `黑${denyN}` : ''
  if (row.acl_mode === 'off') return ''
  return allowN + denyN > 0 ? `白${allowN} / 黑${denyN}` : ''
}

function protoTag(p) {
  return { tcp: 'primary', udp: 'warning', snat: 'success' }[p] || 'info'
}

async function load() {
  loading.value = true
  try {
    const params = { page: page.value, page_size: pageSize.value, protocol: 'tcp,udp' }
    if (search.value.trim()) params.search = search.value.trim()
    const { data } = await api.get('/rules', { params })
    rules.value = (data.items || []).map((r) => ({ ...r, _toggling: false }))
    total.value = data.total || 0
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

function onSearch() {
  page.value = 1
  load()
}

function onPageChange(p) {
  page.value = p
  load()
}

function onSizeChange(s) {
  pageSize.value = s
  page.value = 1
  load()
}

function openCreate() {
  editing.value = null
  Object.assign(form, emptyForm())
  allowInput.value = ''
  denyInput.value = ''
  loadGroups()
  loadIfaces()
  dialogVisible.value = true
}

// inferAclMode 旧数据（acl_mode 为空）按现有名单推断模式。
// 黑白名单同时配置的旧规则无法等价映射，按白名单处理并提示。
function inferAclMode(row) {
  const hasAllow = parseListJSON(row.allow_list).length > 0
  const hasDeny = parseListJSON(row.deny_list).length > 0
  if (hasAllow && hasDeny) {
    ElMessage.warning('该规则为旧版数据（同时配置了黑白名单），已按白名单模式加载，保存后黑名单条目将被移除，请确认')
    return 'whitelist'
  }
  if (hasDeny) return 'blacklist'
  if (hasAllow) return 'whitelist'
  return 'off'
}

function openEdit(row) {
  editing.value = row
  const mode = ['off', 'whitelist', 'blacklist'].includes(row.acl_mode) ? row.acl_mode : inferAclMode(row)
  Object.assign(form, emptyForm(), {
    name: row.name,
    protocol: row.protocol,
    listen_ip: row.listen_addr.split(':')[0] || '',
    listen_port: parseInt(row.listen_addr.split(':')[1] || '0', 10) || undefined,
    listen_addr: row.listen_addr,
    target_addr: row.target_addr,
    acl_mode: mode,
    allow: parseListJSON(row.allow_list),
    deny: parseListJSON(row.deny_list),
    acl_group_id: row.acl_group_id || 0,
    upload_limit_kbps: row.upload_limit_kbps,
    download_limit_kbps: row.download_limit_kbps,
    max_conns: row.max_conns || 0,
    idle_timeout_sec: row.idle_timeout_sec || 0,
    source_ip: row.source_ip || '',
    health_check: row.health_check !== false,
    enabled: row.enabled,
  })
  allowInput.value = ''
  denyInput.value = ''
  loadGroups()
  loadIfaces()
  dialogVisible.value = true
}

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-fA-F:]{2,45}(\/\d{1,3})?$/

function addTag(kind) {
  const input = kind === 'allow' ? allowInput : denyInput
  const v = input.value.trim()
  if (!v) return
  if (!IP_RE.test(v)) {
    ElMessage.warning('格式应为 IP（1.2.3.4）或 CIDR 网段（192.168.1.0/24）')
    return
  }
  if (!form[kind].includes(v)) form[kind].push(v)
  input.value = ''
}

function removeTag(kind, tag) {
  form[kind] = form[kind].filter((t) => t !== tag)
}

async function save() {
  if (!form.name.trim()) return ElMessage.warning('请填写规则名称')
  if (!form.listen_port) return ElMessage.warning('请填写监听端口（1-65535）')
  form.listen_addr = form.listen_ip ? `${form.listen_ip}:${form.listen_port}` : `:${form.listen_port}`
  if (!form.target_addr.trim()) return ElMessage.warning('请填写目标地址')
  if (form.acl_mode === 'whitelist' && !form.acl_group_id && !form.allow.length) return ElMessage.warning('白名单模式需选择名单组或至少添加一条白名单')
  if (form.acl_mode === 'blacklist' && !form.acl_group_id && !form.deny.length) return ElMessage.warning('黑名单模式需选择名单组或至少添加一条黑名单')

  const payload = {
    name: form.name.trim(),
    protocol: form.protocol,
    // snat：listen_addr=入口网卡、target_addr=出口网卡（接口语义复用）
    listen_addr: form.listen_addr.trim(),
    target_addr: form.target_addr.trim(),
    source_ip: form.source_ip || '',
    acl_mode: form.acl_mode,
    // 名单与模式严格对应：未选中的名单不提交，后端亦校验互斥；
    // 引用名单组时直配名单不提交（条目完全来自组）
    acl_group_id: form.acl_mode !== 'off' ? form.acl_group_id || 0 : 0,
    allow_list: form.acl_mode === 'whitelist' && !form.acl_group_id && form.allow.length ? JSON.stringify(form.allow) : '',
    deny_list: form.acl_mode === 'blacklist' && !form.acl_group_id && form.deny.length ? JSON.stringify(form.deny) : '',
    upload_limit_kbps: 0,
    download_limit_kbps: 0,
    max_conns: form.max_conns,
    idle_timeout_sec: form.idle_timeout_sec,
    // UDP 规则无检测语义，恒为 true（后端不探测 UDP）
    health_check: form.protocol === 'tcp' ? form.health_check : true,
    enabled: form.enabled,
  }
  saving.value = true
  try {
    if (editing.value) {
      await api.put(`/rules/${editing.value.id}`, payload)
    } else {
      await api.post('/rules', payload)
    }
    ElMessage.success('已保存并生效')
    dialogVisible.value = false
    await load()
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    saving.value = false
  }
}

async function toggle(row, enabled) {
  row._toggling = true
  try {
    await api.post(`/rules/${row.id}/${enabled ? 'enable' : 'disable'}`)
    row.enabled = enabled
    ElMessage.success(enabled ? '已启用' : '已停用')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    row._toggling = false
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`确定删除规则「${row.name}」？删除后立即停止监听。`, '删除确认', { type: 'warning' })
  } catch (e) {
    return
  }
  try {
    await api.delete(`/rules/${row.id}`)
    ElMessage.success('已删除')
    if (rules.value.length === 1 && page.value > 1) page.value--
    await load()
  } catch (e) {
    ElMessage.error(errMsg(e))
  }
}

// ---------- 后端检测历史 ----------

const healthVisible = ref(false)
const healthLoading = ref(false)
const healthRule = ref(null)
const healthDetail = ref({})
const healthRange = ref([])
const chartWrap = ref(null)
const chartW = ref(720)

// 保留天数提示与后端 log_retention_days 对齐（读不到具体值，用文案兜底）
const retentionDays = 30

const healthShortcuts = [
  { text: '近1小时', value: () => { const e = new Date(); return [new Date(e - 3600 * 1000), e] } },
  { text: '近6小时', value: () => { const e = new Date(); return [new Date(e - 6 * 3600 * 1000), e] } },
  { text: '近24小时', value: () => { const e = new Date(); return [new Date(e - 24 * 3600 * 1000), e] } },
  { text: '近7天', value: () => { const e = new Date(); return [new Date(e - 7 * 24 * 3600 * 1000), e] } },
]

// 检测历史折线图：横轴为所选时间范围（带刻度），纵轴上=正常/下=异常，状态翻转处垂直跳变
const chart = computed(() => {
  const pts = (healthDetail.value.points || []).slice(-1440)
  if (!pts.length) return null
  const w = chartW.value
  const h = 170
  const padL = 10
  const padR = 10
  const yUp = 26
  const yDown = h - 42
  // 图表横轴以查询范围为准：空缺时段（停用/重启）在图上一目了然
  const t0 = healthDetail.value.start || pts[0].ts
  const t1 = healthDetail.value.end || pts[pts.length - 1].ts
  const span = Math.max(t1 - t0, 60)
  const x = (ts) => padL + ((ts - t0) / span) * (w - padL - padR)

  // 水平段：相邻检测点之间按前一点状态延伸；状态变化处补垂直跳变线
  const segs = []
  const jumps = []
  for (let i = 0; i < pts.length - 1; i++) {
    const a = pts[i]
    const b = pts[i + 1]
    segs.push({ x1: x(a.ts), x2: x(b.ts), y: a.up ? yUp : yDown, up: a.up })
    if (a.up !== b.up) {
      jumps.push({ x: x(b.ts), y1: a.up ? yUp : yDown, y2: b.up ? yUp : yDown })
    }
  }

  // 时间刻度：约 5 个，步长圆整到分钟（至少 1 分钟）
  const step = Math.max(60, Math.round(span / 5 / 60) * 60)
  const firstTick = Math.ceil(t0 / step) * step
  const ticks = []
  for (let ts = firstTick; ts <= t1 && ticks.length < 8; ts += step) {
    ticks.push({ ts, x: x(ts), label: fmtTick(ts, t0, t1) })
  }
  // 首尾时间始终标注，避免只有一个刻度时无从对读；单点场景只标一次
  if (ticks.length < 2) {
    ticks.length = 0
    ticks.push({ ts: t0, x: x(t0), label: fmtTick(t0, t0, t1) })
    if (t1 > t0) {
      ticks.push({ ts: t1, x: x(t1), label: fmtTick(t1, t0, t1) })
    }
  }

  // 点多时只画线不画点，避免上千个 DOM 节点
  const sampled = healthDetail.value.points && healthDetail.value.points.length > pts.length
  const dots = pts.length <= 240
    ? pts.map((p) => ({
        x: x(p.ts),
        y: p.up ? yUp : yDown,
        up: p.up,
        title: `${fmtCheckTime(p.ts)} ${p.up ? '正常' : '异常'}`,
      }))
    : []

  return { w, h, padL, padR, yUp, yDown, segs, jumps, ticks, dots, sampled }
})

// 刻度标签：同一天只显示时分，跨天附带月-日
function fmtTick(ts, t0, t1) {
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  const hm = `${p(d.getHours())}:${p(d.getMinutes())}`
  const a = new Date(t0 * 1000)
  const b = new Date(t1 * 1000)
  const crossDay = a.toDateString() !== b.toDateString()
  return crossDay ? `${p(d.getMonth() + 1)}-${p(d.getDate())} ${hm}` : hm
}

async function loadHealthHistory() {
  if (!healthRule.value) return
  healthLoading.value = true
  try {
    const params = {}
    if (Array.isArray(healthRange.value) && healthRange.value[0] && healthRange.value[1]) {
      params.start = Math.floor(healthRange.value[0].getTime() / 1000)
      params.end = Math.floor(healthRange.value[1].getTime() / 1000)
    }
    const { data } = await api.get(`/rules/${healthRule.value.id}/health`, { params })
    healthDetail.value = data
    // 抽屉渲染完成后测量容器宽度，折线坐标按实际宽度计算
    await nextTick()
    if (chartWrap.value) chartW.value = Math.max(chartWrap.value.clientWidth, 360)
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    healthLoading.value = false
  }
}

function openHealth(row) {
  healthRule.value = row
  healthVisible.value = true
  const now = new Date()
  healthRange.value = [new Date(now - 3600 * 1000), now]
  healthDetail.value = {}
  loadHealthHistory()
}

onMounted(() => {
  load()
  loadGroups()
  timer = setInterval(() => {
    // 轻量刷新实时统计与后端健康，不闪表格 loading
    const params = { page: page.value, page_size: pageSize.value, protocol: 'tcp,udp' }
    if (search.value.trim()) params.search = search.value.trim()
    api.get('/rules', { params }).then(({ data }) => {
      const map = {}
      for (const r of data.items || []) map[r.id] = { live: r.live, health: r.health }
      for (const r of rules.value) {
        if (map[r.id]) {
          r.live = map[r.id].live
          r.health = map[r.id].health
        }
      }
      total.value = data.total || 0
    }).catch(() => {})
  }, 5000)
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
  gap: 10px;
  align-items: center;
}
.pager {
  margin-top: 12px;
  display: flex;
  justify-content: flex-end;
}
.toolbar-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.err-tag {
  margin-left: 6px;
}
.be {
  font-size: 12px;
}
.be-link {
  cursor: pointer;
}
.be-up {
  color: #67c23a;
}
.be-down {
  color: #f56c6c;
}
.chart-wrap {
  margin-top: 14px;
}
.hc-toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 12px;
}
.chart {
  width: 100%;
  height: auto;
  display: block;
}
.chart .axis {
  stroke: #e4e7ed;
  stroke-width: 1;
  stroke-dasharray: 3 3;
}
.chart .tick {
  fill: #909399;
  font-size: 11px;
}
.chart .seg-up {
  stroke: #67c23a;
  stroke-width: 2;
}
.chart .seg-down {
  stroke: #f56c6c;
  stroke-width: 2;
}
.chart .seg-jump {
  stroke: #c0c4cc;
  stroke-width: 1;
}
.chart .dot-up {
  fill: #67c23a;
}
.chart .dot-down {
  fill: #f56c6c;
}
.legend {
  display: flex;
  gap: 16px;
  align-items: center;
  margin-top: 6px;
  font-size: 12px;
  color: #606266;
}
.legend .lg {
  display: inline-block;
  width: 14px;
  height: 3px;
  border-radius: 2px;
  margin-right: 4px;
  vertical-align: middle;
}
.lg-up {
  background: #67c23a;
}
.lg-down {
  background: #f56c6c;
}
.rate {
  color: #409eff;
  font-size: 12px;
  margin-top: 2px;
}
.mono-input :deep(input) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
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
.form-tip-inline {
  color: #909399;
  font-size: 12px;
  margin-left: 6px;
}
.unit {
  margin-left: 8px;
  color: #606266;
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
</style>
