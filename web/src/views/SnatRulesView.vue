<template>
  <div>
    <el-card>
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button type="primary" :icon="Plus" @click="openCreate">新建 SNAT 规则</el-button>
          <span class="tip">其他机器的流量从入口网卡进入本机、经出口网卡 SNAT 出去（源地址替换为出口 IP）；由内核线速转发</span>
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
        <el-table-column label="入口网卡" width="110">
          <template #default="{ row }"><code>{{ row.listen_addr }}</code></template>
        </el-table-column>
        <el-table-column label="出口网卡" width="110">
          <template #default="{ row }"><code>{{ row.target_addr }}</code></template>
        </el-table-column>
        <el-table-column label="SNAT 源 IP" width="140">
          <template #default="{ row }">
            <el-tooltip v-if="row.snat" :content="`源地址替换为 ${row.snat.snat_ip}${row.snat_ip ? '' : '（自动·网卡首地址）'}`" placement="top">
              <el-tag size="small" type="success">{{ row.snat.snat_ip }}</el-tag>
            </el-tooltip>
            <el-tag v-else-if="row.snat_ip" size="small" type="success">{{ row.snat_ip }}</el-tag>
            <span v-else class="sub">自动</span>
          </template>
        </el-table-column>
        <el-table-column label="源 IP 网段" min-width="170" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tooltip v-if="row.acl_mode === 'whitelist'" placement="top">
              <template #content>
                <div>仅这些源走本规则：</div>
                <div v-for="s in parseList(row.allow_list)" :key="s">{{ s }}</div>
                <div v-if="row.acl_group_id">（来自名单组 #{{ row.acl_group_id }}）</div>
              </template>
              <span class="mono">{{ srcPreview(row) }}</span>
            </el-tooltip>
            <span v-else class="sub">全放行</span>
          </template>
        </el-table-column>
        <el-table-column label="目标限制" min-width="140" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tooltip v-if="row.dst_acl_mode === 'whitelist' || row.dst_acl_mode === 'blacklist'" placement="top">
              <template #content>
                <div>{{ row.dst_acl_mode === 'whitelist' ? '仅允许访问：' : '禁止访问：' }}</div>
                <div v-for="d in parseList(row.dst_acl_mode === 'whitelist' ? row.dst_allow_list : row.dst_deny_list)" :key="d">{{ d }}</div>
              </template>
              <el-tag size="small" :type="row.dst_acl_mode === 'blacklist' ? 'danger' : 'success'">
                {{ row.dst_acl_mode === 'blacklist' ? '禁' : '允' }}·{{ dstPreview(row) }}
              </el-tag>
            </el-tooltip>
            <span v-else class="sub">不限制</span>
          </template>
        </el-table-column>
        <el-table-column label="限速/带宽包" width="150">
          <template #default="{ row }">
            <el-tooltip v-if="row.bandwidth_group" :content="`共享额度 ${row.bandwidth_group.total_kbps} KB/s（规则自身限速不生效）`" placement="top">
              <el-tag size="small" type="warning">包·{{ row.bandwidth_group.name }}</el-tag>
            </el-tooltip>
            <span v-else class="sub">未限速（加入带宽包限速）</span>
          </template>
        </el-table-column>
        <el-table-column label="穿越统计" width="150">
          <template #default="{ row }">
            <span v-if="row.snat" class="mono sub">{{ row.snat.packets }} 包<span v-if="row.snat.denied_packets"> · 拒 {{ row.snat.denied_packets }}</span></span>
            <span v-else class="sub">-</span>
          </template>
        </el-table-column>
        <el-table-column label="实时速率" width="130">
          <template #default="{ row }">
            <span v-if="row.live && (row.live.rate_up_bps > 0 || row.live.rate_down_bps > 0)" class="mono rate">↑{{ fmtBps(row.live.rate_up_bps) }}/s</span>
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
        <template #empty>还没有 SNAT 规则，点击左上角新建</template>
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

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑 SNAT 规则' : '新建 SNAT 规则'" width="620px" top="6vh" destroy-on-close>
      <el-form :model="form" label-width="100px" class="rule-form-scroll">
        <el-form-item label="规则名称" required>
          <el-input v-model="form.name" placeholder="例如：办公网段出口" maxlength="64" />
        </el-form-item>
        <el-form-item label="入口网卡" required>
          <el-select v-model="form.listen_addr" filterable placeholder="流量从哪块网卡进来" style="width: 100%" class="mono-input">
            <el-option v-for="i in ifaces" :key="i.name" :value="i.name"
              :label="`${i.name}（${i.ips && i.ips.length ? i.ips.join(', ') : '无 IPv4'}，${i.status}）`"
              :disabled="i.status !== 'up' || !i.ips || !i.ips.length" />
          </el-select>
          <div class="form-tip">上游机器把网关/路由指向本机这块网卡</div>
        </el-form-item>
        <el-form-item label="出口网卡" required>
          <el-select v-model="form.target_addr" filterable placeholder="流量从哪块网卡出去" style="width: 100%" class="mono-input" @change="form.snat_ip = ''">
            <el-option v-for="i in ifaces" :key="i.name" :value="i.name"
              :label="`${i.name}（${i.ips && i.ips.length ? i.ips.join(', ') : '无 IPv4'}，${i.status}）${i.name === form.listen_addr ? '· 与入口同一张' : ''}`"
              :disabled="i.status !== 'up' || !i.ips || !i.ips.length" />
          </el-select>
          <div class="form-tip">SNAT 后流量从这块网卡出去，源地址替换为下方选定的 IP</div>
          <div class="form-tip" v-if="form.target_addr && form.target_addr === form.listen_addr">
            单臂网关：入口与出口是同一张网卡（{{
              form.listen_addr
            }}）。上游需把默认网关指向本机在这块网卡上的地址，本机再用另一个地址做 SNAT 转发出去。
          </div>
        </el-form-item>
        <el-form-item label="SNAT 源 IP" required>
          <el-select v-model="form.snat_ip" filterable allow-create placeholder="自动（网卡首地址）" style="width: 100%" class="mono-input">
            <el-option value="" label="自动（跟随出口网卡首地址）" />
            <el-option v-for="ip in outIfIPs" :key="ip" :value="ip" :label="ip" />
          </el-select>
          <div class="form-tip">出口网卡可能有多个地址，选择用哪个 IP 作为 SNAT 源；"自动"跟随网卡首地址</div>
        </el-form-item>
        <el-form-item label="出口网关">
          <el-input v-model="form.egress_gw" placeholder="如 172.16.40.1（留空=仅直连网段）" class="mono-input" />
          <div class="form-tip">穿越目标是公网/跨网段时必填：出向流量经此网关从出口网卡出去（须与出口网卡同网段）；纯直连网段目标可留空；配置了出口实体（「出口管理」页）时以出口实体为准</div>
        </el-form-item>

        <el-divider content-position="left">多出口与 SNAT 源池</el-divider>
        <el-form-item label="绑定出口">
          <el-select v-model="form.egress_ids" multiple placeholder="不绑定 = 全部启用出口" style="width: 100%">
            <el-option v-for="eg in egresses" :key="eg.id" :value="eg.id"
              :label="`${eg.name}（${eg.iface}，优先级 ${eg.priority}${eg.status ? '，' + (eg.status === 'up' ? '可用' : '不可用') : ''}）`"
              :disabled="!eg.enabled" />
          </el-select>
          <div class="form-tip">多出口在「出口管理」页维护；绑定后仅经所选出口出站（多层主备+同层权重分担，探测自动切换）</div>
        </el-form-item>
        <el-form-item label="SNAT 源模式">
          <el-radio-group v-model="form.snat_mode">
            <el-radio value="fixed">固定单 IP</el-radio>
            <el-radio value="rotate">按源轮换</el-radio>
            <el-radio value="sticky">源粘滞</el-radio>
          </el-radio-group>
          <div class="form-tip">v1 的轮换/粘滞同为"源确定性映射"（同源恒同出口 IP）；源池成员在下方填写（1-32 个，须归属出口网卡）</div>
        </el-form-item>
        <el-form-item v-if="form.snat_mode !== 'fixed'" label="SNAT 源池">
          <el-select v-model="form.snat_pool" multiple allow-create filterable default-first-option
            placeholder="选择出口网卡地址，或直接输入 IP 回车" style="width: 100%" class="mono-input">
            <el-option v-for="ip in outIfIPs" :key="ip" :value="ip" :label="ip" />
          </el-select>
          <div class="form-tip">池成员即出口网卡上的多个地址（一卡多址），每个源客户端确定性映射到其中一个</div>
        </el-form-item>

        <el-divider content-position="left">源 IP 网段（哪些客户端能走本规则穿越；必须至少一条）</el-divider>
        <el-form-item label="源名单来源">
          <el-radio-group v-model="form.srcFrom">
            <el-radio-button value="manual">手填网段</el-radio-button>
            <el-radio-button value="group">引用名单组</el-radio-button>
          </el-radio-group>
          <div class="form-tip">源白名单从哪来：手动填写（下方输入框）或引用名单组（在「名单组」页维护、变更即时热生效）</div>
        </el-form-item>
        <el-form-item label="名单组" v-if="form.srcFrom === 'group'">
          <el-select v-model="form.acl_group_id" clearable placeholder="选择要引用的白名单组" style="width: 100%">
            <el-option v-for="g in whitelistGroups" :key="g.id" :value="g.id"
              :label="`${g.name}（白名单组 · ${g.entry_count} 条）`" />
          </el-select>
          <div class="form-tip" v-if="form.acl_group_id">本规则的源白名单 = 该组的全部条目（组内变更即时热生效，无需编辑本规则）</div>
        </el-form-item>
        <el-form-item label="源网段" v-if="form.srcFrom === 'manual'">
          <div class="list-editor">
            <div class="tags" v-if="form.allow.length">
              <el-tag v-for="t in form.allow" :key="t" closable @close="removeTag(t)" class="tag">{{ t }}</el-tag>
            </div>
            <div class="input-line">
              <el-input v-model="allowInput" placeholder="例如 192.168.10.0/24 或 172.16.40.5" size="small" @keyup.enter="addTag" class="mono-input" />
              <el-button size="small" @click="addTag">添加</el-button>
            </div>
            <div class="form-tip">指定哪些客户端源 IP 可经本规则穿越（与下方目标限制互相独立）；仅列表内源被放行并 SNAT，其余一律 DROP</div>
          </div>
        </el-form-item>

        <el-divider content-position="left">目标限制（穿越后能访问哪些目标 IP；默认不限制，与上面源网段互相独立）</el-divider>
        <el-form-item label="限制方式">
          <el-radio-group v-model="form.dst_mode" @change="onDstModeChange">
            <el-radio-button value="off">不限制</el-radio-button>
            <el-radio-button value="whitelist">仅允许访问</el-radio-button>
            <el-radio-button value="blacklist">禁止访问</el-radio-button>
          </el-radio-group>
          <div class="form-tip" v-if="form.dst_mode === 'off'">当前不限制——如需只允许/禁止访问某些目标 IP，点上方「仅允许访问」或「禁止访问」，下方随即出现目标填写框</div>
          <div class="form-tip" v-else-if="form.dst_mode === 'whitelist'">仅列表内目标可达，其余一律拒绝；在下方手填目标 IP/网段，或引用一个白名单组/IP 组（二者其一，必须非空）</div>
          <div class="form-tip" v-else>列表内目标拒绝访问，其余正常穿越；在下方手填目标 IP/网段，或引用一个黑名单组/IP 组（二者其一，必须非空）</div>
        </el-form-item>
        <el-form-item label="目标来源" v-if="form.dst_mode !== 'off'">
          <el-radio-group v-model="form.dstFrom" @change="onDstFromChange">
            <el-radio-button value="manual">手填目标</el-radio-button>
            <el-radio-button value="group">引用名单组</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="名单组" v-if="form.dst_mode !== 'off' && form.dstFrom === 'group'">
          <el-select v-model="form.dst_acl_group_id" clearable filterable
            :placeholder="`选择一个${form.dst_mode === 'whitelist' ? '白名单组' : '黑名单组'}或 IP 组`" style="width: 100%">
            <el-option v-for="g in dstGroups" :key="g.id" :value="g.id"
              :label="`${g.name}（${modeLabelOf(g.mode)} · ${g.entry_count} 条）`" />
          </el-select>
          <div class="form-tip" v-if="form.dst_acl_group_id">目标条目来自「{{ groupNameOf(form.dst_acl_group_id) }}」（在名单组页维护，变更即时热生效）</div>
          <div class="form-tip" v-else>只能选择与「{{ form.dst_mode === 'whitelist' ? '仅允许访问' : '禁止访问' }}」同类型的组，或中性 IP 组</div>
        </el-form-item>
        <el-form-item ref="dstItemRef" :label="form.dst_mode === 'blacklist' ? '禁止目标' : '允许目标'"
          v-if="form.dst_mode !== 'off' && form.dstFrom === 'manual'">
          <div class="list-editor">
            <div class="tags" v-if="form.dst_list.length">
              <el-tag v-for="t in form.dst_list" :key="t" closable :type="form.dst_mode === 'blacklist' ? 'danger' : 'success'" @close="removeDstTag(t)" class="tag">{{ t }}</el-tag>
            </div>
            <div class="input-line">
              <el-input v-model="dstInput" :placeholder="form.dst_mode === 'blacklist' ? '例如 10.0.0.0/8 或 172.16.40.5' : '例如 172.16.41.0/24 或 8.8.8.8'" size="small" @keyup.enter="addDstTag" class="mono-input" />
              <el-button size="small" @click="addDstTag">添加</el-button>
            </div>
          </div>
        </el-form-item>

        <el-divider content-position="left">限速（统一在「带宽包」页配置）</el-divider>
        <el-form-item label="限速方式">
          <span class="sub">本规则不限速——加入带宽包后由包统一配置（合计额度与每源保底在包编辑中设置）</span>
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
  </div>
</template>

<script setup>
import { computed, reactive, ref, nextTick, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh } from '@element-plus/icons-vue'
import api, { errMsg } from '../api'
import { parseListJSON } from '../utils/format'

const rules = ref([])
const loading = ref(false)
const page = ref(1)
const pageSize = ref(50)
const total = ref(0)
const dialogVisible = ref(false)
const editing = ref(null)
const saving = ref(false)
const allowInput = ref('')
const dstInput = ref('')
const ifaces = ref([])
const egresses = ref([])
let timer = null

const emptyForm = () => ({
  name: '',
  listen_addr: '',
  target_addr: '',
  snat_ip: '',
  egress_gw: '',
  snat_mode: 'fixed',
  snat_pool: [],
  egress_ids: [],
  allow: [],
  acl_group_id: 0,
  srcFrom: 'manual',
  dst_mode: 'off',
  dst_list: [],
  dstFrom: 'manual',
  dst_acl_group_id: 0,
  enabled: true,
})
const form = reactive(emptyForm())

// 出口网卡的全部 IPv4（多址下拉）
const outIfIPs = computed(() => {
  const i = ifaces.value.find((x) => x.name === form.target_addr)
  return (i && i.ips) || []
})

const parseList = parseListJSON
const fmtBps = (bps) => {
  if (bps >= 1024 * 1024) return (bps / 1024 / 1024).toFixed(2) + ' MB'
  if (bps >= 1024) return (bps / 1024).toFixed(1) + ' KB'
  return bps + ' B'
}

function srcPreview(row) {
  const list = parseListJSON(row.allow_list)
  if (row.acl_group_id) return `名单组#${row.acl_group_id}`
  if (!list.length) return ''
  return list.length > 3 ? list.slice(0, 3).join(', ') + ` …（${list.length}）` : list.join(', ')
}

function dstPreview(row) {
  const list = parseListJSON(row.dst_acl_mode === 'whitelist' ? row.dst_allow_list : row.dst_deny_list)
  if (!list.length) return ''
  return list.length > 2 ? list.slice(0, 2).join(', ') + ` …（${list.length}）` : list.join(', ')
}

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/rules', { params: { protocol: 'snat', page: page.value, page_size: pageSize.value } })
    rules.value = (data.items || []).map((r) => ({ ...r, _toggling: false }))
    total.value = data.total || 0
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

async function loadIfaces() {
  try {
    const { data } = await api.get('/interfaces')
    ifaces.value = data.items || []
  } catch (e) { /* 不阻塞 */ }
}

// 源名单可引用的组：白名单组 + 中性 IP 组（IP 组按引用方白名单语义生效）
const aclGroups = ref([])
const whitelistGroups = computed(() =>
  aclGroups.value.filter((g) => g.mode === 'whitelist' || g.mode === 'ip'))
// 目标限制可引用的组：与目标模式同类型的组，或中性 IP 组
const dstGroups = computed(() =>
  aclGroups.value.filter((g) => g.mode === form.dst_mode || g.mode === 'ip'))
const groupNameOf = (id) => {
  const g = aclGroups.value.find((x) => x.id === id)
  return g ? g.name : `#${id}`
}
const modeLabelOf = (m) => ({ whitelist: '白名单组', blacklist: '黑名单组', ip: 'IP 组' }[m] || m)
async function loadGroups() {
  try {
    const { data } = await api.get('/acl-groups')
    aclGroups.value = data.items || []
  } catch (e) { /* 不阻塞 */ }
}

function onPageChange(p) {
  page.value = p
  load()
}

function openCreate() {
  editing.value = null
  Object.assign(form, emptyForm())
  allowInput.value = ''
  dstInput.value = ''
  loadIfaces()
  loadGroups()
  dialogVisible.value = true
}

function openEdit(row) {
  editing.value = row
  Object.assign(form, emptyForm(), {
    name: row.name,
    listen_addr: row.listen_addr,
    target_addr: row.target_addr,
    snat_ip: row.snat_ip || '',
    egress_gw: row.egress_gw || '',
    snat_mode: row.snat_mode || 'fixed',
    snat_pool: parseList(row.snat_pool) || [],
    // egress_ids 在库/接口里是 JSON 字符串（如 "[1,2]"），必须先解析再转数字
    egress_ids: parseListJSON(row.egress_ids).map(Number),
    // 组引用与直配按原样装载，保存时不丢失（引用组的规则直配列表为空是正常态）
    acl_group_id: row.acl_group_id || 0,
    srcFrom: row.acl_group_id ? 'group' : 'manual',
    allow: !row.acl_group_id && row.acl_mode === 'whitelist' ? parseListJSON(row.allow_list) : [],
    dst_mode: row.dst_acl_mode === 'whitelist' || row.dst_acl_mode === 'blacklist' ? row.dst_acl_mode : 'off',
    dst_list: row.dst_acl_mode === 'whitelist' ? parseListJSON(row.dst_allow_list)
      : row.dst_acl_mode === 'blacklist' ? parseListJSON(row.dst_deny_list) : [],
    dstFrom: row.dst_acl_group_id ? 'group' : 'manual',
    dst_acl_group_id: row.dst_acl_group_id || 0,
    enabled: row.enabled,
  })
  allowInput.value = ''
  loadIfaces()
  loadGroups()
  dialogVisible.value = true
}

// 与后端 isCIDROrIP 对齐：仅 IPv4（iptables 形态与策略路由均按 IPv4 设计）
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/

function addTag() {
  const v = allowInput.value.trim()
  if (!v) return
  if (!IP_RE.test(v)) {
    ElMessage.warning('格式应为 IP（1.2.3.4）或网段（192.168.1.0/24）')
    return
  }
  if (!form.allow.includes(v)) form.allow.push(v)
  allowInput.value = ''
}

function removeTag(t) {
  form.allow = form.allow.filter((x) => x !== t)
}

// 目标模式切换：黑白名单语义完全相反——切换时确认清空旧列表，防语义反转静默提交；
// 同时把新出现的目标填写框滚到可视区（表单较长，避免"点了没反应"的错觉）
const dstItemRef = ref(null)
function onDstModeChange() {
  if (form.dst_mode !== 'off') {
    nextTick(() => {
      dstItemRef.value?.$el?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    })
  }
  // 模式切换后已选组的类型可能不再兼容（白名单组不能用于黑名单模式）
  if (form.dst_acl_group_id) {
    const g = aclGroups.value.find((x) => x.id === form.dst_acl_group_id)
    if (g && g.mode !== 'ip' && g.mode !== form.dst_mode) {
      form.dst_acl_group_id = 0
      ElMessage.info('已选名单组的类型与新限制方式不匹配，已取消引用')
    }
  }
  if (form.dst_mode === 'off') {
    form.dst_acl_group_id = 0
    form.dst_list = []
    return
  }
  if (form.dst_list.length) {
    ElMessageBox.confirm(
      `目标限制已从「${form.dst_mode === 'blacklist' ? '仅允许访问' : '禁止访问'}」切换，两种模式的语义相反。是否清空已录入的目标列表？`,
      '切换确认',
      { confirmButtonText: '清空', cancelButtonText: '保留', type: 'warning' }
    ).then(() => {
      form.dst_list = []
    }).catch(() => {})
  }
}

// 目标来源切换：手填 ↔ 引用组（二者互斥，切换时清空另一方，避免保存时被 API 拒绝）
function onDstFromChange() {
  if (form.dstFrom === 'group') {
    form.dst_list = []
  } else {
    form.dst_acl_group_id = 0
  }
}

function addDstTag() {
  const v = dstInput.value.trim()
  if (!v) return
  if (!IP_RE.test(v)) {
    ElMessage.warning('格式应为 IP（1.2.3.4）或网段（192.168.1.0/24）')
    return
  }
  if (!form.dst_list.includes(v)) form.dst_list.push(v)
  dstInput.value = ''
}

function removeDstTag(t) {
  form.dst_list = form.dst_list.filter((x) => x !== t)
}

async function save() {
  if (!form.name.trim()) return ElMessage.warning('请填写规则名称')
  if (!form.listen_addr) return ElMessage.warning('请选择入口网卡')
  if (!form.target_addr) return ElMessage.warning('请选择出口网卡')
  if (form.srcFrom === 'group' && !form.acl_group_id) return ElMessage.warning('已选择「引用名单组」，请选择一个白名单组（或切回手填网段）')
  if (form.srcFrom === 'manual' && !form.allow.length) return ElMessage.warning('手填源网段需至少一条（IP 或网段）——未指定的源一律无法穿越')
  if (form.dst_mode !== 'off') {
    if (form.dstFrom === 'group' && !form.dst_acl_group_id) {
      return ElMessage.warning('已选择「引用名单组」，请选择一个名单组（或切回手填目标）')
    }
    if (form.dstFrom === 'manual' && !form.dst_list.length) {
      return ElMessage.warning(form.dst_mode === 'whitelist' ? '「仅允许访问」需至少一条目标（空名单会拒绝全部目标）' : '「禁止访问」需至少一条目标（空名单等于不限制）')
    }
  }
  if (form.snat_mode !== 'fixed' && !(form.snat_pool || []).length) {
    return ElMessage.warning('轮换/粘滞模式需至少一个源池成员（须为出口网卡上的地址）')
  }
  saving.value = true
  try {
    const isWhitelist = !!(form.allow.length || form.acl_group_id)
    const payload = {
      name: form.name.trim(),
      protocol: 'snat',
      listen_addr: form.listen_addr,
      target_addr: form.target_addr,
      snat_ip: form.snat_ip || '',
      egress_gw: form.egress_gw.trim(),
      snat_mode: form.snat_mode,
      // fixed 模式不承载源池：不提交该字段（提交空数组也会被后端归一为空）
      snat_pool: form.snat_mode === 'fixed' ? '' : JSON.stringify(form.snat_pool || []),
      egress_ids: JSON.stringify(form.egress_ids || []),
      acl_mode: isWhitelist ? 'whitelist' : 'off',
      allow_list: !form.acl_group_id && form.allow.length ? JSON.stringify(form.allow) : '',
      deny_list: '',
      acl_group_id: form.acl_group_id || 0,
      dst_acl_mode: form.dst_mode,
      // 引用组时不再直配目标条目（API 强制二选一）
      dst_allow_list: form.dst_mode === 'whitelist' && form.dstFrom === 'manual' && form.dst_list.length ? JSON.stringify(form.dst_list) : '',
      dst_deny_list: form.dst_mode === 'blacklist' && form.dstFrom === 'manual' && form.dst_list.length ? JSON.stringify(form.dst_list) : '',
      dst_acl_group_id: form.dst_mode !== 'off' && form.dstFrom === 'group' ? (form.dst_acl_group_id || 0) : 0,
      download_limit_kbps: 0,
      max_conns: 0,
      idle_timeout_sec: 0,
      health_check: true,
      enabled: form.enabled,
    }
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
    await ElMessageBox.confirm(`确定删除 SNAT 规则「${row.name}」？删除后穿越流量即刻停止放行。`, '删除确认', { type: 'warning' })
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

onMounted(() => {
  loadEgresses()
  load()
  loadIfaces()
  timer = setInterval(() => {
    api.get('/rules', { params: { protocol: 'snat', page: page.value, page_size: pageSize.value } })
      .then(({ data }) => {
        const map = {}
        for (const r of data.items || []) map[r.id] = r
        for (const r of rules.value) {
          if (map[r.id]) {
            r.snat = map[r.id].snat
            r.live = map[r.id].live
            r.enabled = map[r.id].enabled
            r.last_error = map[r.id].last_error
          }
        }
      }).catch(() => {})
  }, 5000)
})
onUnmounted(() => clearInterval(timer))
async function loadEgresses() {
  try {
    const { data } = await api.get('/egresses')
    egresses.value = data.items || []
  } catch (e) { /* 不阻塞页面：出口下拉为空不影响规则新建/编辑 */ }
}
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
.rate {
  color: #409eff;
}
.err-tag {
  margin-left: 6px;
}
.pager {
  margin-top: 12px;
  display: flex;
  justify-content: flex-end;
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
.mono-input :deep(input) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

.rule-form-scroll {
  max-height: 68vh;
  overflow-y: auto;
  padding-right: 8px;
}
</style>
