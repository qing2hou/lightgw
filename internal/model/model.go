package model

import "time"

const (
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolSNAT = "snat" // 内核 iptables/tc 三层转发（不监听端口；listen_addr=入口网卡、target_addr=出口网卡）
	ProtocolDNAT = "dnat" // 内核 nftables 端口发布（listen_addr=公网IP:端口、target_addr=内网后端IP:端口）

	// DnatRejectMode dnat 后端不可达时对公网客户端的行为。
	DnatRejectModeReject  = "reject"  // icmp admin-prohibited / tcp reset 即时拒绝
	DnatRejectModeTimeout = "timeout" // 静默丢弃（客户端超时）

	StatusActive = "active"
	StatusClosed = "closed"
	StatusError  = "error"
	StatusDenied = "denied"

	// AclMode 名单模式：off=不启用，whitelist=仅白名单生效，blacklist=仅黑名单生效。
	// 空串为旧数据兼容值，运行时按"黑名单优先+白名单限制"的并用量纲处理。
	AclModeOff       = "off"
	AclModeWhitelist = "whitelist"
	AclModeBlacklist = "blacklist"

	// AclGroupModeIP 名单组的第三种类型：IP 组——语义中性的 IP 集合。
	// 白/黑名单组只能被同模式的规则引用；IP 组不带方向语义，可被白名单
	// 或黑名单（源名单或目标限制）任意引用，组条目按引用方的语义生效。
	AclGroupModeIP = "ip"
)

// AclGroupModes 名单组的合法类型集合（创建/更新校验用）。
func AclGroupModes() []string {
	return []string{AclModeWhitelist, AclModeBlacklist, AclGroupModeIP}
}

// AclGroupMatchesMode 名单组能否被指定模式引用：同模式组，或中性 IP 组。
// 规则侧的白/黑名单模式与目标限制模式共用此判据。
func AclGroupMatchesMode(groupMode, useMode string) bool {
	if groupMode == AclGroupModeIP {
		return true
	}
	return groupMode == useMode
}

type User struct {
	ID                 uint   `gorm:"primaryKey" json:"id"`
	Username           string `gorm:"uniqueIndex;size:64" json:"username"`
	PasswordHash       string `json:"-"`
	MustChangePassword bool   `json:"must_change_password"`
	TokenVersion       int    `json:"-"` // 改密时递增，旧 JWT 立即失效
	// TOTP 两步验证（RFC 6238）：TOTPSecret 为 base32 密钥（Begin 暂存待扫码，
	// Confirm 验证通过后 TOTPEnabled 置位才真正生效）；BackupCodes 为一次性
	// 恢复码的 JSON 数组字符串列（同 AllowList 惯例，旧数据 NULL 安全）。
	// 三者均不参与 JSON 序列化导出。
	TOTPSecret  string    `json:"-"`
	TOTPEnabled bool      `json:"-"`
	BackupCodes string    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ForwardRule 转发规则。ListenAddr 形如 ":9000" 或 "0.0.0.0:9000"；
// AclMode 选择启用哪种名单（off/whitelist/blacklist）；
// AclGroupID 非零时名单条目引用名单组（组展开发生在 buildRuleConfig，
// 引用与直配（AllowList/DenyList 二选一：whitelist 模式引用白名单组、
// blacklist 模式引用黑名单组）；全部为 JSON 字符串数组，元素支持单 IP 与 CIDR 网段。
type ForwardRule struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	Name              string    `gorm:"size:128" json:"name"`
	Protocol          string    `gorm:"size:16;index" json:"protocol"`
	ListenAddr        string    `gorm:"size:64" json:"listen_addr"`
	TargetAddr        string    `gorm:"size:256" json:"target_addr"`
	AclMode           string    `gorm:"size:16" json:"acl_mode"`
	AllowList         string    `gorm:"type:text" json:"allow_list"`
	DenyList          string    `gorm:"type:text" json:"deny_list"`
	AclGroupID        uint      `gorm:"index;default:0" json:"acl_group_id"`                   // 引用的名单组 ID，0 = 未引用（用直配名单）
	DstAclMode        string    `gorm:"size:16;default:off" json:"dst_acl_mode"`               // snat 目标名单模式（off/whitelist/blacklist）——穿越后能/不能访问哪些目标
	DstAllowList      string    `gorm:"type:text" json:"dst_allow_list"`                       // snat 目标白名单（JSON 字符串数组；whitelist 模式生效）
	DstDenyList       string    `gorm:"type:text" json:"dst_deny_list"`                        // snat 目标黑名单（JSON 字符串数组；blacklist 模式生效）
	DstAclGroupID     uint      `gorm:"index;default:0" json:"dst_acl_group_id"`               // 目标限制引用的名单组 ID；0 = 不引用（用直配目标名单）
	SnatIP            string    `gorm:"size:64" json:"snat_ip"`                                // snat 规则显式出口源 IP；空 = 自动取出口网卡首 IPv4
	DnatRejectMode    string    `gorm:"size:16;default:reject" json:"dnat_reject_mode"`        // dnat 规则后端不可达时对客户端行为（reject/timeout）
	SnatMode          string    `gorm:"size:16;default:fixed" json:"snat_mode"`                // snat 源模式：fixed（单 IP）/ rotate（会话轮换）/ sticky（源粘滞）
	SnatPool          string    `gorm:"type:text" json:"snat_pool"`                            // SNAT 源池（JSON IP 数组；rotate/sticky 模式）
	EgressIDs         string    `gorm:"type:text" json:"egress_ids"`                           // 出口绑定（JSON 出口 ID 数组；空 = 全部出口）
	EgressGw          string    `gorm:"size:64" json:"egress_gw"`                              // snat 出口网关（可选）
	BWGroupID         uint      `gorm:"index;default:0" json:"bw_group_id"`                    // 所属带宽包 ID（成员关系）；0 = 独立行为（自身限速）
	MinKBps           int64     `gorm:"column:min_kbps" json:"min_kbps"`                       // 入包时可设的保底带宽 KB/s（htb rate；闲时可借用至包总额 ceil）；独立规则忽略
	SourceIP          string    `gorm:"size:64" json:"source_ip"`                              // tcp/udp 连接后端时绑定的本机源 IP（后端看到的来源）；空 = 路由自动（策略路由）
	UploadLimitKBps   int64     `gorm:"column:upload_limit_kbps" json:"upload_limit_kbps"`     // 0 = 不限
	DownloadLimitKBps int64     `gorm:"column:download_limit_kbps" json:"download_limit_kbps"` // 0 = 不限
	MaxConns          int       `json:"max_conns"`                                             // 并发连接/请求数上限，0 = 不限
	IdleTimeoutSec    int       `json:"idle_timeout_sec"`                                      // TCP 空闲超时覆盖（秒），0 = 跟随全局 tuning.tcp_idle_timeout_sec
	HealthCheck       *bool     `json:"health_check"`                                          // 后端健康检测开关（仅 TCP 规则生效），nil/true = 开启
	Enabled           bool      `json:"enabled"`
	LastError         string    `gorm:"size:512" json:"last_error"` // 最近一次启动/应用失败原因，成功时清空
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Egress 出口（US4/US5）：网卡 + 网关 + 优先级（层：小者主）/ 层内权重 +
// 探测配置。运行时状态（Up/时延/最近切换）为内存原子量不入库——重启后由
// 立即探测恢复（healthz/observability 暴露）。
type Egress struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:128;uniqueIndex" json:"name"`
	Iface       string    `gorm:"size:64;index" json:"iface"`                // 出口网卡名
	GatewayV4   string    `gorm:"size:64" json:"gateway_v4"`                 // v4 网关（空=无 v4）
	GatewayV6   string    `gorm:"size:64" json:"gateway_v6"`                 // v6 网关（空=无 v6）
	Priority    int       `gorm:"default:10" json:"priority"`                // 层：小者优先（主备）
	Weight      int       `gorm:"default:1" json:"weight"`                   // 层内权重 1..100
	ProbeMode   string    `gorm:"size:16;default:icmp-gw" json:"probe_mode"` // icmp-gw / icmp-target / tcp-target / none
	ProbeTarget string    `gorm:"size:256" json:"probe_target"`              // 探测目标（icmp-target/tcp-target 必填；tcp 为 host:port）
	IntervalSec int       `gorm:"default:3" json:"interval_sec"`
	FailCount   int       `gorm:"default:2" json:"fail_count"` // 判 down 阈值
	UpCount     int       `gorm:"default:2" json:"up_count"`   // 判回 up 阈值
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FwPolicy 状态防火墙策略（US3）：有序规则列表，作用于全部穿越（snat）与
// 发布（dnat）流量。先命中先适用；全部未命中走默认拒绝（v1 白名单穿越形态）。
// 已建会话由 pre_mark established 打标短路，不重复评估。
type FwPolicy struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:128" json:"name"`
	Order     int       `gorm:"uniqueIndex" json:"order"`        // 升序即评估序（1 起）
	Action    string    `gorm:"size:8" json:"action"`            // accept / drop
	SrcList   string    `gorm:"type:text" json:"src_list"`       // JSON 数组（IP/CIDR；空=任意）
	DstList   string    `gorm:"type:text" json:"dst_list"`       // JSON 数组（IP/CIDR；空=任意）
	Proto     string    `gorm:"size:8;default:tcp" json:"proto"` // tcp / udp / icmp / any
	PortRange string    `gorm:"size:128" json:"port_range"`      // "80" / "80,443,1000-2000"（any/icmp 空）
	Enabled   bool      `gorm:"default:true" json:"enabled"`
	Comment   string    `gorm:"size:256" json:"comment"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BWGroup 带宽包：多条转发规则共享的下载（出向）带宽额度。成员关系存于规则行
// （ForwardRule.BWGroupID）；包侧"引用规则"由 API 批量改写成员规则实现。
// 共享执行：tc 每成员网卡 htb 的 per-包 class 各自限total_kbps（同额度多卡独立满额——单卡
// 场景即真共享；跨卡为近似，文档声明）。规则入包后自身限速字段不生效。
type BWGroup struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:128;uniqueIndex" json:"name"`
	TotalKBps int64     `gorm:"column:total_kbps" json:"total_kbps"` // 上下行合计单额度 KB/s（>0）
	MinKBps   int64     `gorm:"column:min_kbps" json:"min_kbps"`     // 每源保底带宽 KB/s（拥塞时每源至少；0 = 默认 1024）
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AclGroup 名单组：可复用的 IP 名单集合，规则通过 acl_group_id（源名单）
// 或 dst_acl_group_id（snat 目标限制）引用。
// Mode 决定组语义：whitelist/blacklist 带方向语义，只能被同模式的引用方使用；
// ip 为中性 IP 组，可被任意模式（白名单、黑名单、目标限制）引用，条目按
// 引用方语义生效。Entries 为 JSON 字符串数组（元素支持单 IP 与 CIDR 网段）。
// 组条目变更时联动重应用所有引用中的规则。
type AclGroup struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:128;uniqueIndex" json:"name"`
	Mode      string    `gorm:"size:16" json:"mode"` // whitelist / blacklist / ip
	Entries   string    `gorm:"type:text" json:"entries"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TrafficLog 逐连接/逐请求流量日志。RuleName 冗余存储，规则删除后日志仍可读。
type TrafficLog struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	RuleID        uint       `gorm:"index" json:"rule_id"`
	RuleName      string     `gorm:"size:128" json:"rule_name"`
	Protocol      string     `gorm:"size:16;index" json:"protocol"`
	SourceIP      string     `gorm:"size:64;index" json:"source_ip"`
	SourcePort    int        `json:"source_port"`
	ListenIP      string     `gorm:"size:64" json:"listen_ip"` // 客户端访问的本机 IP（规则监听地址；如 172.16.40.10）
	ListenPort    int        `json:"listen_port"`              // 客户端访问的监听端口（如 ssh 规则的 1022；区分同规则多入口）
	TargetAddr    string     `gorm:"size:256" json:"target_addr"`
	UploadBytes   int64      `json:"upload_bytes"`
	DownloadBytes int64      `json:"download_bytes"`
	Status        string     `gorm:"size:16;index" json:"status"`
	ErrorMsg      string     `gorm:"size:512" json:"error_msg"`
	StartedAt     time.Time  `gorm:"index" json:"started_at"`
	EndedAt       *time.Time `json:"ended_at"`
	DurationMs    int64      `json:"duration_ms"`
}

// LoginFail 登录失败锁定状态（按来源 IP）。落库使锁定在进程重启后仍然生效，
// 防止攻击者借重启重置计数。
type LoginFail struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	IP          string     `gorm:"uniqueIndex;size:64" json:"ip"`
	FailCount   int        `json:"fail_count"`
	LockedUntil *time.Time `json:"locked_until"`
	LastFailAt  time.Time  `json:"last_fail_at"`
}

// HealthLog 后端健康检测结果（每规则每分钟一条，health.go 写入）。
// 保留期跟随 web.log_retention_days。
type HealthLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	RuleID    uint      `gorm:"index:idx_health_rule_time,priority:1" json:"rule_id"`
	Up        bool      `json:"up"`
	ErrorMsg  string    `gorm:"size:512" json:"error_msg"`
	CheckedAt time.Time `gorm:"index:idx_health_rule_time,priority:2" json:"checked_at"`
}

type AuditLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"size:64;index" json:"username"`
	Action    string    `gorm:"size:64;index" json:"action"`
	Detail    string    `gorm:"type:text" json:"detail"`
	IP        string    `gorm:"size:64" json:"ip"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// SessionInfo 活跃会话实时信息（仅内存，不落库）。
type SessionInfo struct {
	ID         int64  `json:"id"`
	RuleID     uint   `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	Protocol   string `json:"protocol"`
	SourceIP   string `json:"source_ip"`
	SourcePort int    `json:"source_port"`
	ListenIP   string `json:"listen_ip"`
	ListenPort int    `json:"listen_port"`
	TargetAddr string `json:"target_addr"`
	// DialLocalPort 是网关拨后端时内核分配的本地端口（0 = 未知/UDP）。
	//
	// 端口映射是用户态转发，conntrack 里是两条独立连接：
	//   入向段：客户端 ip:port → 网关监听 ip:port
	//   出向段：网关拨号源 ip:DialLocalPort → 后端 TargetAddr
	// 会话表用它把两段合并成一条展示，避免同一逻辑连接出现两行。
	DialLocalPort int       `json:"dial_local_port"`
	UploadBytes   int64     `json:"upload_bytes"`
	DownloadBytes int64     `json:"download_bytes"`
	StartedAt     time.Time `json:"started_at"`
}

// SessionStats 会话计数接口，供 TCP/UDP 引擎实现。
type SessionStats interface {
	Snapshot() (upload int64, download int64)
}
