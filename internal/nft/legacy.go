// iptables-legacy（x_tables）宿主检测：IPT_SO_GET_INFO/GET_ENTRIES sockopt
// 读原生 ip_tables 的 FORWARD policy（零 exec；评审 M3——纯 legacy 宿主的
// policy DROP 在 nf_tables 里不可见，原实现 relied-upon 的 fail-fast 是死逻辑）。
package nft

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// iptables legacy sockopt 值（linux/netfilter_ipv4/ip_tables.h；x/sys/unix
// 未导出——ABI 自 2.6 内核稳定，按头文件值定义）。
const (
	iptBaseCtl        = 64
	iptSoGetInfo      = iptBaseCtl     // IPT_SO_GET_INFO
	iptSoGetEntries   = iptBaseCtl + 1 // IPT_SO_GET_ENTRIES
	xtTableMaxNameLen = 32
	nfInetNumhooks    = 5 // enum nf_inet_hooks（PRE_ROUTING..POST_ROUTING）
	forwardHookIdx    = 2 // NF_INET_FORWARD
)

// ipt_entry 头部固定尺寸（结构体布局见 linux/netfilter_ipv4/ip_tables.h；
// Go 侧不 unsafe.Cast 整个结构——按偏移量读，字段常量化防魔法数）。
const (
	iptIPSize        = 84  // struct ipt_ip：src/dst/smsk/dmsk(16)+in/out iface+mask(64)+proto(2)+flags(1)+inv(1)
	iptEntryHdrNoCtr = 92  // ipt_ip + nfcache(4) + target_offset(2) + next_offset(2)
	iptEntryHdrSize  = 112 // + comefrom(4) + xt_counters(16)
)

// iptGetinfo IPT_SO_GET_INFO 的参数/返回结构（ipt_getinfo）。
type iptGetinfo struct {
	Name       [xtTableMaxNameLen]byte
	ValidHooks uint32
	HookEntry  [nfInetNumhooks]uint32
	Underflow  [nfInetNumhooks]uint32
	NumEntries uint32
	Size       uint32
}

// getEntries IPT_SO_GET_ENTRIES 请求（头长 hdrLen：64 位 ABI=40——36 字节
// 字段 + 4 字节尾部填充，柔性数组 ipt_entry 对齐 8 拉出填充（C sizeof 语义），
// arm64 同；32 位 ABI=36）。内核严格校验 optlen == 内核 sizeof + size——
// 头长不匹配报 EINVAL，调用方据此降级重试。返回 buf 含头，entries 从
// buf[hdrLen:] 起（调用方按 buf 长-声明 size 反推实际头长）。
func getEntries(fd int, size uint32, hdrLen int) ([]byte, syscall.Errno) {
	buf := make([]byte, hdrLen+int(size))
	copy(buf[0:xtTableMaxNameLen], "filter")
	binary.LittleEndian.PutUint32(buf[xtTableMaxNameLen:xtTableMaxNameLen+4], size)
	bufLen := uint32(len(buf))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(unix.IPPROTO_IP), uintptr(iptSoGetEntries),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufLen)), 0)
	return buf, errno
}

// legacyForwardPolicyDrop 检测 iptables-legacy filter 表 FORWARD 链 policy 是否 DROP。
// 返回 (drop, tableExists, err)。表不存在 → (false, false, nil)。
// 判定：FORWARD underflow 条目（policy 行）的 xt_standard_target.verdict：
// -1（-NF_DROP-1）→ DROP；-2（-NF_ACCEPT-1）→ ACCEPT；其余保守按 DROP。
func legacyForwardPolicyDrop() (drop, exists bool, err error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return false, false, fmt.Errorf("legacy 探测 socket 失败（需要 root/CAP_NET_RAW）: %w", err)
	}
	defer unix.Close(fd)

	var info iptGetinfo
	copy(info.Name[:], "filter")
	infoLen := uint32(unsafe.Sizeof(info))
	if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(unix.IPPROTO_IP), uintptr(iptSoGetInfo),
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&infoLen)), 0); errno != 0 {
		if errno == unix.ENOENT {
			return false, false, nil // 无 legacy filter 表（全新部署/纯 nft 宿主）
		}
		return false, false, fmt.Errorf("IPT_SO_GET_INFO(filter): %w", errno)
	}
	if info.ValidHooks&(1<<forwardHookIdx) == 0 {
		return false, true, nil // FORWARD 未挂钩（无 policy 语义）
	}

	// 读全量 entries：64 位 ABI 40 头优先，EINVAL（32 位平台内核 sizeof=36）
	// 降级 36 头重试（两次 EINVAL 才报错——错误侧保守，评审附注）
	buf, errno := getEntries(fd, info.Size, 40)
	if errno == unix.EINVAL {
		buf, errno = getEntries(fd, info.Size, 36)
	}
	if errno != 0 {
		return false, false, fmt.Errorf("IPT_SO_GET_ENTRIES(filter): %w", errno)
	}

	// underflow 条目：entries 数组紧接请求头（实际头长 = buf 长 - 声明 size）
	uf := int(info.Underflow[forwardHookIdx])
	hdrSize := len(buf) - int(info.Size)
	if hdrSize < 0 || hdrSize+uf+iptEntryHdrSize > len(buf) {
		return true, true, nil // 布局异常——读不懂按 DROP 保守处理（复审 M3-b）
	}
	entry := buf[hdrSize+uf:]
	// target_offset：相对条目起点；offset iptIPSize+nfcache 后 2 字节处
	targetOffset := int(binary.LittleEndian.Uint16(entry[iptIPSize+4 : iptIPSize+6]))
	// xt_standard_target 布局：u16 target_size + name[29] + u8 rev（内核 uapi 对齐后 32B）
	// + int verdict（offset 32..36）。内核侧 target union 用 udata 时结构有差异，
	// 但 kernel→user 的标准 target 内容固定为 {verdict}（对齐在 target 头后）。
	verdictOff := targetOffset + 32
	if verdictOff+4 > len(entry) {
		return true, true, nil // 读不懂按 DROP 保守处理（评审 M3-b）
	}
	verdict := int32(binary.LittleEndian.Uint32(entry[verdictOff : verdictOff+4]))
	return policyVerdictIsDrop(verdict), true, nil
}

// policyVerdictIsDrop 标准 target verdict 三值分类（libiptc 编码 -NF_x-1）：
// -1 → DROP，-2 → ACCEPT，其余任何值（读不懂/异常）保守按 DROP
// （宁多锚点/拒装，不漏黑洞——复审 M3-a/b）。
func policyVerdictIsDrop(verdict int32) bool {
	const (
		nfDropVerdict   int32 = -1 // -NF_DROP-1
		nfAcceptVerdict int32 = -2 // -NF_ACCEPT-1
	)
	switch verdict {
	case nfDropVerdict:
		return true
	case nfAcceptVerdict:
		return false
	default:
		return true
	}
}
