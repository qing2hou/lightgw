package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
)

// 双进程升级协议（SIGUSR2）：父进程把监听 socket 以 fd 形式传给子进程，
// 子进程接管全部新连接后父进程排空存量连接再退出。TCP 连接无法跨进程迁移，
// 这是存量长连接不断升级的唯一方式。

// 升级环境变量约定
const (
	// EnvUpgradeChild 子进程标记（值恒为 1）
	EnvUpgradeChild = "HAWEB_UPGRADE_CHILD"
	// EnvUpgradeFDs fd 映射 JSON（ExtraFiles 从 fd=3 起）
	EnvUpgradeFDs = "HAWEB_UPGRADE_FDS"
)

// inheritedFDs 名称 -> 相对 ExtraFiles 起始（fd=3）的偏移。
type inheritedFDs map[string]uint

// InheritedListeners 子进程从父进程继承的监听对象。
type InheritedListeners struct {
	Web net.Listener
	TCP map[uint]net.Listener // ruleID -> listener
	UDP map[uint]*net.UDPConn // ruleID -> socket
}

// MarshalListeners 提取监听对象的 fd 并生成（映射 JSON, ExtraFiles 列表）。
// fd 会 dup 一份，父进程的原监听不受影响。
func MarshalListeners(web net.Listener, tcp map[uint]net.Listener, udp map[uint]*net.UDPConn) (string, []*os.File, error) {
	fds := inheritedFDs{}
	files := make([]*os.File, 0, len(tcp)+len(udp)+1)

	add := func(name string, f *os.File) error {
		if _, exists := fds[name]; exists {
			return fmt.Errorf("fd 名称冲突: %s", name)
		}
		fds[name] = uint(len(files)) // ExtraFiles 从 fd=3 开始
		files = append(files, f)
		return nil
	}

	if web != nil {
		f, err := web.(interface{ File() (*os.File, error) }).File()
		if err != nil {
			return "", nil, fmt.Errorf("提取 web 监听 fd 失败: %w", err)
		}
		if err := add("web", f); err != nil {
			return "", nil, err
		}
	}
	// 稳定顺序：按 ruleID 排序
	tcpIDs := sortedKeys(tcp)
	for _, id := range tcpIDs {
		f, err := tcp[id].(interface{ File() (*os.File, error) }).File()
		if err != nil {
			return "", nil, fmt.Errorf("提取 TCP 规则 #%d 监听 fd 失败: %w", id, err)
		}
		if err := add("tcp:"+strconv.FormatUint(uint64(id), 10), f); err != nil {
			return "", nil, err
		}
	}
	udpIDs := sortedKeys(udp)
	for _, id := range udpIDs {
		f, err := udp[id].File()
		if err != nil {
			return "", nil, fmt.Errorf("提取 UDP 规则 #%d socket fd 失败: %w", id, err)
		}
		if err := add("udp:"+strconv.FormatUint(uint64(id), 10), f); err != nil {
			return "", nil, err
		}
	}

	b, err := json.Marshal(fds)
	if err != nil {
		return "", nil, err
	}
	return string(b), files, nil
}

// unmarshalListeners 从继承的 ExtraFiles 还原监听对象（子进程启动早期调用）。
// extraFiles 即 cmd.ExtraFiles，对应子进程 fd=3 起。
func unmarshalListeners(fdsJSON string, extraFiles []*os.File) (*InheritedListeners, error) {
	var fds inheritedFDs
	if err := json.Unmarshal([]byte(fdsJSON), &fds); err != nil {
		return nil, fmt.Errorf("解析升级 fd 映射失败: %w", err)
	}
	out := &InheritedListeners{TCP: map[uint]net.Listener{}, UDP: map[uint]*net.UDPConn{}}
	for name, off := range fds {
		if int(off) >= len(extraFiles) {
			return nil, fmt.Errorf("继承 fd 越界: %s（共 %d 个）", name, len(extraFiles))
		}
		f := extraFiles[off]
		switch {
		case name == "web":
			ln, err := net.FileListener(f)
			if err != nil {
				return nil, fmt.Errorf("还原 web 监听失败: %w", err)
			}
			out.Web = ln
		case len(name) > 4 && name[:4] == "tcp:":
			id, err := strconv.ParseUint(name[4:], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("非法规则 id: %s", name)
			}
			ln, err := net.FileListener(f)
			if err != nil {
				return nil, fmt.Errorf("还原 TCP 规则 #%d 监听失败: %w", id, err)
			}
			out.TCP[uint(id)] = ln
		case len(name) > 4 && name[:4] == "udp:":
			id, err := strconv.ParseUint(name[4:], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("非法规则 id: %s", name)
			}
			pc, err := net.FilePacketConn(f)
			if err != nil {
				return nil, fmt.Errorf("还原 UDP 规则 #%d socket 失败: %w", id, err)
			}
			uc, ok := pc.(*net.UDPConn)
			if !ok {
				return nil, fmt.Errorf("UDP 规则 #%d socket 类型异常", id)
			}
			out.UDP[uint(id)] = uc
		default:
			return nil, fmt.Errorf("未知继承 fd 名称: %s", name)
		}
	}
	return out, nil
}

// UpgradeInheritedFromEnv 子进程从环境变量与 ExtraFiles 还原继承的监听。
func UpgradeInheritedFromEnv() (*InheritedListeners, error) {
	fdsJSON := os.Getenv(EnvUpgradeFDs)
	if fdsJSON == "" {
		return nil, fmt.Errorf("缺少环境变量 %s", EnvUpgradeFDs)
	}
	var fds inheritedFDs
	if err := json.Unmarshal([]byte(fdsJSON), &fds); err != nil {
		return nil, fmt.Errorf("解析升级 fd 映射失败: %w", err)
	}
	maxOff := 0
	for _, off := range fds {
		if int(off) > maxOff {
			maxOff = int(off)
		}
	}
	extra := make([]*os.File, maxOff+1)
	for i := range extra {
		extra[i] = os.NewFile(uintptr(3+i), "inherited")
	}
	return unmarshalListeners(fdsJSON, extra)
}

func sortedKeys[T any](m map[uint]T) []uint {
	ids := make([]uint, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// AdoptsAvailable 是否存在可继承的监听（父进程升级入口的空判）。
func (m *Manager) AdoptsAvailable() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.webListener != nil || len(m.tcpRules) > 0 || len(m.udpRules) > 0
}

// GatherListeners 快照当前全部监听（供升级 fd 提取）。
func (m *Manager) GatherListeners() (web net.Listener, tcp map[uint]net.Listener, udp map[uint]*net.UDPConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tcp = make(map[uint]net.Listener, len(m.tcpRules))
	for id, e := range m.tcpRules {
		tcp[id] = e.listener
	}
	udp = make(map[uint]*net.UDPConn, len(m.udpRules))
	for id, e := range m.udpRules {
		udp[id] = e.conn
	}
	return m.webListener, tcp, udp
}

// AdoptListeners 把继承的监听注册进管理器（必须在 StartAll 之前调用）。
// StartAll 对已继承监听的规则不再重新 net.Listen（避免与父进程或内核冲突）。
func (m *Manager) AdoptListeners(inherited *InheritedListeners) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webListener = inherited.Web
	for id, ln := range inherited.TCP {
		m.adoptedTCP[id] = ln
	}
	for id, conn := range inherited.UDP {
		m.adoptedUDP[id] = conn
	}
}
