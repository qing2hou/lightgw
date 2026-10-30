// Package sessionapp 是会话管理的用例编排层。
//
// 补上旧实现缺失的两个接口（技术方案 §8.2）：
//   - 批量清会话（旧代码只支持单条 {id}）
//   - 名单组变更后踢匹配会话
//
// 本包不 import gin，也不直接读 /proc 或 netlink——全部通过端口注入。
package sessionapp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// Session 是本包需要的会话视图。
type Session struct {
	// ID 是稳定的会话标识（前端用它引用）。
	ID string
	// Proto 是 "tcp" / "udp"。
	Proto string
	// SrcAddr / DstAddr 是原始方向的地址。
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
}

// Lister 是会话语义端口。
type Lister interface {
	List(ctx context.Context) ([]Session, error)
}

// Killer 是掐断端口。
//
// 单条与批量分开：单条失败要能单独报告（前端要显示哪几条没踢成），
// 批量接口不能因为一条失败就整体回滚（其它会话该踢还是要踢）。
type Killer interface {
	Kill(ctx context.Context, id string) error
}

// Auditor 是审计端口。
type Auditor interface {
	Record(user, action, detail, clientIP string)
}

// ErrNotFound 表示会话不存在。
var ErrNotFound = errors.New("会话不存在")

// Service 是会话用例。
type Service struct {
	lister Lister
	killer Killer
	audit  Auditor
}

// New 创建服务。
func New(lister Lister, killer Killer, audit Auditor) *Service {
	return &Service{lister: lister, killer: killer, audit: audit}
}

// BatchResult 是批量操作的结果。
type BatchResult struct {
	// Killed 是成功掐断的会话 ID。
	Killed []string
	// Failed 是失败项（ID → 原因）。
	//
	// **必须逐条报告**：批量接口不能只给一个总数，运维需要知道具体哪几条没成。
	Failed map[string]string
	// NotFound 是不存在的会话 ID（可能已自然结束）。
	NotFound []string
}

// KillBatch 按 ID 列表批量掐断会话。
//
// 语义：
//   - 逐条执行，**单条失败不影响其它条**
//   - 不存在的 ID 单独归类为 NotFound（不是错误——会话可能已自然结束，
//     这在长时间打开的页面上是常态）
//   - 空列表返回空结果（不是错误）
//   - 超过 maxBatch 条直接拒绝（防误用：一次踢 10 万条会把 conntrack
//     和审计日志同时打爆）
func (s *Service) KillBatch(ctx context.Context, ids []string, actor, clientIP string) (*BatchResult, error) {
	const maxBatch = 1000
	if len(ids) > maxBatch {
		return nil, fmt.Errorf("批量掐断失败: 单次最多 %d 条（收到 %d 条）", maxBatch, len(ids))
	}
	res := &BatchResult{
		Failed: make(map[string]string, len(ids)),
	}
	// 去重：重复 ID 重复踢没有意义，且会让 Failed/NotFound 出现重复项
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("批量掐断被取消: %w", err)
		}
		if err := s.killer.Kill(ctx, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				res.NotFound = append(res.NotFound, id)
				continue
			}
			res.Failed[id] = publicReason(err)
			continue
		}
		res.Killed = append(res.Killed, id)
	}
	if s.audit != nil && (len(res.Killed) > 0 || len(res.Failed) > 0) {
		s.audit.Record(actor, "session_kill_batch",
			fmt.Sprintf("批量掐断：成功 %d，失败 %d，不存在 %d",
				len(res.Killed), len(res.Failed), len(res.NotFound)), clientIP)
	}
	return res, nil
}

// KillByACLGroup 掐断「源地址落在该名单组内」的会话。
//
// 用途（验收用例「名单组生效」）：把自己加入黑名单后，**已建立的会话
// 必须立即断开**，而不是等 conntrack 超时。否则用户会看到「拉黑了但还能
// 继续用」，这是安全上有实质影响的行为。
//
// 匹配口径：只按源地址。理由是本产品的名单组语义就是「按源 IP 放行/拒绝」，
// 目的维度是 SNAT 目标限制（另一处引用位），不在本函数的职责内。
func (s *Service) KillByACLGroup(ctx context.Context, groupID uint, prefixes []netip.Prefix, actor, clientIP string) (int, error) {
	if len(prefixes) == 0 {
		// 空组没有匹配面：既不报错也不踢任何会话。
		// 报错会让「清空名单组」这个合法操作失败。
		return 0, nil
	}
	sessions, err := s.lister.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("列出会话失败: %w", err)
	}
	killed := 0
	for _, sess := range sessions {
		if err := ctx.Err(); err != nil {
			return killed, fmt.Errorf("掐断名单组会话被取消: %w", err)
		}
		if !matchAnyPrefix(sess.SrcAddr, prefixes) {
			continue
		}
		if err := s.killer.Kill(ctx, sess.ID); err != nil {
			// 单条失败继续：名单组里通常有几十上百条会话，
			// 一条踢不掉不该让整次操作失败
			continue
		}
		killed++
	}
	if s.audit != nil {
		s.audit.Record(actor, "acl_group_kick_sessions",
			fmt.Sprintf("名单组#%d 变更后掐断会话 %d 条", groupID, killed), clientIP)
	}
	return killed, nil
}

// matchAnyPrefix 报告 addr 是否落在任一网段内。
func matchAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// publicReason 把内部错误转成可回传给客户端的简短原因。
//
// **不泄露内部细节**（技术方案 §8.5）：SQL 语句、文件路径、栈信息一律不出去。
// 这里只做白名单化的粗分类，具体错误由调用方记日志。
func publicReason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "操作被取消"
	}
	if errors.Is(err, ErrNotFound) {
		return "会话不存在"
	}
	return "掐断失败"
}
