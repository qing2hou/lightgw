package nftables

import (
	"github.com/google/nftables"
)

// connAPI 是 Engine 使用的最小 netlink 接口。
//
// 抽成接口的唯一目的是**可测试性**：切换逻辑（尤其是失败回滚）必须在 CI 里
// 可验证，而真实的 nftables.Conn 需要 CAP_NET_ADMIN。S1 的 DoD 要求
// 「连续切换 200 次」与「注入 AddRule 失败」，这两条在真机上做成本高且危险
// （业务机）。
//
// 生产路径传 *nftables.Conn（它满足本接口），测试路径传内存实现。
// 接口方法刻意做成与 nftables.Conn 完全一致的签名，避免包装层的语义漂移。
type connAPI interface {
	AddTable(t *nftables.Table) *nftables.Table
	AddChain(c *nftables.Chain) *nftables.Chain
	ListChains() ([]*nftables.Chain, error)
	AddRule(r *nftables.Rule) *nftables.Rule
	DelRule(r *nftables.Rule) error
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
	FlushChain(c *nftables.Chain)
	Flush() error
	CloseLasting() error
}

// 编译期断言：*nftables.Conn 必须满足 connAPI。
//
// 这条断言的价值：一旦上游库改了方法签名，编译会立即失败，
// 而不是等到运行时才发现行为差异。
var _ connAPI = (*nftables.Conn)(nil)
