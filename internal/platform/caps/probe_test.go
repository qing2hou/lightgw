package caps

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// TestNftProbeCleansUp 探测后不能残留临时表。
//
// 这是安全要求：在业务机上探测，留下的表可能影响业务。
// 无权限时跳过（CI 环境）。
func TestNftProbeCleansUp(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("无 nft 命令")
	}
	ctx := context.Background()
	err := NftProbe(ctx)
	if err != nil {
		// 无 CAP_NET_ADMIN 时必然失败——只验证失败时不残留
		out, _ := exec.Command("nft", "list", "tables").CombinedOutput()
		if strings.Contains(string(out), "haweb_caps_probe") {
			t.Fatalf("★ 探测失败后残留了临时表: %s", out)
		}
		t.Skipf("无权限探测（%v），已确认无残留", err)
	}
	// 成功时也必须无残留
	out, _ := exec.Command("nft", "list", "tables").CombinedOutput()
	if strings.Contains(string(out), "haweb_caps_probe") {
		t.Fatalf("★ 探测成功后残留了临时表: %s", out)
	}
}

// TestIfbProbeCleansUp 探测后不能残留临时 ifb 设备。
func TestIfbProbeCleansUp(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("无 ip 命令")
	}
	err := IfbProbe(context.Background())
	if err != nil {
		out, _ := exec.Command("ip", "link", "show").CombinedOutput()
		if strings.Contains(string(out), "haweb-caps-ifb") {
			t.Fatalf("★ 探测失败后残留了临时 ifb: %s", out)
		}
		t.Skipf("无权限探测（%v），已确认无残留", err)
	}
	out, _ := exec.Command("ip", "link", "show").CombinedOutput()
	if strings.Contains(string(out), "haweb-caps-ifb") {
		t.Fatalf("★ 探测成功后残留了临时 ifb: %s", out)
	}
}

// TestSqliteWALProbe 真实探测：应在任意可写目录成功。
func TestSqliteWALProbe(t *testing.T) {
	if err := SqliteWALProbe(context.Background()); err != nil {
		t.Fatalf("SQLite WAL 探测应成功（临时目录一定可写）: %v", err)
	}
}

// TestConntrackProbe 真实探测：无权限时返回错误但不 panic。
func TestConntrackProbe(t *testing.T) {
	err := ConntrackProbe(context.Background())
	if err != nil {
		t.Logf("conntrack 不可用（预期在无 CAP_NET_ADMIN 的环境）: %v", err)
		if !strings.Contains(err.Error(), "nf_conntrack") &&
			!strings.Contains(err.Error(), "CAP_NET_ADMIN") {
			t.Fatalf("失败提示应给出原因线索，实际: %v", err)
		}
	}
}

// TestTcProbe 真实探测：tc 存在时应通过。
func TestTcProbe(t *testing.T) {
	_, err := exec.LookPath("tc")
	want := err == nil
	got := TcProbe(context.Background()) == nil
	if got != want {
		t.Fatalf("TcProbe 结果（%v）与 LookPath（%v）不一致", got, want)
	}
}
