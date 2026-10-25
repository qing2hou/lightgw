package api

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"haproxyweb/internal/model"
)

// TestFwPolicyReorderTwoPhase 复审 #4 回归：order uniqueIndex 下非平凡重排
// （[2,1,3]→1,2,3）必须成功——逐行直写会撞 UNIQUE 约束。
func TestFwPolicyReorderTwoPhase(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_pragma=foreign_keys=1"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.FwPolicy{}); err != nil {
		t.Fatal(err)
	}
	pols := []model.FwPolicy{
		{Name: "a", Order: 1, Action: "drop"}, {Name: "b", Order: 2, Action: "drop"}, {Name: "c", Order: 3, Action: "drop"},
	}
	for i := range pols {
		if err := db.Create(&pols[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	// 交换前两行：ordered_ids = [2,1,3]
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.FwPolicy{}).
			Where("`order` > 0").
			UpdateColumn("order", gorm.Expr("-`order`")).Error; err != nil {
			return err
		}
		for i, id := range []uint{pols[1].ID, pols[0].ID, pols[2].ID} {
			if err := tx.Model(&model.FwPolicy{}).Where("id = ?", id).Update("order", i+1).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("重排失败（UNIQUE 约束回归）: %v", err)
	}
	var got []model.FwPolicy
	db.Order("`order` asc").Find(&got)
	if len(got) != 3 || got[0].Name != "b" || got[1].Name != "a" || got[2].Name != "c" {
		t.Fatalf("重排结果: %+v", got)
	}
}
