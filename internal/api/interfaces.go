package api

import (
	"github.com/gin-gonic/gin"

	"haproxyweb/internal/proxy"
)

// listInterfaces 网卡列表（snat 规则表单下拉数据源）。
func (h *handlers) listInterfaces(c *gin.Context) {
	items := proxy.ListInterfaces()
	if items == nil {
		items = []proxy.IfaceInfo{}
	}
	c.JSON(200, gin.H{"items": items})
}
