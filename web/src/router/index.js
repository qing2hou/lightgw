import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/LoginView.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    component: () => import('../layout/AdminLayout.vue'),
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', name: 'dashboard', component: () => import('../views/DashboardView.vue'), meta: { title: '总览' } },
      { path: 'rules', name: 'rules', component: () => import('../views/RulesView.vue'), meta: { title: '端口映射' } },
      { path: 'snat-rules', name: 'snat-rules', component: () => import('../views/SnatRulesView.vue'), meta: { title: 'SNAT 穿越' } },
      { path: 'egresses', name: 'egresses', component: () => import('../views/EgressesView.vue'), meta: { title: '出口管理' } },
      { path: 'dnat-rules', name: 'dnat-rules', component: () => import('../views/DnatRulesView.vue'), meta: { title: '端口发布' } },
      { path: 'fw-policies', name: 'fw-policies', component: () => import('../views/FwPoliciesView.vue'), meta: { title: '防火墙策略' } },
      { path: 'sessions', name: 'sessions', component: () => import('../views/SessionsView.vue'), meta: { title: '会话表' } },
      { path: 'bw-groups', name: 'bw-groups', component: () => import('../views/BWGroupsView.vue'), meta: { title: '带宽包' } },
      { path: 'acl-groups', name: 'acl-groups', component: () => import('../views/AclGroupsView.vue'), meta: { title: '名单组' } },
      { path: 'traffic-logs', name: 'traffic-logs', component: () => import('../views/TrafficLogsView.vue'), meta: { title: '流量日志' } },
      { path: 'audit-logs', name: 'audit-logs', component: () => import('../views/AuditLogsView.vue'), meta: { title: '操作审计' } },
      { path: 'observability', name: 'observability', component: () => import('../views/ObservabilityView.vue'), meta: { title: '运行监控' } },
      { path: 'backup', name: 'backup', component: () => import('../views/BackupView.vue'), meta: { title: '备份恢复' } },
      { path: 'settings', name: 'settings', component: () => import('../views/SettingsView.vue'), meta: { title: '设置' } },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const token = localStorage.getItem('haweb_token')
  if (!to.meta.public && !token) return { path: '/login' }
  if (to.path === '/login' && token) return { path: '/' }
  return true
})

export default router
