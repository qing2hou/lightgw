import { defineStore } from 'pinia'
import api from '../api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    username: localStorage.getItem('haweb_username') || '',
    mustChangePassword: localStorage.getItem('haweb_must_change') === '1',
  }),
  actions: {
    // applyLogin 统一落地登录态（密码直登与两步验证登录共用）
    applyLogin(data) {
      localStorage.setItem('haweb_token', data.token)
      if (data.username !== undefined) localStorage.setItem('haweb_username', data.username)
      localStorage.setItem('haweb_must_change', data.must_change_password ? '1' : '0')
      this.username = data.username ?? this.username
      this.mustChangePassword = !!data.must_change_password
    },
    async login(username, password) {
      const { data } = await api.post('/login', { username, password })
      this.applyLogin(data)
    },
    async refresh() {
      try {
        const { data } = await api.get('/me')
        this.username = data.username
        this.mustChangePassword = !!data.must_change_password
        localStorage.setItem('haweb_must_change', data.must_change_password ? '1' : '0')
      } catch (e) {
        /* 忽略 */
      }
    },
    async logout() {
      try {
        await api.post('/logout')
      } catch (e) {
        /* 忽略 */
      }
      localStorage.removeItem('haweb_token')
      localStorage.removeItem('haweb_username')
      localStorage.removeItem('haweb_must_change')
      this.username = ''
    },
    passwordChanged() {
      this.mustChangePassword = false
      localStorage.setItem('haweb_must_change', '0')
    },
  },
})
