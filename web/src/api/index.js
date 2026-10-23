import axios from 'axios'
import { ElMessage } from 'element-plus'
import router from '../router'

const api = axios.create({ baseURL: '/api', timeout: 30000 })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('haweb_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (resp) => resp,
  async (err) => {
    if (err.response) {
      // blob 响应（文件下载）的错误体仍是 Blob，解析成 JSON 让 errMsg 能取到错误信息
      if (err.response.data instanceof Blob) {
        try {
          err.response.data = JSON.parse(await err.response.data.text())
        } catch (e) {
          // 非 JSON 错误体，保留原样
        }
      }
      if (err.response.status === 401) {
        localStorage.removeItem('haweb_token')
        if (router.currentRoute.value.path !== '/login') {
          router.push('/login')
        }
      }
      // 仍使用默认密码：除改密相关接口外一律被服务端 403 拦截，引导到设置页
      if (
        err.response.status === 403 &&
        err.response.data &&
        err.response.data.code === 'must_change_password' &&
        router.currentRoute.value.path !== '/settings'
      ) {
        ElMessage.warning('请先修改默认密码')
        router.push('/settings')
      }
    }
    return Promise.reject(err)
  }
)

export function errMsg(e) {
  return (e && e.response && e.response.data && e.response.data.error) || (e && e.message) || '请求失败'
}

export default api
