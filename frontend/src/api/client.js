import axios from 'axios'

const getApiBase = () => {
  if (import.meta.env.VITE_API_URL) {
    return `${import.meta.env.VITE_API_URL}/api`
  }
  
  // Auto-detect environment if no explicit env var is set
  const isLocal = typeof window !== 'undefined' && 
    (window.location.hostname === 'localhost' || 
     window.location.hostname === '127.0.0.1' || 
     window.location.hostname.startsWith('192.168.'));
     
  return isLocal ? '/api' : 'https://apk-shield-production.up.railway.app/api'
}

const API_BASE = getApiBase()

const api = axios.create({
  baseURL: API_BASE,
  timeout: 120000, // 2 min for analysis
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const msg = error.response?.data?.detail || error.message || 'Request failed'
    return Promise.reject(new Error(msg))
  }
)

export const uploadAPK = async (file, onProgress) => {
  const formData = new FormData()
  formData.append('file', file)
  const response = await api.post('/upload/', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (onProgress && e.total) {
        onProgress(Math.round((e.loaded * 100) / e.total))
      }
    },
  })
  return response.data
}

export const analyzeAPK = async (fileHash, filename) => {
  const response = await api.post(
    `/analyze/${fileHash}?filename=${encodeURIComponent(filename)}`
  )
  return response.data
}

export const getAnalysis = async (id) => {
  const response = await api.get(`/analyze/${id}`)
  return response.data
}

export const getHistory = async (params = {}) => {
  const response = await api.get('/history/', { params })
  return response.data
}

export const getScoreBreakdown = async (id) => {
  const response = await api.get(`/score/${id}`)
  return response.data
}

export const getDashboardStats = async () => {
  const response = await api.get('/history/stats/dashboard')
  return response.data
}

export const getScoreStats = async () => {
  const response = await api.get('/score/stats/overview')
  return response.data
}

export const getExplanation = async (id) => {
  const response = await api.get(`/explain/${id}`)
  return response.data
}

export const regenerateExplanation = async (id) => {
  const response = await api.post(`/explain/${id}/regenerate`)
  return response.data
}

export const getReport = async (id) => {
  const response = await api.get(`/report/${id}/json`)
  return response.data
}

export const deleteAnalysis = async (id) => {
  const response = await api.delete(`/history/${id}`)
  return response.data
}

export default api
