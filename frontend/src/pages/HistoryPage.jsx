import React, { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  History, Search, Filter, Trash2, Eye, Shield,
  AlertTriangle, XCircle, CheckCircle, ChevronLeft, ChevronRight
} from 'lucide-react'
import { getHistory, deleteAnalysis } from '../api/client'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { formatDistanceToNow } from 'date-fns'

const RISK_LEVELS = ['', 'SAFE', 'SUSPICIOUS', 'BLOCK']

export default function HistoryPage() {
  const navigate = useNavigate()
  const [data, setData] = useState({ results: [], total: 0, page: 1, pages: 1 })
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [page, setPage] = useState(1)
  const [deletingId, setDeletingId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const result = await getHistory({
        page,
        limit: 20,
        ...(search && { search }),
        ...(riskFilter && { risk_level: riskFilter }),
      })
      setData(result)
    } catch (err) {
      toast.error('Failed to load history')
    } finally {
      setLoading(false)
    }
  }, [page, search, riskFilter])

  useEffect(() => { load() }, [load])

  const handleSearch = (e) => {
    setSearch(e.target.value)
    setPage(1)
  }

  const handleDelete = async (id, e) => {
    e.stopPropagation()
    if (!confirm('Delete this analysis?')) return
    setDeletingId(id)
    try {
      await deleteAnalysis(id)
      toast.success('Analysis deleted')
      load()
    } catch (err) {
      toast.error('Delete failed')
    } finally {
      setDeletingId(null)
    }
  }

  const RiskIcon = ({ level }) => {
    const props = { className: 'w-4 h-4' }
    if (level === 'SAFE') return <CheckCircle {...props} className="w-4 h-4 text-emerald-400" />
    if (level === 'SUSPICIOUS') return <AlertTriangle {...props} className="w-4 h-4 text-amber-400" />
    if (level === 'BLOCK') return <XCircle {...props} className="w-4 h-4 text-red-400" />
    return <Shield {...props} className="w-4 h-4 text-dark-400" />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">
          Analysis <span className="gradient-text">History</span>
        </h1>
        <p className="text-dark-400 mt-1">Browse all past APK security analyses</p>
      </div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card p-4 flex flex-col md:flex-row gap-4"
      >
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
          <input
            id="history-search"
            className="input-cyber w-full pl-10"
            placeholder="Search by filename, package, or app name..."
            value={search}
            onChange={handleSearch}
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-dark-500" />
          <select
            id="risk-filter"
            className="input-cyber"
            value={riskFilter}
            onChange={e => { setRiskFilter(e.target.value); setPage(1) }}
          >
            <option value="">All Risk Levels</option>
            <option value="SAFE">Safe</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="BLOCK">Block</option>
          </select>
        </div>
      </motion.div>

      {/* Count */}
      <div className="flex items-center justify-between">
        <p className="text-dark-400 text-sm">
          {data.total} analyses found
          {search && ` for "${search}"`}
        </p>
        <p className="text-dark-500 text-sm">
          Page {data.page} of {data.pages}
        </p>
      </div>

      {/* Table */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="glass-card overflow-hidden"
      >
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : data.results.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>App / File</th>
                  <th>Package</th>
                  <th>Risk Score</th>
                  <th>Level</th>
                  <th>Fraud Types</th>
                  <th>Analyzed</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((item, i) => (
                  <motion.tr
                    key={item.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.03 }}
                    className="cursor-pointer group"
                    onClick={() => navigate(`/report/${item.id}`)}
                  >
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-dark-700 border border-dark-600 flex items-center justify-center flex-shrink-0">
                          <RiskIcon level={item.risk_level} />
                        </div>
                        <div>
                          <p className="text-dark-100 font-medium text-sm max-w-[150px] truncate">
                            {item.app_name || item.filename}
                          </p>
                          <p className="text-dark-500 text-xs truncate max-w-[150px]">{item.filename}</p>
                        </div>
                      </div>
                    </td>
                    <td>
                      <code className="text-xs text-dark-400 max-w-[140px] truncate block">
                        {item.package_name || '—'}
                      </code>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-16 progress-bar">
                          <div
                            className={clsx(
                              'progress-fill',
                              item.risk_score < 25 ? 'bg-emerald-500' : item.risk_score < 55 ? 'bg-amber-500' : 'bg-red-500'
                            )}
                            style={{ width: `${item.risk_score}%` }}
                          />
                        </div>
                        <span className="text-sm text-dark-300 font-mono">{item.risk_score?.toFixed(0)}</span>
                      </div>
                    </td>
                    <td>
                      <RiskBadge level={item.risk_level} />
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {(item.fraud_types || []).slice(0, 2).map(ft => (
                          <span key={ft} className="px-1.5 py-0.5 bg-orange-500/15 text-orange-400 text-xs rounded">
                            {ft.split(' ')[0]}
                          </span>
                        ))}
                        {(item.fraud_types || []).length > 2 && (
                          <span className="text-dark-500 text-xs">+{item.fraud_types.length - 2}</span>
                        )}
                        {(item.fraud_types || []).length === 0 && (
                          <span className="text-dark-600 text-xs">None</span>
                        )}
                      </div>
                    </td>
                    <td className="text-dark-500 text-xs whitespace-nowrap">
                      {item.created_at
                        ? formatDistanceToNow(new Date(item.created_at), { addSuffix: true })
                        : '—'}
                    </td>
                    <td>
                      <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          id={`view-${item.id}`}
                          onClick={(e) => { e.stopPropagation(); navigate(`/report/${item.id}`) }}
                          className="p-1.5 rounded-lg text-blue-400 hover:bg-blue-500/10 transition-colors"
                          title="View report"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          id={`delete-${item.id}`}
                          onClick={(e) => handleDelete(item.id, e)}
                          disabled={deletingId === item.id}
                          className="p-1.5 rounded-lg text-red-400 hover:bg-red-500/10 transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-20 text-center">
            <History className="w-16 h-16 text-dark-600 mx-auto mb-4" />
            <h3 className="text-xl font-bold text-dark-300 mb-2">No analyses found</h3>
            <p className="text-dark-500">
              {search || riskFilter ? 'Try adjusting your filters' : 'Upload and analyze an APK to get started'}
            </p>
          </div>
        )}
      </motion.div>

      {/* Pagination */}
      {data.pages > 1 && (
        <div className="flex items-center justify-center gap-4">
          <button
            id="prev-page"
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="btn-secondary flex items-center gap-2 disabled:opacity-40"
          >
            <ChevronLeft className="w-4 h-4" /> Prev
          </button>
          <span className="text-dark-400 text-sm">{page} / {data.pages}</span>
          <button
            id="next-page"
            onClick={() => setPage(p => Math.min(data.pages, p + 1))}
            disabled={page === data.pages}
            className="btn-secondary flex items-center gap-2 disabled:opacity-40"
          >
            Next <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      )}
    </div>
  )
}

function RiskBadge({ level }) {
  const cls = { SAFE: 'badge-safe', SUSPICIOUS: 'badge-suspicious', BLOCK: 'badge-block' }[level] || 'badge-safe'
  return <span className={cls}>{level}</span>
}
