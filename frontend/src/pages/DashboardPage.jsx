import React, { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, XCircle, CheckCircle,
  TrendingUp, FileWarning, Clock, Zap, RefreshCw
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import { getDashboardStats, getHistory } from '../api/client'
import clsx from 'clsx'
import { formatDistanceToNow } from 'date-fns'

const RISK_COLORS = {
  SAFE: '#10b981',
  SUSPICIOUS: '#f59e0b',
  BLOCK: '#ef4444',
}

const PIE_COLORS = ['#10b981', '#f59e0b', '#ef4444']

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass-card p-3 text-sm">
        <p className="text-dark-300 mb-1">{label}</p>
        {payload.map(p => (
          <p key={p.name} style={{ color: p.color }} className="font-semibold">
            {p.name}: {p.value}
          </p>
        ))}
      </div>
    )
  }
  return null
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const load = async () => {
    try {
      const [s, h] = await Promise.all([
        getDashboardStats(),
        getHistory({ limit: 10 }),
      ])
      setStats(s)
      setHistory(h.results || [])
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => { load() }, [])

  const refresh = () => {
    setRefreshing(true)
    load()
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-dark-400">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  const totals = stats?.totals || {}
  const pieData = [
    { name: 'Safe', value: totals.safe || 0 },
    { name: 'Suspicious', value: totals.suspicious || 0 },
    { name: 'Blocked', value: totals.blocked || 0 },
  ].filter(d => d.value > 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">
            Threat <span className="gradient-text">Dashboard</span>
          </h1>
          <p className="text-dark-400 mt-1">Security intelligence overview</p>
        </div>
        <button
          onClick={refresh}
          id="refresh-dashboard"
          className="btn-secondary flex items-center gap-2"
          disabled={refreshing}
        >
          <RefreshCw className={clsx('w-4 h-4', refreshing && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Stat cards */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4"
      >
        <StatCard
          label="Total Analyzed"
          value={totals.total || 0}
          icon={Shield}
          color="blue"
          id="stat-total"
        />
        <StatCard
          label="Safe"
          value={totals.safe || 0}
          icon={CheckCircle}
          color="emerald"
          id="stat-safe"
        />
        <StatCard
          label="Suspicious"
          value={totals.suspicious || 0}
          icon={AlertTriangle}
          color="amber"
          id="stat-suspicious"
        />
        <StatCard
          label="Blocked"
          value={totals.blocked || 0}
          icon={XCircle}
          color="red"
          id="stat-blocked"
        />
      </motion.div>

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Distribution pie */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
          className="glass-card p-6"
        >
          <h3 className="section-header">
            <TrendingUp className="w-5 h-5 text-blue-400" />
            Risk Distribution
          </h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  formatter={(value) => (
                    <span className="text-dark-300 text-sm">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[200px] flex items-center justify-center text-dark-500 text-sm">
              No data yet. Analyze some APKs!
            </div>
          )}
        </motion.div>

        {/* Fraud types */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="glass-card p-6"
        >
          <h3 className="section-header">
            <FileWarning className="w-5 h-5 text-orange-400" />
            Top Fraud Types
          </h3>
          {(stats?.top_fraud_types || []).length > 0 ? (
            <div className="space-y-3">
              {stats.top_fraud_types.map(({ type, count }) => (
                <div key={type}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-dark-300 truncate">{type}</span>
                    <span className="text-dark-400 ml-2 flex-shrink-0">{count}</span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className="progress-fill bg-gradient-to-r from-orange-600 to-red-600"
                      style={{ width: `${Math.min((count / Math.max(...stats.top_fraud_types.map(f => f.count))) * 100, 100)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-40 flex items-center justify-center text-dark-500 text-sm">
              No fraud data yet
            </div>
          )}
        </motion.div>

        {/* Avg score gauge */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="glass-card p-6 flex flex-col items-center justify-center"
        >
          <h3 className="section-header w-full justify-center">
            <Zap className="w-5 h-5 text-yellow-400" />
            Avg Risk Score
          </h3>
          <RiskGauge score={stats?.avg_risk_score || 0} />
          <p className="text-dark-400 text-sm mt-4 text-center">
            Average across {totals.completed || 0} analyzed APKs
          </p>
        </motion.div>
      </div>

      {/* Recent threats table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="glass-card p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="section-header mb-0">
            <Clock className="w-5 h-5 text-blue-400" />
            Recent Analyses
          </h3>
          <button
            onClick={() => navigate('/history')}
            className="text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors"
          >
            View all →
          </button>
        </div>

        {history.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Package</th>
                  <th>Risk Score</th>
                  <th>Level</th>
                  <th>Fraud Types</th>
                  <th>Time</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.id} className="cursor-pointer" onClick={() => navigate(`/report/${item.id}`)}>
                    <td className="font-medium text-dark-100 max-w-[150px] truncate">{item.filename}</td>
                    <td className="font-mono text-xs text-dark-400 max-w-[150px] truncate">{item.package_name || '—'}</td>
                    <td>
                      <ScoreBar score={item.risk_score} />
                    </td>
                    <td>
                      <RiskBadge level={item.risk_level} />
                    </td>
                    <td className="text-xs text-dark-400 max-w-[150px]">
                      {(item.fraud_types || []).slice(0, 2).join(', ') || '—'}
                    </td>
                    <td className="text-dark-500 text-xs whitespace-nowrap">
                      {item.created_at ? formatDistanceToNow(new Date(item.created_at), { addSuffix: true }) : '—'}
                    </td>
                    <td>
                      <button
                        className="text-blue-400 hover:text-blue-300 text-sm"
                        onClick={() => navigate(`/report/${item.id}`)}
                      >
                        View →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-16 text-center">
            <Shield className="w-12 h-12 text-dark-600 mx-auto mb-4" />
            <p className="text-dark-400">No APKs analyzed yet.</p>
            <button
              onClick={() => navigate('/upload')}
              className="btn-primary mt-4"
            >
              Analyze your first APK
            </button>
          </div>
        )}
      </motion.div>
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color, id }) {
  const colors = {
    blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    emerald: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    amber: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    red: 'text-red-400 bg-red-500/10 border-red-500/20',
  }

  return (
    <div id={id} className="stat-card">
      <div className={clsx('w-10 h-10 rounded-xl border flex items-center justify-center', colors[color])}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="mt-2">
        <p className="text-3xl font-bold text-white">{value.toLocaleString()}</p>
        <p className="text-dark-400 text-sm mt-1">{label}</p>
      </div>
    </div>
  )
}

function RiskGauge({ score }) {
  const r = 70
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const color = score < 25 ? '#10b981' : score < 55 ? '#f59e0b' : '#ef4444'

  return (
    <div className="relative w-44 h-44">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 180 180">
        <circle cx="90" cy="90" r={r} fill="none" stroke="#1e293b" strokeWidth="12" />
        <circle
          cx="90" cy="90" r={r} fill="none"
          stroke={color} strokeWidth="12"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1.5s ease-out, stroke 0.5s' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold text-white">{score.toFixed(0)}</span>
        <span className="text-dark-400 text-sm">/ 100</span>
      </div>
    </div>
  )
}

function ScoreBar({ score }) {
  const color = score < 25 ? 'from-emerald-600 to-emerald-400' : score < 55 ? 'from-amber-600 to-amber-400' : 'from-red-600 to-red-400'
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 progress-bar">
        <div className={`progress-fill bg-gradient-to-r ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-dark-300 w-8">{score.toFixed(0)}</span>
    </div>
  )
}

function RiskBadge({ level }) {
  const cls = {
    SAFE: 'badge-safe',
    SUSPICIOUS: 'badge-suspicious',
    BLOCK: 'badge-block',
  }[level] || 'badge-safe'

  return <span className={cls}>{level}</span>
}
