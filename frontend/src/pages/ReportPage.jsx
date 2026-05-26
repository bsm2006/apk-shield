import React, { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, AlertTriangle, XCircle, CheckCircle, ChevronDown,
  ChevronUp, Download, ArrowLeft, Lock, Globe, Code,
  Cpu, AlertCircle, FileText, Link2, Activity, Copy,
  RefreshCw, Eye, Layers, Bug
} from 'lucide-react'
import { getAnalysis, getReport, regenerateExplanation } from '../api/client'
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, Tooltip } from 'recharts'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { formatDistanceToNow } from 'date-fns'

const SEVERITY_CLASSES = {
  CRITICAL: 'fraud-badge-critical',
  HIGH: 'fraud-badge-high',
  MEDIUM: 'fraud-badge-medium',
  LOW: 'fraud-badge-low',
}

export default function ReportPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(true)
  const [regenLoading, setRegenLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('overview')
  const [expandedSections, setExpandedSections] = useState({
    permissions: true,
    apiCalls: false,
    urls: false,
    frauds: true,
    similar: true,
    explanation: true,
  })

  useEffect(() => {
    const load = async () => {
      try {
        const data = await getAnalysis(Number(id))
        setAnalysis(data)
      } catch (err) {
        toast.error('Failed to load analysis: ' + err.message)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

  const toggleSection = (key) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const handleRegenExplanation = async () => {
    setRegenLoading(true)
    try {
      const result = await regenerateExplanation(Number(id))
      setAnalysis(prev => ({
        ...prev,
        ai_explanation: result.explanation,
        ai_recommendations: result.recommendations,
      }))
      toast.success('AI explanation regenerated!')
    } catch (err) {
      toast.error('Regeneration failed: ' + err.message)
    } finally {
      setRegenLoading(false)
    }
  }

  const handleDownloadReport = async () => {
    try {
      const report = await getReport(Number(id))
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `apk-report-${id}-${analysis?.filename?.replace('.apk', '')}.json`
      a.click()
      URL.revokeObjectURL(url)
      toast.success('Report downloaded!')
    } catch (err) {
      toast.error('Download failed')
    }
  }

  const copyHash = () => {
    navigator.clipboard.writeText(analysis?.file_hash || '')
    toast.success('Hash copied!')
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-dark-400">Loading analysis report...</p>
        </div>
      </div>
    )
  }

  if (!analysis) {
    return (
      <div className="text-center py-20">
        <AlertCircle className="w-16 h-16 text-red-400 mx-auto mb-4" />
        <h2 className="text-2xl font-bold text-white mb-2">Analysis Not Found</h2>
        <p className="text-dark-400 mb-6">The requested analysis could not be found.</p>
        <button onClick={() => navigate('/upload')} className="btn-primary">Go to Upload</button>
      </div>
    )
  }

  const riskColor = {
    SAFE: 'emerald',
    SUSPICIOUS: 'amber',
    BLOCK: 'red',
  }[analysis.risk_level] || 'blue'

  const riskIcon = { SAFE: CheckCircle, SUSPICIOUS: AlertTriangle, BLOCK: XCircle }[analysis.risk_level] || Shield
  const RiskIcon = riskIcon

  const radarData = [
    { subject: 'Permissions', score: analysis.permission_score || 0, fullMark: 100 },
    { subject: 'APIs', score: analysis.api_score || 0, fullMark: 100 },
    { subject: 'URLs', score: analysis.url_score || 0, fullMark: 100 },
    { subject: 'Obfuscation', score: analysis.obfuscation_score || 0, fullMark: 100 },
    { subject: 'Behavior', score: analysis.behavior_score || 0, fullMark: 100 },
  ]

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Eye },
    { id: 'permissions', label: 'Permissions', icon: Lock },
    { id: 'code', label: 'Code Analysis', icon: Code },
    { id: 'fraud', label: 'Fraud Map', icon: Bug },
    { id: 'ai', label: 'AI Report', icon: Cpu },
    { id: 'similar', label: 'Similar Threats', icon: Layers },
  ]

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Back + actions */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate(-1)}
          className="flex items-center gap-2 text-dark-400 hover:text-dark-100 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back
        </button>
        <div className="flex gap-3">
          <button
            id="download-report"
            onClick={handleDownloadReport}
            className="btn-secondary flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Download JSON
          </button>
        </div>
      </div>

      {/* Hero verdict card */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={clsx(
          'glass-card p-8 border-2',
          analysis.risk_level === 'BLOCK'
            ? 'border-red-500/40 glow-red'
            : analysis.risk_level === 'SUSPICIOUS'
            ? 'border-amber-500/40 glow-yellow'
            : 'border-emerald-500/40 glow-green'
        )}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center gap-6">
          {/* Score gauge */}
          <div className="flex-shrink-0">
            <ScoreGauge score={analysis.risk_score} level={analysis.risk_level} />
          </div>

          {/* Info */}
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <RiskIcon className={clsx(
                'w-6 h-6',
                riskColor === 'emerald' ? 'text-emerald-400' :
                riskColor === 'amber' ? 'text-amber-400' : 'text-red-400'
              )} />
              <span className={clsx(
                'text-lg font-bold',
                riskColor === 'emerald' ? 'text-emerald-400' :
                riskColor === 'amber' ? 'text-amber-400' : 'text-red-400'
              )}>
                VERDICT: {analysis.risk_level}
              </span>
            </div>
            
            <h2 className="text-2xl font-bold text-white mb-1">
              {analysis.app_name || analysis.filename}
            </h2>
            <p className="text-dark-400 font-mono text-sm mb-4">
              {analysis.package_name || '—'}
            </p>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <InfoPill label="Version" value={analysis.version_name || '—'} />
              <InfoPill label="Min SDK" value={analysis.sdk_min || '—'} />
              <InfoPill label="Fraud Types" value={(analysis.fraud_types || []).length} />
              <InfoPill label="Dangerous Perms" value={(analysis.dangerous_permissions || []).length} />
            </div>
          </div>

          {/* Hash */}
          <div className="flex-shrink-0 text-right">
            <p className="text-dark-500 text-xs mb-1">SHA256</p>
            <div className="flex items-center gap-2">
              <code className="text-xs font-mono text-dark-300 bg-dark-800 px-2 py-1 rounded">
                {(analysis.file_hash || '').slice(0, 16)}...
              </code>
              <button onClick={copyHash} className="text-dark-400 hover:text-blue-400 transition-colors">
                <Copy className="w-4 h-4" />
              </button>
            </div>
            <p className="text-dark-600 text-xs mt-2">
              {analysis.created_at
                ? formatDistanceToNow(new Date(analysis.created_at), { addSuffix: true })
                : '—'}
            </p>
          </div>
        </div>
      </motion.div>

      {/* Tabs */}
      <div className="flex gap-2 overflow-x-auto pb-2">
        {tabs.map(({ id: tabId, label, icon: Icon }) => (
          <button
            key={tabId}
            id={`tab-${tabId}`}
            onClick={() => setActiveTab(tabId)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium whitespace-nowrap transition-all duration-200',
              activeTab === tabId
                ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                : 'text-dark-400 hover:text-dark-200 hover:bg-dark-800'
            )}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <AnimatePresence mode="wait">
        {activeTab === 'overview' && (
          <motion.div
            key="overview"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="grid grid-cols-1 md:grid-cols-2 gap-6"
          >
            {/* Radar chart */}
            <div className="glass-card p-6">
              <h3 className="section-header">
                <Activity className="w-5 h-5 text-blue-400" />
                Risk Profile
              </h3>
              <ResponsiveContainer width="100%" height={280}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke="#334155" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                  <Radar
                    name="Risk Score"
                    dataKey="score"
                    stroke="#3b82f6"
                    fill="#3b82f6"
                    fillOpacity={0.2}
                  />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload?.length) {
                        return (
                          <div className="glass-card p-2 text-sm">
                            <p className="text-dark-300">{payload[0]?.payload?.subject}</p>
                            <p className="text-blue-400 font-bold">{payload[0]?.value?.toFixed(1)}</p>
                          </div>
                        )
                      }
                      return null
                    }}
                  />
                </RadarChart>
              </ResponsiveContainer>
            </div>

            {/* Score breakdown */}
            <div className="glass-card p-6">
              <h3 className="section-header">
                <Shield className="w-5 h-5 text-blue-400" />
                Score Breakdown
              </h3>
              <div className="space-y-4">
                {[
                  { label: 'Permissions', score: analysis.permission_score, weight: '30%' },
                  { label: 'API Calls', score: analysis.api_score, weight: '25%' },
                  { label: 'Network / URLs', score: analysis.url_score, weight: '20%' },
                  { label: 'Obfuscation', score: analysis.obfuscation_score, weight: '15%' },
                  { label: 'Behavior', score: analysis.behavior_score, weight: '10%' },
                ].map(({ label, score, weight }) => (
                  <ScoreRow key={label} label={label} score={score || 0} weight={weight} />
                ))}
                <div className="border-t border-dark-700 pt-3">
                  <ScoreRow
                    label="Overall Risk Score"
                    score={analysis.risk_score || 0}
                    weight="total"
                    bold
                  />
                </div>
              </div>
            </div>

            {/* App info */}
            <div className="glass-card p-6">
              <h3 className="section-header">
                <FileText className="w-5 h-5 text-blue-400" />
                Application Details
              </h3>
              <div className="space-y-2">
                {[
                  { label: 'App Name', value: analysis.app_name },
                  { label: 'Package', value: analysis.package_name },
                  { label: 'Version Name', value: analysis.version_name },
                  { label: 'Version Code', value: analysis.version_code },
                  { label: 'Min SDK', value: analysis.sdk_min },
                  { label: 'Target SDK', value: analysis.sdk_target },
                  { label: 'File Size', value: analysis.file_size ? `${(analysis.file_size / 1024).toFixed(0)} KB` : '—' },
                ].map(({ label, value }) => (
                  <div key={label} className="flex justify-between py-1 border-b border-dark-800">
                    <span className="text-dark-400 text-sm">{label}</span>
                    <span className="text-dark-200 text-sm font-mono">{value || '—'}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Obfuscation */}
            <div className="glass-card p-6">
              <h3 className="section-header">
                <Eye className="w-5 h-5 text-purple-400" />
                Obfuscation Analysis
              </h3>
              <div className={clsx(
                'p-4 rounded-xl mb-4',
                analysis.obfuscation_detected
                  ? 'bg-red-500/10 border border-red-500/30'
                  : 'bg-emerald-500/10 border border-emerald-500/30'
              )}>
                <div className="flex items-center gap-3">
                  {analysis.obfuscation_detected
                    ? <AlertTriangle className="w-6 h-6 text-red-400" />
                    : <CheckCircle className="w-6 h-6 text-emerald-400" />}
                  <div>
                    <p className={clsx(
                      'font-semibold',
                      analysis.obfuscation_detected ? 'text-red-300' : 'text-emerald-300'
                    )}>
                      {analysis.obfuscation_detected ? 'Obfuscation Detected' : 'No Obfuscation Detected'}
                    </p>
                    <p className="text-dark-400 text-sm">
                      {analysis.obfuscation_detected
                        ? 'Code has been deliberately obfuscated to evade detection'
                        : 'Code appears readable and unobfuscated'}
                    </p>
                  </div>
                </div>
              </div>
              {(analysis.obfuscation_indicators || []).length > 0 && (
                <ul className="space-y-2">
                  {analysis.obfuscation_indicators.map((ind, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm">
                      <AlertCircle className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />
                      <span className="text-dark-300">{ind}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === 'permissions' && (
          <motion.div
            key="permissions"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="space-y-6"
          >
            {/* Dangerous permissions */}
            <div className="glass-card p-6">
              <h3 className="section-header">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                Dangerous Permissions ({(analysis.dangerous_permissions || []).length})
              </h3>
              {(analysis.dangerous_permissions || []).length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {analysis.dangerous_permissions.map(perm => (
                    <PermissionItem key={perm} perm={perm} dangerous />
                  ))}
                </div>
              ) : (
                <p className="text-dark-500 text-sm">No dangerous permissions found</p>
              )}
            </div>

            {/* All permissions */}
            <div className="glass-card p-6">
              <h3 className="section-header">
                <Lock className="w-5 h-5 text-blue-400" />
                All Permissions ({(analysis.permissions || []).length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {(analysis.permissions || []).map(perm => (
                  <PermissionItem
                    key={perm}
                    perm={perm}
                    dangerous={(analysis.dangerous_permissions || []).includes(perm)}
                  />
                ))}
              </div>
            </div>

            {/* Components */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <ComponentList title="Services" icon={Activity} items={analysis.services || []} color="purple" />
              <ComponentList title="Receivers" icon={Activity} items={analysis.receivers || []} color="orange" />
              <ComponentList title="Activities" icon={Activity} items={analysis.activities || []} color="blue" />
            </div>
          </motion.div>
        )}

        {activeTab === 'code' && (
          <motion.div
            key="code"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="space-y-6"
          >
            {/* API Calls */}
            <div className="glass-card p-6">
              <h3 className="section-header">
                <Code className="w-5 h-5 text-cyan-400" />
                Suspicious API Calls ({(analysis.api_calls || []).length})
              </h3>
              {(analysis.api_calls || []).length > 0 ? (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {analysis.api_calls.map((call, i) => (
                    <div key={i} className="permission-item">
                      <Code className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                      <code className="text-xs text-cyan-300 truncate">{call}</code>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-dark-500 text-sm">No suspicious API calls detected</p>
              )}
            </div>

            {/* URLs */}
            <div className="glass-card p-6">
              <h3 className="section-header">
                <Globe className="w-5 h-5 text-orange-400" />
                Embedded URLs ({(analysis.urls || []).length})
              </h3>
              {(analysis.urls || []).length > 0 ? (
                <div className="space-y-2">
                  {analysis.urls.map((url, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 rounded-xl bg-dark-800/50 border border-dark-700/50 hover:border-orange-500/30 transition-colors group">
                      <Globe className="w-4 h-4 text-orange-400 flex-shrink-0" />
                      <code className="text-xs text-orange-300 break-all flex-1">{url}</code>
                      <button
                        onClick={() => { navigator.clipboard.writeText(url); toast.success('URL copied!') }}
                        className="opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <Copy className="w-3 h-3 text-dark-400" />
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-dark-500 text-sm">No suspicious URLs found</p>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === 'fraud' && (
          <motion.div
            key="fraud"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="space-y-4"
          >
            {(analysis.fraud_indicators || []).length > 0 ? (
              analysis.fraud_indicators.map((fraud, i) => (
                <FraudCard key={i} fraud={fraud} />
              ))
            ) : (
              <div className="glass-card p-12 text-center">
                <CheckCircle className="w-16 h-16 text-emerald-400 mx-auto mb-4" />
                <h3 className="text-xl font-bold text-white mb-2">No Fraud Patterns Detected</h3>
                <p className="text-dark-400">This APK does not exhibit known fraud behaviors.</p>
              </div>
            )}
          </motion.div>
        )}

        {activeTab === 'ai' && (
          <motion.div
            key="ai"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="space-y-6"
          >
            {/* AI Explanation */}
            <div className="glass-card p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="section-header mb-0">
                  <Cpu className="w-5 h-5 text-purple-400" />
                  AI Security Analysis
                </h3>
                <button
                  id="regen-explanation"
                  onClick={handleRegenExplanation}
                  disabled={regenLoading}
                  className="btn-secondary flex items-center gap-2 text-sm"
                >
                  <RefreshCw className={clsx('w-4 h-4', regenLoading && 'animate-spin')} />
                  Regenerate
                </button>
              </div>
              <div className="prose prose-invert max-w-none">
                <div className="bg-dark-800/50 rounded-xl p-6 border border-dark-700/50">
                  <pre className="whitespace-pre-wrap font-sans text-dark-200 text-sm leading-relaxed">
                    {analysis.ai_explanation || 'AI explanation not available. Click "Regenerate" to generate one.'}
                  </pre>
                </div>
              </div>
            </div>

            {/* Recommendations */}
            {(analysis.ai_recommendations || []).length > 0 && (
              <div className="glass-card p-6">
                <h3 className="section-header">
                  <AlertCircle className="w-5 h-5 text-yellow-400" />
                  Security Recommendations
                </h3>
                <div className="space-y-3">
                  {analysis.ai_recommendations.map((rec, i) => (
                    <div key={i} className="flex items-start gap-3 p-4 rounded-xl bg-dark-800/50 border border-dark-700/50">
                      <div className="w-6 h-6 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0 text-xs font-bold text-blue-400">
                        {i + 1}
                      </div>
                      <p className="text-dark-200 text-sm leading-relaxed">{rec}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}

        {activeTab === 'similar' && (
          <motion.div
            key="similar"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
          >
            <div className="glass-card p-6">
              <h3 className="section-header">
                <Layers className="w-5 h-5 text-blue-400" />
                Similar Threat APKs
              </h3>
              {(analysis.similar_apks || []).length > 0 ? (
                <div className="space-y-3">
                  {analysis.similar_apks.map((similar, i) => (
                    <div
                      key={i}
                      onClick={() => navigate(`/report/${similar.id}`)}
                      className="flex items-center justify-between p-4 rounded-xl bg-dark-800/50 border border-dark-700/50 hover:border-blue-500/30 cursor-pointer transition-all group"
                    >
                      <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-xl bg-dark-700 flex items-center justify-center">
                          <Shield className="w-5 h-5 text-dark-400" />
                        </div>
                        <div>
                          <p className="text-dark-100 font-medium">{similar.filename}</p>
                          <p className="text-dark-500 text-xs font-mono">{similar.package_name || '—'}</p>
                          <div className="flex gap-1 mt-1">
                            {(similar.fraud_types || []).slice(0, 2).map(ft => (
                              <span key={ft} className="px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 text-xs">{ft}</span>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="flex items-center justify-end gap-2 mb-1">
                          <span className="text-dark-400 text-xs">Similarity</span>
                          <span className="text-blue-400 font-bold text-sm">
                            {(similar.similarity_score * 100).toFixed(0)}%
                          </span>
                        </div>
                        <RiskBadge level={similar.risk_level} />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-12 text-center">
                  <Layers className="w-12 h-12 text-dark-600 mx-auto mb-4" />
                  <p className="text-dark-400">No similar APKs found in database yet.</p>
                  <p className="text-dark-500 text-sm mt-1">Analyze more APKs to build similarity database.</p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function ScoreGauge({ score, level }) {
  const r = 56
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const color = level === 'BLOCK' ? '#ef4444' : level === 'SUSPICIOUS' ? '#f59e0b' : '#10b981'

  return (
    <div className="relative w-36 h-36">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={r} fill="none" stroke="#1e293b" strokeWidth="10" />
        <circle
          cx="80" cy="80" r={r} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1.5s ease-out' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{(score || 0).toFixed(0)}</span>
        <span className="text-dark-400 text-xs">/ 100</span>
      </div>
    </div>
  )
}

function InfoPill({ label, value }) {
  return (
    <div className="bg-dark-800/50 rounded-xl px-4 py-3 text-center border border-dark-700/50">
      <p className="text-xl font-bold text-white">{value}</p>
      <p className="text-dark-500 text-xs">{label}</p>
    </div>
  )
}

function ScoreRow({ label, score, weight, bold }) {
  const color = score < 25 ? 'from-emerald-600 to-emerald-400' : score < 55 ? 'from-amber-600 to-amber-400' : 'from-red-600 to-red-400'
  return (
    <div className="flex items-center gap-3">
      <span className={clsx('text-sm flex-shrink-0 w-32', bold ? 'text-white font-semibold' : 'text-dark-400')}>{label}</span>
      <div className="flex-1 progress-bar h-1.5">
        <div className={`progress-fill bg-gradient-to-r ${color}`} style={{ width: `${Math.min(score, 100)}%` }} />
      </div>
      <span className={clsx('text-sm font-mono w-8 text-right', bold ? 'text-white font-bold' : 'text-dark-300')}>
        {(score || 0).toFixed(0)}
      </span>
      {weight !== 'total' && <span className="text-dark-600 text-xs w-10 text-right">{weight}</span>}
    </div>
  )
}

function PermissionItem({ perm, dangerous }) {
  const short = perm.replace('android.permission.', '')
  return (
    <div className={clsx(
      'flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono border transition-colors',
      dangerous
        ? 'bg-red-500/10 border-red-500/30 text-red-300'
        : 'bg-dark-800/50 border-dark-700/50 text-dark-300'
    )}>
      {dangerous
        ? <AlertTriangle className="w-3 h-3 text-red-400 flex-shrink-0" />
        : <Lock className="w-3 h-3 text-dark-500 flex-shrink-0" />}
      <span className="truncate" title={perm}>{short}</span>
    </div>
  )
}

function ComponentList({ title, icon: Icon, items, color }) {
  const colors = {
    purple: 'text-purple-400',
    orange: 'text-orange-400',
    blue: 'text-blue-400',
  }
  return (
    <div className="glass-card p-5">
      <h3 className={clsx('section-header', colors[color])}>
        <Icon className="w-4 h-4" />
        {title} ({items.length})
      </h3>
      <div className="space-y-1 max-h-48 overflow-y-auto">
        {items.map((item, i) => (
          <p key={i} className="text-xs font-mono text-dark-400 truncate py-1 border-b border-dark-800" title={item}>
            {item}
          </p>
        ))}
        {items.length === 0 && <p className="text-dark-600 text-xs">None found</p>}
      </div>
    </div>
  )
}

function FraudCard({ fraud }) {
  const [expanded, setExpanded] = useState(false)
  const cls = SEVERITY_CLASSES[fraud.severity] || 'fraud-badge-medium'

  const bgColors = {
    CRITICAL: 'border-red-500/40 bg-red-500/5',
    HIGH: 'border-orange-500/40 bg-orange-500/5',
    MEDIUM: 'border-yellow-500/40 bg-yellow-500/5',
    LOW: 'border-blue-500/40 bg-blue-500/5',
  }

  return (
    <div className={clsx('glass-card border-2 overflow-hidden', bgColors[fraud.severity] || bgColors.MEDIUM)}>
      <div
        className="flex items-center justify-between p-5 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-4">
          <div className="text-2xl">{fraud.type.includes('OTP') ? '📱' : fraud.type.includes('PHISH') ? '🎣' : fraud.type.includes('SPY') ? '🕵️' : fraud.type.includes('BANK') ? '🏦' : fraud.type.includes('RANSOM') ? '🔐' : '⚠️'}</div>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h3 className="text-white font-bold">{fraud.type.replace(/_/g, ' ')}</h3>
              <span className={cls}>{fraud.severity}</span>
            </div>
            <p className="text-dark-400 text-sm">{fraud.description}</p>
          </div>
        </div>
        <button className="text-dark-400 hover:text-dark-200">
          {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </button>
      </div>
      
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0 }}
            animate={{ height: 'auto' }}
            exit={{ height: 0 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 border-t border-dark-700/30 pt-4">
              <p className="text-dark-400 text-xs font-semibold uppercase tracking-wider mb-3">Evidence</p>
              <div className="space-y-2">
                {(fraud.evidence || []).map((ev, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm">
                    <AlertCircle className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />
                    <code className="text-dark-300 text-xs">{ev}</code>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function RiskBadge({ level }) {
  const cls = { SAFE: 'badge-safe', SUSPICIOUS: 'badge-suspicious', BLOCK: 'badge-block' }[level] || 'badge-safe'
  return <span className={cls}>{level}</span>
}
