import React, { useCallback, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDropzone } from 'react-dropzone'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Upload, FileText, Shield, Zap, AlertCircle, 
  CheckCircle, Loader2, X, Lock, Eye, Cpu
} from 'lucide-react'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { uploadAPK, analyzeAPK } from '../api/client'

const FEATURES = [
  { icon: Shield, label: 'Static Analysis', desc: 'Permissions, APIs, URLs' },
  { icon: Zap, label: 'Risk Scoring', desc: 'ML-powered 0-100 score' },
  { icon: Eye, label: 'Fraud Mapping', desc: 'OTP theft, phishing, spyware' },
  { icon: Cpu, label: 'AI Explanation', desc: 'GPT/Gemini insights' },
]

const STAGES = [
  'Uploading file...',
  'Extracting APK structure...',
  'Analyzing permissions & APIs...',
  'Computing risk score...',
  'Mapping fraud patterns...',
  'Finding similar threats...',
  'Generating AI explanation...',
  'Analysis complete!',
]

export default function UploadPage() {
  const navigate = useNavigate()
  const [file, setFile] = useState(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [analyzing, setAnalyzing] = useState(false)
  const [stage, setStage] = useState(0)
  const [error, setError] = useState(null)

  const simulateStages = async () => {
    for (let i = 1; i < STAGES.length - 1; i++) {
      await new Promise(r => setTimeout(r, 600 + Math.random() * 400))
      setStage(i)
    }
  }

  const onDrop = useCallback((acceptedFiles, rejectedFiles) => {
    if (rejectedFiles.length > 0) {
      toast.error('Only APK files are accepted')
      return
    }
    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0])
      setError(null)
    }
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'application/vnd.android.package-archive': ['.apk'], 'application/octet-stream': ['.apk', '.xapk'] },
    maxFiles: 1,
    maxSize: 100 * 1024 * 1024,
  })

  const handleAnalyze = async () => {
    if (!file) {
      toast.error('Please select an APK file first')
      return
    }

    setError(null)
    setAnalyzing(true)
    setStage(0)

    try {
      // Upload
      const uploadResult = await uploadAPK(file, setUploadProgress)
      setStage(1)

      // Start stage simulation concurrently with analysis
      simulateStages()

      // Run analysis
      const analysis = await analyzeAPK(uploadResult.file_hash, file.name)
      
      setStage(STAGES.length - 1)
      await new Promise(r => setTimeout(r, 500))

      toast.success(`Analysis complete! Risk level: ${analysis.risk_level}`)
      navigate(`/report/${analysis.id}`)

    } catch (err) {
      setError(err.message)
      toast.error(err.message)
    } finally {
      setAnalyzing(false)
    }
  }

  const clearFile = (e) => {
    e.stopPropagation()
    setFile(null)
    setUploadProgress(0)
    setStage(0)
    setError(null)
  }

  const fileSizeMB = file ? (file.size / 1024 / 1024).toFixed(2) : 0

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <h1 className="text-3xl font-bold text-white mb-2">
          APK <span className="gradient-text">Malware Analysis</span>
        </h1>
        <p className="text-dark-400 text-lg">
          Upload an Android APK for comprehensive AI-powered security analysis
        </p>
      </motion.div>

      {/* Feature cards */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"
      >
        {FEATURES.map(({ icon: Icon, label, desc }, i) => (
          <div key={label} className="glass-card p-4 text-center">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center mx-auto mb-3">
              <Icon className="w-5 h-5 text-blue-400" />
            </div>
            <p className="text-dark-100 font-semibold text-sm">{label}</p>
            <p className="text-dark-400 text-xs mt-1">{desc}</p>
          </div>
        ))}
      </motion.div>

      {/* Upload area */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card p-8 mb-6"
      >
        <AnimatePresence mode="wait">
          {!analyzing ? (
            <motion.div
              key="upload"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              {/* Dropzone */}
              <div
                {...getRootProps()}
                className={clsx(
                  'border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all duration-300',
                  isDragActive
                    ? 'border-blue-400 bg-blue-500/5 dropzone-active'
                    : file
                    ? 'border-emerald-500/50 bg-emerald-500/5'
                    : 'border-dark-600 hover:border-dark-500 hover:bg-dark-800/30'
                )}
              >
                <input {...getInputProps()} id="apk-file-input" />

                <AnimatePresence mode="wait">
                  {file ? (
                    <motion.div
                      key="file-selected"
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="flex flex-col items-center gap-4"
                    >
                      <div className="w-16 h-16 rounded-2xl bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center">
                        <CheckCircle className="w-8 h-8 text-emerald-400" />
                      </div>
                      <div>
                        <p className="text-white font-semibold text-lg">{file.name}</p>
                        <p className="text-dark-400 text-sm mt-1">{fileSizeMB} MB • APK File</p>
                      </div>
                      <button
                        onClick={clearFile}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-dark-700 hover:bg-dark-600 text-dark-300 text-sm transition-colors"
                      >
                        <X className="w-4 h-4" /> Remove file
                      </button>
                    </motion.div>
                  ) : (
                    <motion.div
                      key="empty"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="flex flex-col items-center gap-4"
                    >
                      <div className={clsx(
                        'w-20 h-20 rounded-2xl flex items-center justify-center transition-all duration-300',
                        isDragActive
                          ? 'bg-blue-500/20 border-2 border-blue-400/50 glow-blue'
                          : 'bg-dark-700/50 border border-dark-600'
                      )}>
                        <Upload className={clsx(
                          'w-10 h-10 transition-colors',
                          isDragActive ? 'text-blue-400' : 'text-dark-400'
                        )} />
                      </div>
                      <div>
                        <p className="text-dark-100 font-semibold text-xl">
                          {isDragActive ? 'Drop the APK here' : 'Drop APK file here'}
                        </p>
                        <p className="text-dark-400 mt-2">or click to browse • Max 100 MB</p>
                      </div>
                      <div className="flex items-center gap-3 text-dark-500 text-sm">
                        <Lock className="w-4 h-4" />
                        <span>Files are analyzed locally and never shared</span>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Error */}
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-4 p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start gap-3"
                >
                  <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                  <p className="text-red-300 text-sm">{error}</p>
                </motion.div>
              )}

              {/* Analyze button */}
              <div className="mt-6 flex justify-center">
                <button
                  id="analyze-btn"
                  onClick={handleAnalyze}
                  disabled={!file}
                  className={clsx(
                    'px-10 py-4 rounded-2xl font-bold text-lg transition-all duration-300 flex items-center gap-3',
                    file
                      ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white hover:from-blue-500 hover:to-cyan-500 hover:shadow-xl hover:shadow-blue-500/30 hover:scale-105 active:scale-100'
                      : 'bg-dark-700 text-dark-500 cursor-not-allowed'
                  )}
                >
                  <Zap className="w-6 h-6" />
                  Analyze APK
                </button>
              </div>
            </motion.div>
          ) : (
            /* Analysis in progress */
            <motion.div
              key="analyzing"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-center py-8"
            >
              {/* Animated scanner */}
              <div className="relative w-32 h-32 mx-auto mb-8">
                <div className="absolute inset-0 rounded-full border-2 border-blue-500/20 animate-ping" />
                <div className="absolute inset-2 rounded-full border-2 border-blue-500/30 animate-ping" style={{ animationDelay: '0.3s' }} />
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-600 to-cyan-600 flex items-center justify-center glow-blue">
                    <Shield className="w-10 h-10 text-white animate-pulse" />
                  </div>
                </div>
              </div>

              <h2 className="text-2xl font-bold text-white mb-2">Analyzing APK</h2>
              <p className="text-blue-400 font-medium mb-2">{file?.name}</p>
              
              {/* Stage indicator */}
              <motion.p
                key={stage}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="text-dark-400 text-sm mb-6"
              >
                {STAGES[Math.min(stage, STAGES.length - 1)]}
              </motion.p>

              {/* Progress stages */}
              <div className="max-w-md mx-auto space-y-2">
                {STAGES.slice(0, -1).map((s, i) => (
                  <div key={s} className="flex items-center gap-3">
                    <div className={clsx(
                      'w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 transition-all duration-300',
                      i < stage
                        ? 'bg-emerald-500'
                        : i === stage
                        ? 'bg-blue-500 animate-pulse'
                        : 'bg-dark-700'
                    )}>
                      {i < stage ? (
                        <CheckCircle className="w-3 h-3 text-white" />
                      ) : i === stage ? (
                        <Loader2 className="w-3 h-3 text-white animate-spin" />
                      ) : null}
                    </div>
                    <span className={clsx(
                      'text-sm transition-colors',
                      i < stage ? 'text-emerald-400' : i === stage ? 'text-blue-400' : 'text-dark-600'
                    )}>
                      {s}
                    </span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Info section */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
        className="glass-card p-6"
      >
        <h3 className="section-header">
          <FileText className="w-5 h-5 text-blue-400" />
          What we analyze
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <InfoBlock
            title="Static Analysis"
            items={['Android Manifest permissions', 'Dangerous permission combinations', 'SDK version targeting', 'Package structure']}
          />
          <InfoBlock
            title="Code Analysis"
            items={['Suspicious API calls', 'Embedded URLs & endpoints', 'Obfuscation detection', 'Dynamic code loading']}
          />
          <InfoBlock
            title="Fraud Intelligence"
            items={['OTP theft patterns', 'Overlay phishing attacks', 'Spyware behaviors', 'Ransomware indicators']}
          />
        </div>
      </motion.div>
    </div>
  )
}

function InfoBlock({ title, items }) {
  return (
    <div>
      <p className="text-dark-300 font-semibold mb-2">{title}</p>
      <ul className="space-y-1">
        {items.map(item => (
          <li key={item} className="flex items-center gap-2 text-dark-400">
            <div className="w-1 h-1 rounded-full bg-blue-400 flex-shrink-0" />
            {item}
          </li>
        ))}
      </ul>
    </div>
  )
}
