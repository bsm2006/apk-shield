import React from 'react'
import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { 
  Shield, Upload, LayoutDashboard, History, 
  FileText, Zap, AlertTriangle, Activity
} from 'lucide-react'
import clsx from 'clsx'

const navItems = [
  { to: '/upload', icon: Upload, label: 'Analyze APK', id: 'nav-upload' },
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard', id: 'nav-dashboard' },
  { to: '/history', icon: History, label: 'History', id: 'nav-history' },
]

export default function Layout() {
  const location = useLocation()

  return (
    <div className="min-h-screen animated-bg flex">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 bg-dark-900/80 backdrop-blur-lg border-r border-dark-700/50 flex flex-col">
        {/* Logo */}
        <div className="p-6 border-b border-dark-700/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center glow-blue">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="font-bold text-white text-lg leading-tight">APK Shield</h1>
              <p className="text-dark-400 text-xs">AI Malware Analysis</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1">
          <p className="text-dark-500 text-xs font-semibold uppercase tracking-wider px-4 py-2">
            Main
          </p>
          {navItems.map(({ to, icon: Icon, label, id }) => (
            <NavLink
              key={to}
              to={to}
              id={id}
              className={({ isActive }) =>
                clsx(
                  'sidebar-item',
                  isActive && 'active'
                )
              }
            >
              <Icon className="w-5 h-5 flex-shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Status indicator */}
        <div className="p-4 border-t border-dark-700/50">
          <div className="glass-card p-3">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-semibold text-dark-300">System Status</span>
            </div>
            <div className="space-y-1">
              <StatusRow label="Analysis Engine" status="online" />
              <StatusRow label="AI Layer" status="online" />
              <StatusRow label="Database" status="online" />
            </div>
          </div>
        </div>

        {/* Version */}
        <div className="px-4 pb-4">
          <p className="text-dark-600 text-xs text-center font-mono">v1.0.0 • Production</p>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto cyber-grid">
        <div className="min-h-full p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

function StatusRow({ label, status }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-dark-400">{label}</span>
      <div className="flex items-center gap-1">
        <div className={clsx(
          'w-1.5 h-1.5 rounded-full',
          status === 'online' ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'
        )} />
        <span className={clsx(
          'text-xs font-medium',
          status === 'online' ? 'text-emerald-400' : 'text-red-400'
        )}>
          {status}
        </span>
      </div>
    </div>
  )
}
