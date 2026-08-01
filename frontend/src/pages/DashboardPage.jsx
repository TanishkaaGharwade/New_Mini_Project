import { useState } from 'react'
import Navbar from '../components/Navbar'
import Sidebar from '../components/Sidebar'
import StatCards from '../components/StatCards'
import ProtocolChart from '../components/ProtocolChart'
import ThreatTable from '../components/ThreatTable'
import TopologyGraph from '../components/TopologyGraph'
import GeminiPanel from '../components/GeminiPanel'
import { useLiveEngine } from '../hooks/useLiveEngine'

import ThreatsView from './ThreatsView'
import TopologyView from './TopologyView'
import AIAnalystView from './AIAnalystView'
import SettingsView from './SettingsView'

export default function DashboardPage() {
  const [activeNav, setActiveNav] = useState('dashboard')
  const [selectedThreat, setSelectedThreat] = useState(null)

  // Real-time live engine connection via SSE & unblock API
  const { threats, stats, isConnected, handleUnblock } = useLiveEngine()

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: 'var(--bg-base)' }}>
      <Navbar totalAttacks={stats.totalAttacks} isConnected={isConnected} />

      <div style={{ display: 'flex', flex: 1 }}>
        <Sidebar active={activeNav} onNav={setActiveNav} />

        {/* Main content area */}
        <main style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>

          {/* Tab 1: Main Security Dashboard */}
          {activeNav === 'dashboard' && (
            <>
              <div style={{ marginBottom: 24 }}>
                <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
                  Security Command Center
                </h1>
                <p style={{ color: '#64748b', fontSize: 13 }}>
                  Real-Time Network Intrusion Detection & Automated Prevention (NetSentinel Engine)
                </p>
              </div>

              <StatCards stats={stats} />

              <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 16, marginBottom: 24 }}>
                <ProtocolChart threats={threats} />
                <TopologyGraph threats={threats} />
              </div>

              <ThreatTable
                threats={threats}
                onExplain={t => setSelectedThreat(t)}
                onUnblock={handleUnblock}
              />
            </>
          )}

          {/* Tab 2: Dedicated Threat Log */}
          {activeNav === 'threats' && (
            <ThreatsView
              threats={threats}
              onExplain={t => setSelectedThreat(t)}
              onUnblock={handleUnblock}
            />
          )}

          {/* Tab 3: Dedicated Network Topology */}
          {activeNav === 'topology' && (
            <TopologyView threats={threats} />
          )}

          {/* Tab 4: AI Analyst Chat */}
          {activeNav === 'ai' && (
            <AIAnalystView threats={threats} />
          )}

          {/* Tab 5: Settings & Config */}
          {activeNav === 'settings' && (
            <SettingsView />
          )}

          {/* Gemini AI Side Panel for Threat Explanations */}
          {selectedThreat && (
            <GeminiPanel
              threat={selectedThreat}
              onClose={() => setSelectedThreat(null)}
            />
          )}
        </main>
      </div>
    </div>
  )
}
