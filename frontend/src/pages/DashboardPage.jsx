/**
 * DashboardPage — main shell for both Live and Demo modes.
 *
 * Accepts `dataHook` as a prop so it can be powered by either
 * useFirestoreThreats (live) or useDemoReplay (demo) without changing internals.
 */
import { useState } from 'react'
import Navbar from '../components/Navbar'
import Sidebar from '../components/Sidebar'
import StatCards from '../components/StatCards'
import ProtocolChart from '../components/ProtocolChart'
import ThreatTable from '../components/ThreatTable'
import TopologyGraph from '../components/TopologyGraph'
import ExplanationPanel from '../components/ExplanationPanel'

import ThreatsView from './ThreatsView'
import TopologyView from './TopologyView'
import AIAnalystView from './AIAnalystView'
import SettingsView from './SettingsView'

/**
 * @param {{ dataHook: function }} props
 *   dataHook — a hook function (useFirestoreThreats or useDemoReplay) that
 *   returns { threats, stats, engineOnline, mode, requestUnblock, error }
 */
export default function DashboardPage({ dataHook }) {
  const [activeNav, setActiveNav]       = useState('dashboard')
  const [selectedThreat, setSelectedThreat] = useState(null)

  const { threats, stats, engineOnline, mode, requestUnblock, error } =
    dataHook?.() ?? { threats: [], stats: {}, engineOnline: false, mode: 'live', requestUnblock: null, error: null }

  // Show the latest copy of the selected record, so an explanation the engine adds
  // after the panel opened appears without reopening it
  const shownThreat = (selectedThreat?.id && threats.find(t => t.id === selectedThreat.id)) || selectedThreat

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: 'var(--bg-base)' }}>
      <Navbar
        totalAttacks={stats?.total_attacks ?? 0}
        engineOnline={engineOnline}
        mode={mode}
      />

      <div style={{ display: 'flex', flex: 1 }}>
        <Sidebar active={activeNav} onNav={setActiveNav} mode={mode} />

        <main style={{ flex: 1, minWidth: 0, padding: '24px' }}>
          {/* Demo banner */}
          {mode === 'demo' && (
            <div style={{
              background: 'rgba(255,165,0,0.12)', border: '1px solid rgba(255,165,0,0.3)',
              padding: '8px 24px', borderRadius: 8, marginBottom: 16, textAlign: 'center', color: '#ffa500', fontSize: 13, fontWeight: 600,
            }}>
              ⚠️ Simulated replay of recorded attack traffic. Not live data.
            </div>
          )}

          {/* Firestore error banner */}
          {error && (
            <div style={{
              background: 'rgba(255,69,96,0.10)', border: '1px solid rgba(255,69,96,0.3)',
              padding: '8px 24px', borderRadius: 8, marginBottom: 16, textAlign: 'center', color: '#ff4560', fontSize: 13,
            }}>
              {error}
            </div>
          )}

          {activeNav === 'dashboard' && (
            <>
              <div style={{ marginBottom: 24 }}>
                <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
                  Security Command Center
                </h1>
                <p style={{ color: '#64748b', fontSize: 13 }}>
                  Real-Time Network Intrusion Detection &amp; Automated Prevention — CyberSentinel
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
                requestUnblock={requestUnblock}
                mode={mode}
              />
            </>
          )}

          {activeNav === 'threats' && (
            <ThreatsView
              threats={threats}
              onExplain={t => setSelectedThreat(t)}
              requestUnblock={requestUnblock}
              mode={mode}
            />
          )}

          {activeNav === 'topology' && (
            <TopologyView threats={threats} />
          )}

          {activeNav === 'ai' && (
            <AIAnalystView threats={threats} mode={mode} />
          )}

          {activeNav === 'settings' && (
            <SettingsView stats={stats} />
          )}

          {shownThreat && (
            <ExplanationPanel
              threat={shownThreat}
              onClose={() => setSelectedThreat(null)}
            />
          )}
        </main>
      </div>
    </div>
  )
}
