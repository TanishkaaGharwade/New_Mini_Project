import { ShieldAlert, ShieldX, ShieldCheck, Filter } from 'lucide-react'
import ThreatTable from '../components/ThreatTable'

export default function ThreatsView({ threats = [], onExplain, onUnblock }) {
  const attacksOnly = threats.filter(t => t.attack_type?.toLowerCase().replace(/\.$/, '') !== 'normal')
  const blockedCount = threats.filter(t => t.blocked).length

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldAlert size={20} color="#ff4560" /> Threat Intelligence & Event Log
        </h1>
        <p style={{ color: '#64748b', fontSize: 13 }}>
          Detailed record of all captured packet flows, ML classification labels, and active firewall blocks
        </p>
      </div>

      {/* Summary KPI Pills */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
        <div style={{ background: 'rgba(255,69,96,0.08)', border: '1px solid rgba(255,69,96,0.2)', borderRadius: 10, padding: 16 }}>
          <span style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: 0.5 }}>CLASSIFIED THREATS</span>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#ff4560', marginTop: 4 }}>{attacksOnly.length}</div>
        </div>
        <div style={{ background: 'rgba(255,165,0,0.08)', border: '1px solid rgba(255,165,0,0.2)', borderRadius: 10, padding: 16 }}>
          <span style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: 0.5 }}>ACTIVE FIREWALL BLOCKS</span>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#ffa500', marginTop: 4 }}>{blockedCount}</div>
        </div>
        <div style={{ background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 10, padding: 16 }}>
          <span style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: 0.5 }}>TOTAL FLOWS CAPTURED</span>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#00d4ff', marginTop: 4 }}>{threats.length}</div>
        </div>
      </div>

      {/* Threat Table */}
      <ThreatTable
        threats={threats}
        onExplain={onExplain}
        onUnblock={onUnblock}
      />
    </div>
  )
}
