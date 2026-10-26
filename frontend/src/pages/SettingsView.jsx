/**
 * SettingsView — engine and model settings page.
 *
 * Shows real values (CICIDS2017, 19 features, 7 labels, Random Forest v1).
 * NSL-KDD, 20 labels, localhost:5000 SSE references all removed.
 * Engine online/offline indicator driven by stats.updated_at heartbeat.
 */
import { Settings, Shield, Sliders, Cpu, Database, Wifi, WifiOff } from 'lucide-react'
import { ATTACK_LABELS } from '../data/labels'

function Row({ label, value, valueColor = '#00d4ff' }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10, fontSize: 13, color: '#cbd5e1' }}>
      <span>{label}</span>
      <span style={{ fontFamily: 'monospace', color: valueColor }}>{value}</span>
    </div>
  )
}

function Card({ title, icon: Icon, color, children }) {
  return (
    <div style={{ background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: 24 }}>
      <h3 style={{ fontSize: 15, fontWeight: 600, color, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon size={16} /> {title}
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {children}
      </div>
    </div>
  )
}

export default function SettingsView({ stats }) {
  // Derive engine online from the heartbeat timestamp
  const updatedAt = stats?.updated_at
  let engineOnline = false
  if (updatedAt) {
    const ts = updatedAt?.toDate ? updatedAt.toDate() : new Date(updatedAt)
    engineOnline = Date.now() - ts.getTime() < 2 * 60 * 1000
  }

  const detectOnly    = stats?.detect_only ?? false
  const modelVersion  = stats?.model_version ?? 'v1'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Settings size={20} color="#7c3aed" /> Engine &amp; System Settings
        </h1>
        <p style={{ color: '#64748b', fontSize: 13 }}>
          Live engine status and detection configuration (read-only — set in python-engine/config.py)
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
        {/* Card 1: Engine heartbeat */}
        <Card title="Engine Status" icon={engineOnline ? Wifi : WifiOff} color={engineOnline ? '#00e396' : '#ff4560'}>
          <Row label="Status"
            value={engineOnline ? 'ONLINE' : 'OFFLINE'}
            valueColor={engineOnline ? '#00e396' : '#ff4560'} />
          <Row label="Mode"
            value={detectOnly ? 'Detect-only (no blocking)' : 'Active prevention'}
            valueColor={detectOnly ? '#ffa500' : '#00e396'} />
          <Row label="Last heartbeat"
            value={updatedAt
              ? (updatedAt?.toDate ? updatedAt.toDate() : new Date(updatedAt)).toLocaleTimeString('en-IN', { hour12: false })
              : '—'}
            valueColor="#94a3b8" />
        </Card>

        {/* Card 2: ML Model */}
        <Card title="ML Classification Model" icon={Cpu} color="#7c3aed">
          <Row label="Algorithm"        value="Random Forest Classifier" />
          <Row label="Model version"    value={`model_${modelVersion}.pkl`} />
          <Row label="Training dataset" value="CICIDS2017"               valueColor="#7c3aed" />
          <Row label="Features"         value="19 flow-level features"   valueColor="#7c3aed" />
          <Row label="Test accuracy"    value="99.56%"                   valueColor="#00e396" />
          <Row label="Macro F1"         value="0.9472"                   valueColor="#00e396" />
        </Card>

        {/* Card 3: Detection labels */}
        <Card title="Detection Labels" icon={Database} color="#00d4ff">
          <Row label="Classes" value={`${ATTACK_LABELS.length} attack labels`} valueColor="#00d4ff" />
          {ATTACK_LABELS.map(l => (
            <Row key={l} label={l} value="Active" valueColor="#00e396" />
          ))}
          <div style={{ fontSize: 12, color: '#475569', marginTop: 4 }}>
            Note: Benign flows are never stored as threat records.
          </div>
        </Card>

        {/* Card 4: Prevention engine */}
        <Card title="Active Prevention Engine" icon={Shield} color="#ff4560">
          <Row label="Firewall system"      value="Windows advfirewall (netsh)" valueColor="#ff4560" />
          <Row label="Alert threshold"      value="≥ 70% confidence"            valueColor="#ffa500" />
          <Row label="Block threshold"      value="≥ 90% confidence, 3 flows"   valueColor="#ffa500" />
          <Row label="Rate rules"           value="SYN Flood, Port Scan, ICMP Flood" />
          <Row label="Never-block list"     value="127.0.0.1, gateway, cloud subnets" valueColor="#00e396" />
          <Row label="Data channel"         value="Firestore (cloud)"           />
          <div style={{ fontSize: 12, color: '#475569', marginTop: 4 }}>
            Engine is Windows-only. Dashboard connects via Firestore, not localhost.
          </div>
        </Card>
      </div>

      {/* Known limitations */}
      <div style={{ background: 'rgba(255,165,0,0.06)', border: '1px solid rgba(255,165,0,0.2)', borderRadius: 12, padding: 20 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#ffa500', marginBottom: 12 }}>Known Limitations</h3>
        <ul style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.8, paddingLeft: 18 }}>
          <li>Botnet detection recall is 59.6% — some bots may be missed (lower still after the 70% alert threshold).</li>
          <li>Model verdicts under 70% confidence are ignored to cut false alarms on normal traffic; rate rules still catch floods at any confidence.</li>
          <li>Web attacks, Infiltration and Heartbleed are not detected (too few training samples).</li>
          <li>Engine is Windows-only; Linux/macOS are not supported.</li>
          <li>Live mode requires the CyberSentinel engine running on the protected machine.</li>
          <li>Model accuracy figures are from the CICIDS2017 dataset, not live traffic validation.</li>
        </ul>
      </div>
    </div>
  )
}
