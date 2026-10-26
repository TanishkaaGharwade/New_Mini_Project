/**
 * ExplanationPanel — slides in from the right to show a stored threat explanation.
 * Renders threat.explanation from Firestore (or the waiting/offline states).
 */
import { Sparkles, X, Cpu, AlertTriangle, CheckCircle2, ShieldAlert, Zap } from 'lucide-react'
import { getLabelStyle } from '../data/labels'

const SEVERITY_COLOR = {
  LOW:      '#00e396',
  MEDIUM:   '#ffa500',
  HIGH:     '#ff4560',
  CRITICAL: '#ff2244',
}

function SeverityBadge({ severity }) {
  const color = SEVERITY_COLOR[severity] ?? '#94a3b8'
  return (
    <span style={{
      padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
      letterSpacing: '0.5px', textTransform: 'uppercase',
      background: `${color}22`, color, border: `1px solid ${color}55`,
    }}>
      {severity ?? '—'}
    </span>
  )
}

function EvidenceRow({ feature, value }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12,
      padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
      <span style={{ color: '#94a3b8' }}>{feature}</span>
      <span style={{ color: '#00d4ff', fontFamily: 'monospace', fontWeight: 600 }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </span>
    </div>
  )
}

export default function ExplanationPanel({ threat, onClose }) {
  if (!threat) return null

  const labelStyle  = getLabelStyle(threat.label)
  const explanation = threat.explanation   // may be absent
  const evidence    = threat.evidence ?? []

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, width: 440,
      background: 'rgba(9,15,30,0.98)',
      borderLeft: '1px solid rgba(0,212,255,0.2)',
      backdropFilter: 'blur(24px)',
      zIndex: 100, padding: 28,
      display: 'flex', flexDirection: 'column', gap: 20,
      boxShadow: '-10px 0 40px rgba(0,0,0,0.7)',
      animation: 'slide-in 0.25s ease-out',
      overflowY: 'auto',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 8,
            background: 'linear-gradient(135deg, #7c3aed, #00d4ff)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Sparkles size={18} color="#fff" />
          </div>
          <div>
            <h2 style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>AI Threat Analysis</h2>
            <span style={{ fontSize: 11, color: '#00d4ff', letterSpacing: '0.5px' }}>
              PLAIN-ENGLISH EXPLANATION
            </span>
          </div>
        </div>
        <button onClick={onClose} style={{
          background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8, padding: '6px', color: '#94a3b8', cursor: 'pointer',
        }}>
          <X size={16} />
        </button>
      </div>

      {/* Threat Quick Specs */}
      <div style={{
        background: 'rgba(15,31,56,0.8)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 10,
        fontSize: 12, fontFamily: 'monospace',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{
            padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
            background: labelStyle.bg, color: labelStyle.color, border: `1px solid ${labelStyle.border}`,
            textTransform: 'uppercase',
          }}>
            {labelStyle.displayName}
          </span>
          {explanation ? <SeverityBadge severity={explanation.severity} /> : null}
        </div>
        <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.06)' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b' }}>
          <span>Source IP:</span>
          <span style={{ color: '#00d4ff' }}>{threat.src_ip}:{threat.src_port || '—'}</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b' }}>
          <span>Target IP:</span>
          <span style={{ color: '#e2e8f0' }}>{threat.dst_ip}:{threat.dst_port || '—'}</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b' }}>
          <span>Protocol / Packets:</span>
          <span style={{ color: '#7c3aed' }}>{threat.protocol} ({threat.packet_count ?? 1} pkts)</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b' }}>
          <span>Trigger / Confidence:</span>
          <span style={{ color: '#e2e8f0' }}>
            {threat.trigger ?? '—'}
            {' / '}
            {threat.confidence != null ? `${(threat.confidence * 100).toFixed(0)}%` : 'rule'}
          </span>
        </div>
      </div>

      {/* Explanation content */}
      {!explanation ? (
        <div style={{
          background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.15)',
          borderRadius: 12, padding: 20, textAlign: 'center', color: '#64748b', fontSize: 13,
        }}>
          <Zap size={20} color="#00d4ff" style={{ marginBottom: 8 }} />
          <div>Generating explanation…</div>
          <div style={{ fontSize: 11, marginTop: 4, color: '#475569' }}>
            The AI explanation is being generated by the engine and will appear within seconds.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#00d4ff', fontSize: 13, fontWeight: 600 }}>
            <Cpu size={15} />
            What Happened?
          </div>
          <p style={{ color: '#cbd5e1', fontSize: 13, lineHeight: 1.6, background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, borderLeft: '3px solid #00d4ff', margin: 0 }}>
            {explanation.summary}
          </p>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#ffa500', fontSize: 13, fontWeight: 600, marginTop: 4 }}>
            <AlertTriangle size={15} />
            Technical Mechanism
          </div>
          <p style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.6, background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, borderLeft: '3px solid #ffa500', margin: 0 }}>
            {explanation.mechanism}
          </p>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#00e396', fontSize: 13, fontWeight: 600, marginTop: 4 }}>
            <CheckCircle2 size={15} />
            Recommendation
          </div>
          <p style={{ color: '#00e396', fontSize: 13, lineHeight: 1.6, background: 'rgba(0,227,150,0.06)', padding: 12, borderRadius: 8, borderLeft: '3px solid #00e396', margin: 0 }}>
            {explanation.recommendation}
          </p>
        </div>
      )}

      {/* Evidence features */}
      {evidence.length > 0 && (
        <div style={{
          background: 'rgba(15,31,56,0.8)', border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: 12, padding: '14px 16px',
        }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#7c3aed', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Evidence Features
          </div>
          {evidence.map((e, i) => (
            <EvidenceRow key={i} feature={e.feature} value={e.value} />
          ))}
        </div>
      )}

      {/* Footer */}
      <div style={{ marginTop: 'auto', paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.08)',
        display: 'flex', alignItems: 'center', gap: 8, color: '#64748b', fontSize: 11 }}>
        <ShieldAlert size={14} color="#7c3aed" />
        <span>
          {explanation
            ? explanation.source === 'offline'
              ? 'Offline knowledge base'
              : 'AI-generated explanation — CyberSentinel Engine'
            : 'Explanation pending…'}
        </span>
      </div>
    </div>
  )
}
