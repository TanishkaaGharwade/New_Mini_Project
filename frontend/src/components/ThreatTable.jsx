/**
 * ThreatTable — real-time threat log table.
 *
 * Uses the new contract fields:
 *   threat.label      (not attack_type)
 *   threat.action     ('blocked'|'alert_only'|'detect_only'|'whitelisted'|'unblocked')
 *   threat.confidence (0–1 or null → show "rule")
 *   threat.trigger    ('model'|'rule'|'both')
 *
 * Unblock button visible only when role === 'admin', mode === 'live', action === 'blocked'.
 */
import { useState } from 'react'
import { Search, ShieldCheck, ShieldX, Unlock, ShieldOff, AlertCircle } from 'lucide-react'
import { getLabelStyle, ATTACK_LABELS } from '../data/labels'
import { useAuth } from '../context/AuthContext'

/** Badge for the label column */
function LabelBadge({ label }) {
  const s = getLabelStyle(label)
  return (
    <span style={{
      padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
      textTransform: 'uppercase', letterSpacing: '0.3px',
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
    }}>
      {s.displayName}
    </span>
  )
}

/** Action status chip */
function ActionChip({ action }) {
  const MAP = {
    blocked:     { label: 'Blocked',     color: '#ff4560', Icon: ShieldX     },
    alert_only:  { label: 'Alert Only',  color: '#ffa500', Icon: AlertCircle },
    detect_only: { label: 'Detect Only', color: '#00d4ff', Icon: ShieldCheck },
    whitelisted: { label: 'Whitelisted', color: '#00e396', Icon: ShieldCheck },
    unblocked:   { label: 'Unblocked',   color: '#94a3b8', Icon: ShieldOff   },
  }
  const { label, color, Icon } = MAP[action] ?? { label: action ?? '—', color: '#94a3b8', Icon: ShieldCheck }
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 4, color, fontSize: 12, fontWeight: 600 }}>
      <Icon size={13} /> {label}
    </span>
  )
}

function formatTime(iso) {
  try { return new Date(iso).toLocaleTimeString('en-IN', { hour12: false }) }
  catch { return iso?.slice(11, 19) || '—' }
}

export default function ThreatTable({ threats = [], onExplain, requestUnblock, mode }) {
  const [search, setSearch]             = useState('')
  const [filterLabel, setFilterLabel]   = useState('all')
  const [filterAction, setFilterAction] = useState('all')
  const [unblockState, setUnblockState] = useState({}) // ip → 'pending'|'done'|'failed'|message

  const { role } = useAuth() ?? {}
  const canUnblock = role === 'admin' && mode === 'live'

  const filtered = threats.filter(t => {
    if (filterLabel !== 'all' && t.label !== filterLabel) return false
    if (filterAction !== 'all' && t.action !== filterAction) return false
    if (search && !t.src_ip?.includes(search) && !t.label?.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const handleUnblockClick = async (ip) => {
    setUnblockState(prev => ({ ...prev, [ip]: 'pending' }))
    try {
      const result = await requestUnblock?.(ip)
      setUnblockState(prev => ({ ...prev, [ip]: result?.status ?? 'done' }))
    } catch (err) {
      setUnblockState(prev => ({ ...prev, [ip]: 'failed:' + err.message }))
    }
  }

  const unblockLabel = (ip) => {
    const s = unblockState[ip]
    if (!s) return 'Unblock'
    if (s === 'pending') return 'Pending…'
    if (s === 'done') return 'Unblocked'
    if (s.startsWith('failed:')) return 'Failed'
    return s
  }

  return (
    <div style={{
      background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 12, padding: '20px 0', backdropFilter: 'blur(8px)', overflow: 'hidden',
    }}>
      {/* Header + filters */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 24px 16px', flexWrap: 'wrap', gap: 10 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Threat Log ({threats.length})
        </h3>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {/* IP / label search */}
          <div style={{ position: 'relative' }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter by IP or label…"
              style={{
                background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 8, padding: '6px 12px 6px 30px',
                color: '#e2e8f0', fontSize: 12, outline: 'none', width: 180,
              }}
            />
          </div>
          {/* Label filter */}
          <select
            value={filterLabel}
            onChange={e => setFilterLabel(e.target.value)}
            style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: '6px 10px', color: '#e2e8f0', fontSize: 12, outline: 'none' }}
          >
            <option value="all">All Labels</option>
            {ATTACK_LABELS.map(l => <option key={l} value={l}>{l}</option>)}
          </select>
          {/* Action filter */}
          <select
            value={filterAction}
            onChange={e => setFilterAction(e.target.value)}
            style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: '6px 10px', color: '#e2e8f0', fontSize: 12, outline: 'none' }}
          >
            <option value="all">All Actions</option>
            <option value="blocked">Blocked</option>
            <option value="alert_only">Alert Only</option>
            <option value="detect_only">Detect Only</option>
            <option value="whitelisted">Whitelisted</option>
            <option value="unblocked">Unblocked</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              {['Time', 'Source IP', 'Destination', 'Proto', 'Label', 'Confidence', 'Trigger', 'Action', 'Pkts', 'Controls'].map(h => (
                <th key={h} style={{
                  padding: '8px 14px', textAlign: 'left',
                  color: '#475569', fontWeight: 500, fontSize: 11,
                  textTransform: 'uppercase', letterSpacing: '0.5px', whiteSpace: 'nowrap',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={10} style={{ padding: '32px 16px', textAlign: 'center', color: '#475569', fontSize: 13 }}>
                  No threats match current filters. Engine monitoring active…
                </td>
              </tr>
            )}
            {filtered.map((threat, i) => (
              <tr
                key={threat.id || i}
                className="slide-in"
                style={{
                  borderBottom: '1px solid rgba(255,255,255,0.04)',
                  background: 'transparent',
                  transition: 'background 0.15s',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <td style={{ padding: '11px 14px', color: '#64748b', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: 12 }}>
                  {formatTime(threat.timestamp)}
                </td>
                <td style={{ padding: '11px 14px', color: '#e2e8f0', fontFamily: 'monospace', fontWeight: 500 }}>
                  {threat.src_ip}
                  {threat.src_port ? <span style={{ color: '#475569' }}>:{threat.src_port}</span> : null}
                </td>
                <td style={{ padding: '11px 14px', color: '#94a3b8', fontFamily: 'monospace', fontSize: 12 }}>
                  {threat.dst_ip}
                  {threat.dst_port ? <span style={{ color: '#475569' }}>:{threat.dst_port}</span> : null}
                </td>
                <td style={{ padding: '11px 14px' }}>
                  <span style={{ color: '#7c3aed', fontSize: 11, fontWeight: 600, fontFamily: 'monospace' }}>
                    {threat.protocol || '?'}
                  </span>
                </td>
                <td style={{ padding: '11px 14px' }}>
                  <LabelBadge label={threat.label} />
                </td>
                <td style={{ padding: '11px 14px', color: '#94a3b8', fontSize: 12, fontFamily: 'monospace' }}>
                  {threat.confidence != null ? `${(threat.confidence * 100).toFixed(0)}%` : 'rule'}
                </td>
                <td style={{ padding: '11px 14px', color: '#64748b', fontSize: 12, textTransform: 'capitalize' }}>
                  {threat.trigger ?? '—'}
                </td>
                <td style={{ padding: '11px 14px' }}>
                  <ActionChip action={threat.action} />
                </td>
                <td style={{ padding: '11px 14px', color: '#64748b', fontSize: 12 }}>
                  {threat.packet_count ?? 1}
                </td>
                <td style={{ padding: '11px 14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <button
                      onClick={() => onExplain?.(threat)}
                      style={{
                        background: 'rgba(124,58,237,0.15)', border: '1px solid rgba(124,58,237,0.3)',
                        borderRadius: 6, padding: '4px 10px', color: '#a78bfa',
                        fontSize: 11, fontWeight: 600, cursor: 'pointer', transition: 'all 0.15s',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(124,58,237,0.3)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'rgba(124,58,237,0.15)'}
                    >
                      Explain
                    </button>
                    {canUnblock && threat.action === 'blocked' && (
                      <button
                        onClick={() => handleUnblockClick(threat.src_ip)}
                        disabled={unblockState[threat.src_ip] === 'pending'}
                        title={unblockState[threat.src_ip]?.startsWith('failed:')
                          ? unblockState[threat.src_ip].replace('failed:', '')
                          : undefined}
                        style={{
                          background: 'rgba(255,165,0,0.15)', border: '1px solid rgba(255,165,0,0.3)',
                          borderRadius: 6, padding: '4px 10px', color: '#ffa500',
                          fontSize: 11, fontWeight: 600, cursor: 'pointer',
                          display: 'flex', alignItems: 'center', gap: 4, transition: 'all 0.15s',
                          opacity: unblockState[threat.src_ip] === 'pending' ? 0.6 : 1,
                        }}
                      >
                        <Unlock size={11} />
                        {unblockLabel(threat.src_ip)}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
