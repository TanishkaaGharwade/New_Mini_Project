import { useState } from 'react'
import { Search, ShieldCheck, ShieldX, Unlock } from 'lucide-react'
import { ATTACK_BADGE_COLORS } from '../data/dummyThreats'

/**
 * Visual badge indicating the classification label of a packet.
 * Dynamically assigns colors based on the attack type (e.g., normal, neptune, nmap).
 * 
 * @param {Object} props
 * @param {string} props.label - The ML classification label (e.g., "neptune.", "normal.")
 */
function AttackBadge({ label }) {
  const key = label?.toLowerCase().replace(/\.$/, '') // strip trailing dot
  const classes = ATTACK_BADGE_COLORS[key] || 'bg-slate-700/40 text-slate-300 border border-slate-600/30'
  return (
    <span style={{
      padding: '2px 10px', borderRadius: 20,
      fontSize: 11, fontWeight: 600, letterSpacing: '0.3px',
      textTransform: 'uppercase',
      ...(key === 'normal'
        ? { background: 'rgba(0,227,150,0.15)', color: '#00e396', border: '1px solid rgba(0,227,150,0.3)' }
        : { background: 'rgba(255,69,96,0.12)', color: '#ff4560', border: '1px solid rgba(255,69,96,0.25)' }),
    }}>
      {key || label}
    </span>
  )
}

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString('en-IN', { hour12: false })
  } catch { return iso?.slice(11, 19) || '—' }
}

/**
 * Renders a real-time table of intercepted network traffic.
 * Highlights identified threats and provides actionable mitigation controls (Explain, Unblock).
 *
 * @param {Object} props
 * @param {Object[]} props.threats - Array of threat event objects from the SSE stream.
 * @param {Function} props.onExplain - Callback invoked when the user clicks 'Explain' for a threat.
 * @param {Function} props.onUnblock - Callback invoked when the user clicks 'Unblock' for an IP.
 */
export default function ThreatTable({ threats = [], onExplain, onUnblock }) {
  const [search, setSearch] = useState('')
  const [unblockingIp, setUnblockingIp] = useState(null)

  const filtered = threats.filter(t =>
    !search ||
    t.src_ip?.includes(search) ||
    t.attack_type?.toLowerCase().includes(search.toLowerCase())
  )

  const handleUnblockClick = async (ip) => {
    setUnblockingIp(ip)
    await onUnblock?.(ip)
    setUnblockingIp(null)
  }

  return (
    <div style={{
      background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 12, padding: '20px 0', backdropFilter: 'blur(8px)',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 24px 16px' }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Real-Time Threat Log ({threats.length})
        </h3>
        <div style={{ position: 'relative' }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter by IP or attack..."
            style={{
              background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 8, padding: '6px 12px 6px 30px',
              color: '#e2e8f0', fontSize: 13, outline: 'none', width: 220,
            }}
          />
        </div>
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              {['Time', 'Source IP', 'Destination', 'Protocol', 'Attack', 'Packets', 'Status', 'Action'].map(h => (
                <th key={h} style={{
                  padding: '8px 16px', textAlign: 'left',
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
                <td colSpan={8} style={{ padding: '32px 16px', textAlign: 'center', color: '#475569', fontSize: 13 }}>
                  No threats recorded yet. Monitoring active...
                </td>
              </tr>
            )}
            {filtered.map((threat, i) => {
              const isAttack = threat.attack_type?.toLowerCase().replace(/\.$/, '') !== 'normal'
              return (
                <tr
                  key={threat.id || i}
                  className="slide-in"
                  style={{
                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                    background: isAttack ? 'rgba(255,69,96,0.03)' : 'transparent',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                  onMouseLeave={e => e.currentTarget.style.background = isAttack ? 'rgba(255,69,96,0.03)' : 'transparent'}
                >
                  <td style={{ padding: '12px 16px', color: '#64748b', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: 12 }}>
                    {formatTime(threat.timestamp)}
                  </td>
                  <td style={{ padding: '12px 16px', color: '#e2e8f0', fontFamily: 'monospace', fontWeight: 500 }}>
                    {threat.src_ip}
                    {threat.src_port && threat.src_port !== 'N/A' && <span style={{ color: '#475569' }}>:{threat.src_port}</span>}
                  </td>
                  <td style={{ padding: '12px 16px', color: '#94a3b8', fontFamily: 'monospace', fontSize: 12 }}>
                    {threat.dst_ip}
                    {threat.dst_port && threat.dst_port !== 'N/A' && <span style={{ color: '#475569' }}>:{threat.dst_port}</span>}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ color: '#7c3aed', fontSize: 11, fontWeight: 600, fontFamily: 'monospace' }}>
                      {threat.protocol || '?'}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <AttackBadge label={threat.attack_type} />
                  </td>
                  <td style={{ padding: '12px 16px', color: '#64748b', fontSize: 12 }}>
                    {threat.packet_count || 1}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    {threat.blocked
                      ? <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#ff4560', fontSize: 12, fontWeight: 600 }}>
                          <ShieldX size={13} /> BLOCKED
                        </span>
                      : <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#00e396', fontSize: 12, fontWeight: 600 }}>
                          <ShieldCheck size={13} /> ALLOWED
                        </span>
                    }
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {isAttack && (
                        <button
                          onClick={() => onExplain?.(threat)}
                          style={{
                            background: 'rgba(124,58,237,0.15)', border: '1px solid rgba(124,58,237,0.3)',
                            borderRadius: 6, padding: '4px 10px', color: '#a78bfa',
                            fontSize: 11, fontWeight: 600, cursor: 'pointer',
                            transition: 'all 0.15s',
                          }}
                          onMouseEnter={e => e.currentTarget.style.background = 'rgba(124,58,237,0.3)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'rgba(124,58,237,0.15)'}
                        >
                          Explain
                        </button>
                      )}
                      {threat.blocked && (
                        <button
                          onClick={() => handleUnblockClick(threat.src_ip)}
                          disabled={unblockingIp === threat.src_ip}
                          style={{
                            background: 'rgba(255,165,0,0.15)', border: '1px solid rgba(255,165,0,0.3)',
                            borderRadius: 6, padding: '4px 10px', color: '#ffa500',
                            fontSize: 11, fontWeight: 600, cursor: 'pointer',
                            display: 'flex', alignItems: 'center', gap: 4,
                            transition: 'all 0.15s',
                          }}
                        >
                          <Unlock size={11} />
                          {unblockingIp === threat.src_ip ? 'Unblocking...' : 'Unblock'}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
