import { useCallback, useEffect, useState } from 'react'
import { collection, getDocs, limit, orderBy, query, startAfter } from 'firebase/firestore'
import { RefreshCw, ScrollText } from 'lucide-react'
import { db } from '../firebaseConfig'

const PAGE = 50

const EVENTS = {
  block: { label: 'Blocked', color: '#ff4560' },
  unblock: { label: 'Unblocked', color: '#00e396' },
  unblock_failed: { label: 'Unblock failed', color: '#ffa500' },
  engine_start: { label: 'Engine started', color: '#00d4ff' },
}

const cell = { padding: '11px 16px', fontSize: 13, textAlign: 'left', verticalAlign: 'top' }
const head = { ...cell, fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: 0.6, fontWeight: 600 }

function formatTime(entry) {
  const when = entry.created_at?.toDate?.() || (entry.timestamp ? new Date(entry.timestamp) : null)
  return when ? when.toLocaleString() : '—'
}

/**
 * Admin page: who blocked or unblocked what, newest first. Entries are written
 * only by the engine, so this page reads on demand instead of holding a live listener.
 */
export default function AuditLogPage() {
  const [entries, setEntries] = useState([])
  const [cursor, setCursor] = useState(null)
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async (after) => {
    setLoading(true)
    setError('')
    try {
      const parts = [collection(db, 'audit'), orderBy('created_at', 'desc')]
      if (after) parts.push(startAfter(after))
      const snapshot = await getDocs(query(...parts, limit(PAGE)))
      const rows = snapshot.docs.map((d) => ({ id: d.id, ...d.data() }))
      setEntries((previous) => (after ? [...previous, ...rows] : rows))
      setCursor(snapshot.docs[snapshot.docs.length - 1] || null)
      setHasMore(snapshot.docs.length === PAGE)
    } catch {
      setError('Could not load the audit log. Check your connection and that your account is an admin.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(null) }, [load])

  return (
    <div style={{ padding: 24, maxWidth: 1100, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 10 }}>
            <ScrollText size={20} color="#00d4ff" /> Audit log
          </h1>
          <p style={{ color: '#64748b', fontSize: 13, marginTop: 4 }}>
            Every block and unblock, and who asked for it. Entries cannot be edited or deleted from the dashboard.
          </p>
        </div>
        <button onClick={() => load(null)} disabled={loading} style={{
          display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(255,255,255,0.05)',
          border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: '8px 12px',
          color: '#cbd5e1', fontSize: 13, cursor: loading ? 'wait' : 'pointer',
        }}>
          <RefreshCw size={14} className={loading ? 'spin' : undefined} /> Refresh
        </button>
      </div>

      {error && (
        <p role="alert" style={{
          fontSize: 13, color: '#ff8a9b', background: 'rgba(255,69,96,0.08)',
          border: '1px solid rgba(255,69,96,0.25)', borderRadius: 8, padding: '10px 12px',
        }}>{error}</p>
      )}

      <div className="glass-card" style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 640 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              <th style={head}>When</th>
              <th style={head}>Event</th>
              <th style={head}>Address</th>
              <th style={head}>By</th>
              <th style={head}>Detail</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => {
              const event = EVENTS[entry.event] || { label: entry.event, color: '#94a3b8' }
              return (
                <tr key={entry.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <td style={{ ...cell, color: '#94a3b8', whiteSpace: 'nowrap' }}>{formatTime(entry)}</td>
                  <td style={{ ...cell, color: event.color, fontWeight: 600, whiteSpace: 'nowrap' }}>{event.label}</td>
                  <td style={{ ...cell, fontFamily: 'monospace', color: '#e2e8f0' }}>{entry.ip || '—'}</td>
                  <td style={{ ...cell, color: '#cbd5e1' }}>
                    {entry.actor === 'engine' ? 'Engine (automatic)' : (entry.actor_email || entry.actor || '—')}
                  </td>
                  <td style={{ ...cell, color: '#94a3b8' }}>{entry.detail || '—'}</td>
                </tr>
              )
            })}
            {!loading && !error && entries.length === 0 && (
              <tr><td colSpan={5} style={{ ...cell, color: '#64748b' }}>
                Nothing yet. Entries appear when the engine blocks an address or an admin unblocks one.
              </td></tr>
            )}
            {loading && entries.length === 0 && (
              <tr><td colSpan={5} style={{ ...cell, color: '#64748b' }}>Loading…</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {hasMore && (
        <button onClick={() => load(cursor)} disabled={loading} style={{
          alignSelf: 'center', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.3)',
          borderRadius: 8, padding: '9px 18px', color: '#00d4ff', fontSize: 13, fontWeight: 600,
          cursor: loading ? 'wait' : 'pointer',
        }}>
          {loading ? 'Loading…' : 'Load older entries'}
        </button>
      )}
    </div>
  )
}
