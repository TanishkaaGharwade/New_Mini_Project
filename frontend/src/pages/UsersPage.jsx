import { useEffect, useState } from 'react'
import { collection, doc, onSnapshot, updateDoc } from 'firebase/firestore'
import { Users } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { db } from '../firebaseConfig'

const cell = { padding: '12px 16px', fontSize: 13, textAlign: 'left' }
const head = { ...cell, fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: 0.6, fontWeight: 600 }

/** Admin page: everyone with a profile, and a control to change another person's role. */
export default function UsersPage() {
  const { user } = useAuth()
  const [profiles, setProfiles] = useState(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(null)

  useEffect(() => onSnapshot(
    collection(db, 'users'),
    (snapshot) => {
      const rows = snapshot.docs.map((d) => ({ uid: d.id, ...d.data() }))
      rows.sort((a, b) => (a.email || '').localeCompare(b.email || ''))
      setProfiles(rows)
    },
    () => setError('Could not load users. Check your connection and that your account is an admin.'),
  ), [])

  const changeRole = async (uid, role) => {
    setError('')
    setSaving(uid)
    try {
      await updateDoc(doc(db, 'users', uid), { role })
    } catch {
      setError('The role was not changed. You may have lost admin access, or the connection dropped.')
    } finally {
      setSaving(null)
    }
  }

  return (
    <div style={{ padding: 24, maxWidth: 860, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Users size={20} color="#00d4ff" /> Users
        </h1>
        <p style={{ color: '#64748b', fontSize: 13, marginTop: 4 }}>
          Admins can unblock addresses, manage users and read the audit log. Viewers can only look.
        </p>
      </div>

      {error && (
        <p role="alert" style={{
          fontSize: 13, color: '#ff8a9b', background: 'rgba(255,69,96,0.08)',
          border: '1px solid rgba(255,69,96,0.25)', borderRadius: 8, padding: '10px 12px',
        }}>{error}</p>
      )}

      <div className="glass-card" style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              <th style={head}>Email</th>
              <th style={head}>Role</th>
            </tr>
          </thead>
          <tbody>
            {profiles === null && !error && (
              <tr><td colSpan={2} style={{ ...cell, color: '#64748b' }}>Loading…</td></tr>
            )}
            {profiles?.map((p) => {
              const isSelf = p.uid === user.uid
              const role = p.role === 'admin' ? 'admin' : 'viewer'
              return (
                <tr key={p.uid} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <td style={{ ...cell, color: '#e2e8f0' }}>
                    {p.email || <span style={{ color: '#64748b' }}>(no email on profile)</span>}
                    {isSelf && <span style={{ color: '#64748b', marginLeft: 8 }}>(you)</span>}
                  </td>
                  <td style={cell}>
                    {isSelf ? (
                      <span style={{ color: '#94a3b8' }} title="Another admin has to change your role">
                        {role} — cannot change your own
                      </span>
                    ) : (
                      <select
                        aria-label={`Role for ${p.email || p.uid}`}
                        value={role}
                        disabled={saving === p.uid}
                        onChange={(e) => changeRole(p.uid, e.target.value)}
                        style={{
                          background: '#0f1f38', color: '#e2e8f0', border: '1px solid rgba(255,255,255,0.15)',
                          borderRadius: 6, padding: '6px 10px', fontSize: 13,
                        }}
                      >
                        <option value="viewer">viewer</option>
                        <option value="admin">admin</option>
                      </select>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.7 }}>
        <p style={{ color: '#cbd5e1', fontWeight: 600 }}>Adding someone</p>
        <p>
          New accounts are created on the machine that holds the project key, not from this page:
        </p>
        <code style={{
          display: 'block', margin: '8px 0', padding: '10px 12px', borderRadius: 8, fontSize: 12,
          background: 'rgba(255,255,255,0.04)', color: '#e2e8f0', overflowX: 'auto', whiteSpace: 'nowrap',
        }}>
          python python-engine/tools/manage_users.py add person@example.com viewer
        </code>
        <p>It prints a one-time link for them to choose a password. They then appear in this list.</p>
      </div>
    </div>
  )
}
