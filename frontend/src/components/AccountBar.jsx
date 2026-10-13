import { NavLink, useNavigate } from 'react-router-dom'
import { LogOut, ScrollText, ShieldCheck, UserRound, Users } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

const linkStyle = ({ isActive }) => ({
  display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600, textDecoration: 'none',
  padding: '5px 10px', borderRadius: 6,
  color: isActive ? '#00d4ff' : '#94a3b8',
  background: isActive ? 'rgba(0,212,255,0.1)' : 'transparent',
})

/**
 * Thin bar above the signed-in pages: who is signed in, their role, the
 * admin-only pages, and sign out.
 */
export default function AccountBar() {
  const { user, role, isAdmin, signOut } = useAuth()
  const navigate = useNavigate()

  const handleSignOut = async () => {
    await signOut()
    navigate('/login', { replace: true })
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8,
      padding: '6px 24px', background: 'rgba(13,21,38,0.9)',
      borderBottom: '1px solid rgba(255,255,255,0.06)',
    }}>
      <nav style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <NavLink to="/app" end style={linkStyle}><ShieldCheck size={14} /> Dashboard</NavLink>
        {isAdmin && <NavLink to="/app/users" style={linkStyle}><Users size={14} /> Users</NavLink>}
        {isAdmin && <NavLink to="/app/audit" style={linkStyle}><ScrollText size={14} /> Audit log</NavLink>}
      </nav>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 12 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#cbd5e1' }}>
          <UserRound size={14} color="#64748b" /> {user?.email}
        </span>
        <span style={{
          fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase', fontSize: 10,
          padding: '3px 8px', borderRadius: 20,
          color: isAdmin ? '#00d4ff' : '#94a3b8',
          background: isAdmin ? 'rgba(0,212,255,0.1)' : 'rgba(148,163,184,0.1)',
          border: `1px solid ${isAdmin ? 'rgba(0,212,255,0.3)' : 'rgba(148,163,184,0.25)'}`,
        }}>{role}</span>
        <button onClick={handleSignOut} style={{
          display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(255,255,255,0.05)',
          border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, padding: '5px 10px',
          color: '#cbd5e1', fontSize: 12, cursor: 'pointer',
        }}>
          <LogOut size={13} /> Sign out
        </button>
      </div>
    </div>
  )
}
