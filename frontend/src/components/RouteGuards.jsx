import { Navigate, useLocation } from 'react-router-dom'
import { Loader2, ShieldOff, TriangleAlert } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { isConfigured, missingConfig } from '../firebaseConfig'

function CenteredNote({ icon: Icon, color, title, children }) {
  return (
    <div style={{
      minHeight: '60vh', display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', gap: 12, padding: 24, textAlign: 'center',
    }}>
      <Icon size={28} color={color} className={Icon === Loader2 ? 'spin' : undefined} />
      {title && <h2 style={{ fontSize: 17, fontWeight: 600, color: '#e2e8f0' }}>{title}</h2>}
      <div style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.6, maxWidth: 460 }}>{children}</div>
    </div>
  )
}

/** Shown instead of the app when the Firebase settings are missing. */
export function ConfigGate({ children }) {
  if (isConfigured) return children
  return (
    <CenteredNote icon={TriangleAlert} color="#ffa500" title="Firebase is not configured">
      <p>Sign-in cannot work until these settings are provided:</p>
      <p style={{ fontFamily: 'monospace', color: '#e2e8f0', margin: '8px 0' }}>{missingConfig.join(', ')}</p>
      <p>Copy <code>frontend/.env.example</code> to <code>frontend/.env</code>, fill it in, and restart the dev server.</p>
    </CenteredNote>
  )
}

/** Renders its children for signed-in users; sends everyone else to /login and remembers where they were going. */
export function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) return <CenteredNote icon={Loader2} color="#00d4ff">Checking your sign-in…</CenteredNote>
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  return children
}

/** Renders its children for admins only. The Firestore rules enforce the same limit on the data itself. */
export function AdminRoute({ children }) {
  const { isAdmin } = useAuth()
  if (!isAdmin) {
    return (
      <CenteredNote icon={ShieldOff} color="#ff4560" title="Admins only">
        Your account can view detections but cannot manage users or read the audit log.
        Ask an admin if you need this access.
      </CenteredNote>
    )
  }
  return children
}
