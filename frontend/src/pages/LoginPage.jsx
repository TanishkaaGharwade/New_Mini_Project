import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Loader2, LogIn, Shield } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

// Firebase error codes → what the person should know. Wrong email and wrong
// password share one message so the form does not reveal which accounts exist.
const MESSAGES = {
  'auth/invalid-credential': 'Email or password is incorrect.',
  'auth/wrong-password': 'Email or password is incorrect.',
  'auth/user-not-found': 'Email or password is incorrect.',
  'auth/invalid-email': 'Enter a valid email address.',
  'auth/missing-password': 'Enter your password.',
  'auth/user-disabled': 'This account has been disabled. Ask an admin.',
  'auth/too-many-requests': 'Too many failed attempts. Wait a few minutes, or reset your password.',
  'auth/network-request-failed': 'Could not reach the sign-in service. Check your internet connection.',
}

const inputStyle = {
  width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: 8, padding: '11px 14px', color: '#e2e8f0', fontSize: 14, outline: 'none',
}
const labelStyle = { display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 6, fontWeight: 500 }

export default function LoginPage() {
  const { user, loading, signIn, resetPassword } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const destination = location.state?.from || '/app'

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  if (!loading && user) return <Navigate to={destination} replace />

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setNotice('')
    setBusy(true)
    try {
      await signIn(email, password)
      navigate(destination, { replace: true })
    } catch (err) {
      setError(MESSAGES[err.code] || 'Sign-in failed. Try again.')
    } finally {
      setBusy(false)
    }
  }

  const handleReset = async () => {
    setError('')
    setNotice('')
    if (!email.trim()) {
      setError('Enter your email address first, then choose "Forgot password".')
      return
    }
    try {
      await resetPassword(email)
    } catch (err) {
      if (err.code === 'auth/invalid-email' || err.code === 'auth/network-request-failed') {
        setError(MESSAGES[err.code])
        return
      }
      // Any other failure (such as no account for this address) shows the same notice as success
    }
    setNotice('If an account exists for that address, a password reset email is on its way.')
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg-base)', padding: 20,
    }}>
      <form onSubmit={handleSubmit} noValidate style={{
        width: '100%', maxWidth: 400, background: 'rgba(13,21,38,0.85)',
        border: '1px solid rgba(255,255,255,0.08)', borderRadius: 14, padding: 32,
        backdropFilter: 'blur(12px)', display: 'flex', flexDirection: 'column', gap: 18,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 40, height: 40, borderRadius: 9, flexShrink: 0,
            background: 'linear-gradient(135deg, #00d4ff, #7c3aed)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={20} color="#fff" />
          </div>
          <div>
            <h1 style={{ fontSize: 19, fontWeight: 700 }}>
              Cyber<span style={{ color: '#00d4ff' }}>Sentinel</span>
            </h1>
            <p style={{ fontSize: 12, color: '#64748b' }}>Sign in to the live dashboard</p>
          </div>
        </div>

        <div>
          <label htmlFor="email" style={labelStyle}>Email</label>
          <input
            id="email" type="email" autoComplete="username" autoFocus required
            value={email} onChange={(e) => setEmail(e.target.value)} style={inputStyle}
          />
        </div>

        <div>
          <label htmlFor="password" style={labelStyle}>Password</label>
          <input
            id="password" type="password" autoComplete="current-password" required
            value={password} onChange={(e) => setPassword(e.target.value)} style={inputStyle}
          />
        </div>

        {error && (
          <p role="alert" style={{
            fontSize: 13, color: '#ff8a9b', background: 'rgba(255,69,96,0.08)',
            border: '1px solid rgba(255,69,96,0.25)', borderRadius: 8, padding: '10px 12px',
          }}>{error}</p>
        )}
        {notice && (
          <p role="status" style={{
            fontSize: 13, color: '#7be8c0', background: 'rgba(0,227,150,0.07)',
            border: '1px solid rgba(0,227,150,0.25)', borderRadius: 8, padding: '10px 12px',
          }}>{notice}</p>
        )}

        <button type="submit" disabled={busy} style={{
          background: 'linear-gradient(135deg, #00d4ff, #7c3aed)', border: 'none', borderRadius: 8,
          padding: '12px 16px', color: '#fff', fontWeight: 600, fontSize: 14,
          cursor: busy ? 'wait' : 'pointer', opacity: busy ? 0.7 : 1,
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
        }}>
          {busy ? <Loader2 size={16} className="spin" /> : <LogIn size={16} />}
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        <button type="button" onClick={handleReset} style={{
          background: 'none', border: 'none', color: '#00d4ff', fontSize: 13, cursor: 'pointer',
          alignSelf: 'center', padding: 4,
        }}>
          Forgot password?
        </button>

        <p style={{ fontSize: 12, color: '#64748b', textAlign: 'center', lineHeight: 1.5 }}>
          Accounts are created by an admin. There is no public sign-up.
        </p>
      </form>
    </div>
  )
}
