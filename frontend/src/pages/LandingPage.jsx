/**
 * LandingPage — public entry point at "/"
 *
 * Two CTAs: "View Demo" → /demo, "Sign In" → /login
 * Short "how it works" strip and team section.
 */
import { useNavigate } from 'react-router-dom'
import { Shield, Play, LogIn, Cpu, Database, Monitor, AlertTriangle } from 'lucide-react'

function HowItWorksStep({ icon: Icon, color, title, description }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12,
      padding: 24, textAlign: 'center', flex: 1, minWidth: 180,
    }}>
      <div style={{
        width: 52, height: 52, borderRadius: 14,
        background: `${color}20`, border: `1px solid ${color}44`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <Icon size={24} color={color} />
      </div>
      <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>{title}</div>
      <div style={{ fontSize: 13, color: '#64748b', lineHeight: 1.6 }}>{description}</div>
    </div>
  )
}

export default function LandingPage() {
  const navigate = useNavigate()

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg-base)',
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      fontFamily: 'Inter, system-ui, sans-serif',
    }}>
      {/* Hero */}
      <div style={{
        width: '100%', maxWidth: 820, padding: '80px 24px 60px',
        display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 24,
      }}>
        {/* Logo */}
        <div style={{
          width: 72, height: 72, borderRadius: 20,
          background: 'linear-gradient(135deg, #7c3aed, #00d4ff)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 0 40px rgba(0,212,255,0.25)',
        }}>
          <Shield size={36} color="#fff" />
        </div>

        <div>
          <h1 style={{ fontSize: 48, fontWeight: 800, color: '#e2e8f0', lineHeight: 1.15, margin: 0,
            background: 'linear-gradient(135deg, #e2e8f0, #00d4ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            CyberSentinel
          </h1>
          <p style={{ fontSize: 18, color: '#94a3b8', marginTop: 12, lineHeight: 1.6, maxWidth: 560 }}>
            A machine-learning powered network intrusion detection and prevention system for Windows.
            Classifies live traffic in real time using a Random Forest model trained on CICIDS2017.
          </p>
        </div>

        {/* CTAs */}
        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', justifyContent: 'center' }}>
          <button
            onClick={() => navigate('/demo')}
            style={{
              background: 'linear-gradient(135deg, #00d4ff, #7c3aed)',
              border: 'none', borderRadius: 12, padding: '14px 32px',
              color: '#fff', fontSize: 15, fontWeight: 700, cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 8,
              boxShadow: '0 4px 24px rgba(0,212,255,0.3)',
              transition: 'transform 0.15s, box-shadow 0.15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 8px 32px rgba(0,212,255,0.4)' }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.boxShadow = '0 4px 24px rgba(0,212,255,0.3)' }}
          >
            <Play size={18} /> View Demo
          </button>
          <button
            onClick={() => navigate('/login')}
            style={{
              background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.15)',
              borderRadius: 12, padding: '14px 32px',
              color: '#e2e8f0', fontSize: 15, fontWeight: 700, cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 8,
              transition: 'background 0.15s',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.1)'}
            onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.06)'}
          >
            <LogIn size={18} /> Sign In
          </button>
        </div>

        <p style={{ fontSize: 12, color: '#475569' }}>
          The demo is a replay of recorded attack traffic — no engine required, no sign-in needed.
          Live monitoring requires the engine running on a Windows machine.
        </p>
      </div>

      {/* How it works */}
      <div style={{
        width: '100%', maxWidth: 900, padding: '0 24px 60px',
      }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: '#94a3b8', textAlign: 'center', marginBottom: 32, textTransform: 'uppercase', letterSpacing: '1px' }}>
          How It Works
        </h2>
        <div style={{
          display: 'flex', gap: 0, flexWrap: 'wrap',
          background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 16, overflow: 'hidden',
        }}>
          <HowItWorksStep icon={Monitor} color="#00d4ff"
            title="1 — Capture"
            description="The engine captures every packet on the Windows machine using Scapy." />
          <HowItWorksStep icon={Cpu} color="#7c3aed"
            title="2 — Classify"
            description="Flows are built from packets. 19 features are extracted and classified by Random Forest." />
          <HowItWorksStep icon={AlertTriangle} color="#ff4560"
            title="3 — Detect &amp; Block"
            description="High-confidence attacks and rule-based floods trigger a Windows Firewall block." />
          <HowItWorksStep icon={Database} color="#00e396"
            title="4 — Monitor"
            description="Detections stream to Firestore. Sign in to see your live dashboard from any browser." />
        </div>
      </div>

      {/* Team */}
      <div style={{ width: '100%', maxWidth: 900, padding: '0 24px 80px', textAlign: 'center' }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: '#94a3b8', marginBottom: 20, textTransform: 'uppercase', letterSpacing: '1px' }}>
          Team
        </h2>
        <p style={{ color: '#64748b', fontSize: 14, lineHeight: 1.8 }}>
          College mini-project · CICIDS2017 Random Forest · Firebase + Vercel · Groq AI
        </p>
      </div>
    </div>
  )
}
