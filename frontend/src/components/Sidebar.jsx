import { useNavigate } from 'react-router-dom'
import { LayoutDashboard, ShieldAlert, Network, BrainCircuit, Settings, LogOut } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

const NAV_ITEMS = [
  { icon: LayoutDashboard, label: 'Dashboard',   id: 'dashboard' },
  { icon: ShieldAlert,     label: 'Threats',     id: 'threats'   },
  { icon: Network,         label: 'Topology',    id: 'topology'  },
  { icon: BrainCircuit,    label: 'AI Analyst',  id: 'ai'        },
  { icon: Settings,        label: 'Settings',    id: 'settings'  },
]

export default function Sidebar({ active = 'dashboard', onNav, mode = 'live' }) {
  const navigate = useNavigate()
  const { signOut } = useAuth()
  const isDemo = mode === 'demo'

  // Demo: back to the landing page. Live: sign out, as the account bar does.
  const handleExit = async () => {
    if (isDemo) {
      navigate('/')
      return
    }
    await signOut()
    navigate('/login', { replace: true })
  }

  return (
    <aside style={{
      width: 220,
      // Stays in view under the 64px navbar while the page scrolls
      position: 'sticky', top: 64, alignSelf: 'flex-start',
      height: 'calc(100vh - 64px)',
      background: 'rgba(9,15,30,0.95)',
      borderRight: '1px solid rgba(255,255,255,0.07)',
      display: 'flex', flexDirection: 'column',
      padding: '16px 0',
      flexShrink: 0,
    }}>
      <nav style={{ flex: 1 }}>
        {NAV_ITEMS.map(({ icon: Icon, label, id }) => {
          const isActive = active === id
          return (
            <button
              key={id}
              onClick={() => onNav?.(id)}
              style={{
                width: '100%',
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '11px 20px',
                border: 'none',
                borderLeft: isActive ? '3px solid #00d4ff' : '3px solid transparent',
                background: isActive ? 'rgba(0,212,255,0.08)' : 'transparent',
                color: isActive ? '#00d4ff' : '#64748b',
                cursor: 'pointer',
                fontSize: 14, fontWeight: isActive ? 600 : 400,
                textAlign: 'left',
                transition: 'all 0.15s ease',
              }}
              onMouseEnter={e => { if (!isActive) e.currentTarget.style.color = '#94a3b8' }}
              onMouseLeave={e => { if (!isActive) e.currentTarget.style.color = '#64748b' }}
            >
              <Icon size={16} />
              {label}
            </button>
          )
        })}
      </nav>

      {/* Exit demo / sign out */}
      <button onClick={handleExit} style={{
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '11px 20px', border: 'none', borderLeft: '3px solid transparent',
        background: 'transparent', color: '#64748b', cursor: 'pointer',
        fontSize: 14, width: '100%', textAlign: 'left',
      }}
        onMouseEnter={e => e.currentTarget.style.color = '#ff4560'}
        onMouseLeave={e => e.currentTarget.style.color = '#64748b'}
      >
        <LogOut size={16} />
        {isDemo ? 'Exit demo' : 'Sign out'}
      </button>
    </aside>
  )
}
