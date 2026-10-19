import { Shield, Bell, Wifi, WifiOff, AlertTriangle, Play } from 'lucide-react'

export default function Navbar({ totalAttacks = 0, engineOnline = false, mode = 'live' }) {
  return (
    <header style={{
      background: 'rgba(5,11,26,0.95)',
      borderBottom: '1px solid rgba(255,255,255,0.08)',
      backdropFilter: 'blur(12px)',
      position: 'sticky', top: 0, zIndex: 50,
      padding: '0 24px',
      height: '64px',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    }}>
      {/* Left — Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: 'linear-gradient(135deg, #00d4ff, #7c3aed)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Shield size={18} color="#fff" />
        </div>
        <span style={{ fontSize: 18, fontWeight: 700, letterSpacing: '-0.3px' }}>
          Cyber<span style={{ color: '#00d4ff' }}>Sentinel</span>
        </span>
      </div>

      {/* Center — Status pill */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {mode === 'demo' && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'rgba(255,165,0,0.12)', border: '1px solid rgba(255,165,0,0.3)',
            borderRadius: 20, padding: '5px 14px',
            color: '#ffa500', fontSize: 12, fontWeight: 700,
          }}>
            <Play size={12} /> DEMO
          </div>
        )}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          background: engineOnline ? 'rgba(0,227,150,0.1)' : 'rgba(148,163,184,0.08)',
          border: `1px solid ${engineOnline ? 'rgba(0,227,150,0.3)' : 'rgba(148,163,184,0.2)'}`,
          borderRadius: 20, padding: '6px 16px',
        }}>
          <span className={engineOnline ? 'pulse-dot' : ''} style={{
            width: 8, height: 8, borderRadius: '50%',
            background: engineOnline ? '#00e396' : '#64748b', display: 'inline-block',
          }} />
          <span style={{ fontSize: 12, fontWeight: 600, color: engineOnline ? '#00e396' : '#94a3b8', letterSpacing: 1 }}>
            {engineOnline ? 'ENGINE ONLINE' : 'ENGINE OFFLINE'}
          </span>
          {engineOnline ? <Wifi size={13} color="#00e396" /> : <WifiOff size={13} color="#94a3b8" />}
        </div>
      </div>

      {/* Right — Actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        {totalAttacks > 0 && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            color: '#ff4560', fontSize: 13, fontWeight: 600,
          }}>
            <AlertTriangle size={15} />
            {totalAttacks} attack{totalAttacks !== 1 ? 's' : ''} detected
          </div>
        )}
        <button style={{
          background: 'none', border: '1px solid rgba(255,255,255,0.12)',
          borderRadius: 8, padding: '6px 8px', cursor: 'pointer', color: '#94a3b8',
        }}>
          <Bell size={16} />
        </button>
        <div style={{
          width: 32, height: 32, borderRadius: '50%',
          background: 'linear-gradient(135deg, #7c3aed, #00d4ff)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 12, fontWeight: 700, color: '#fff', cursor: 'pointer',
        }}>A</div>
      </div>
    </header>
  )
}
