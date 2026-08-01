import { Package, ShieldX, ShieldOff, TrendingUp } from 'lucide-react'

const CARDS = [
  {
    id: 'totalPackets',
    label: 'Total Packets',
    icon: Package,
    color: '#00d4ff',
    bgGlow: 'rgba(0,212,255,0.08)',
    border: 'rgba(0,212,255,0.2)',
    format: v => v?.toLocaleString() ?? '0',
  },
  {
    id: 'totalAttacks',
    label: 'Attacks Detected',
    icon: ShieldX,
    color: '#ff4560',
    bgGlow: 'rgba(255,69,96,0.08)',
    border: 'rgba(255,69,96,0.2)',
    format: v => v?.toLocaleString() ?? '0',
  },
  {
    id: 'blockedIPs',
    label: 'IPs Blocked',
    icon: ShieldOff,
    color: '#ffa500',
    bgGlow: 'rgba(255,165,0,0.08)',
    border: 'rgba(255,165,0,0.2)',
    format: v => v?.toLocaleString() ?? '0',
  },
  {
    id: 'threatLevel',
    label: 'Threat Level',
    icon: TrendingUp,
    color: '#00e396',
    bgGlow: 'rgba(0,227,150,0.08)',
    border: 'rgba(0,227,150,0.2)',
    format: v => `${v ?? '0'}%`,
  },
]

export default function StatCards({ stats }) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(4, 1fr)',
      gap: 16,
      marginBottom: 24,
    }}>
      {CARDS.map(({ id, label, icon: Icon, color, bgGlow, border, format }) => (
        <div key={id} style={{
          background: bgGlow,
          border: `1px solid ${border}`,
          borderRadius: 12,
          padding: '20px 24px',
          display: 'flex', flexDirection: 'column', gap: 12,
          backdropFilter: 'blur(8px)',
          transition: 'transform 0.2s ease, box-shadow 0.2s ease',
          cursor: 'default',
        }}
          onMouseEnter={e => {
            e.currentTarget.style.transform = 'translateY(-2px)'
            e.currentTarget.style.boxShadow = `0 8px 32px ${border}`
          }}
          onMouseLeave={e => {
            e.currentTarget.style.transform = 'translateY(0)'
            e.currentTarget.style.boxShadow = 'none'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: 12, fontWeight: 500, color: '#64748b', letterSpacing: '0.5px', textTransform: 'uppercase' }}>
              {label}
            </span>
            <div style={{
              width: 32, height: 32, borderRadius: 8,
              background: `${color}20`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Icon size={16} color={color} />
            </div>
          </div>
          <div style={{ fontSize: 32, fontWeight: 700, color, lineHeight: 1, letterSpacing: '-1px' }}
            className="count-up"
          >
            {format(stats?.[id])}
          </div>
        </div>
      ))}
    </div>
  )
}
