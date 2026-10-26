import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS = {
  TCP:   '#00d4ff',
  UDP:   '#7c3aed',
  ICMP:  '#ffa500',
  OTHER: '#64748b',
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const { name, value } = payload[0]
  return (
    <div style={{
      background: '#0d1526', border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: 8, padding: '8px 14px', fontSize: 13,
    }}>
      <span style={{ color: COLORS[name] || '#fff', fontWeight: 600 }}>{name}</span>
      <span style={{ color: '#94a3b8', marginLeft: 8 }}>{value} pkts</span>
    </div>
  )
}

export default function ProtocolChart({ threats = [] }) {
  // Compute protocol distribution from threats array
  const counts = threats.reduce((acc, t) => {
    const p = (t.protocol || 'OTHER').toUpperCase()
    acc[p] = (acc[p] || 0) + (t.packet_count || 1)
    return acc
  }, { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 })

  const data = Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  if (data.length === 0) {
    data.push({ name: 'TCP', value: 1 }) // default placeholder
  }

  return (
    <div style={{
      background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 12, padding: '20px 24px', minWidth: 0,
      backdropFilter: 'blur(8px)',
    }}>
      <h3 style={{ fontSize: 14, fontWeight: 600, color: '#94a3b8', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        Protocol Distribution
      </h3>
      {/* debounce moves the resize out of the ResizeObserver callback, avoiding "ResizeObserver loop" errors */}
      <ResponsiveContainer width="100%" height={220} debounce={50}>
        <PieChart>
          <Pie
            data={data}
            cx="50%" cy="50%"
            innerRadius={55} outerRadius={85}
            paddingAngle={3}
            dataKey="value"
          >
            {data.map(({ name }) => (
              <Cell key={name} fill={COLORS[name] || '#64748b'} stroke="transparent" />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            formatter={(value) => (
              <span style={{ color: '#94a3b8', fontSize: 12 }}>{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
