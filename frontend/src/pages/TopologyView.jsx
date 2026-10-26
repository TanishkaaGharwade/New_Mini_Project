import { Network } from 'lucide-react'
import TopologyGraph from '../components/TopologyGraph'

export default function TopologyView({ threats = [] }) {
  const activeNodes = new Set(threats.map(t => t.src_ip)).size

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, height: 'calc(100vh - 120px)' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
            <Network size={20} color="#00d4ff" /> Interactive Network Topology Graph
          </h1>
          <p style={{ color: '#64748b', fontSize: 13 }}>
            Full-screen force-directed graph mapping active host connections, attack vectors, and target node
          </p>
        </div>
        <div style={{ color: '#00d4ff', fontSize: 12, fontWeight: 600, fontFamily: 'monospace' }}>
          {activeNodes} attacking source{activeNodes !== 1 ? 's' : ''}
        </div>
      </div>

      {/* Full-screen Topology Container */}
      <div style={{ flex: 1, minHeight: 0 }}>
        <TopologyGraph threats={threats} height="100%" />
      </div>
    </div>
  )
}
