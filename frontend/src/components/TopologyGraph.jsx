import { useEffect, useRef } from 'react'
import { Network } from 'vis-network'
import { DataSet } from 'vis-data'

export default function TopologyGraph({ threats = [] }) {
  const containerRef = useRef(null)
  const networkRef = useRef(null)

  useEffect(() => {
    if (!containerRef.current) return

    // Base nodes: Target Machine (CyberSentinel Laptop)
    const nodesArray = [
      {
        id: 'target',
        label: 'CyberSentinel Machine\n(192.168.1.20)',
        shape: 'box',
        color: { background: '#0d1526', border: '#00d4ff', highlight: { background: '#0f1f38', border: '#00d4ff' } },
        font: { color: '#00d4ff', face: 'Inter', size: 12, multi: true },
        margin: 10,
        shadow: true,
      },
    ]

    const edgesArray = []
    const addedNodes = new Set(['target'])

    // Dynamically build network topology nodes & edges from threat events
    threats.forEach((threat, idx) => {
      const srcIp = threat.src_ip
      if (!srcIp) return

      const isAttack = true  // every stored record is a detection
      const isBlocked = threat.action === 'blocked'

      if (!addedNodes.has(srcIp)) {
        addedNodes.add(srcIp)
        nodesArray.push({
          id: srcIp,
          label: `${srcIp}\n[${threat.label || '?'}]`,
          shape: isAttack ? 'diamond' : 'dot',
          size: isAttack ? 18 : 12,
          color: {
            background: isBlocked ? '#ff4560' : isAttack ? '#ffa500' : '#00e396',
            border: isBlocked ? '#ff4560' : isAttack ? '#ffa500' : '#00e396',
            highlight: { background: '#ffffff', border: '#00d4ff' }
          },
          font: { color: isAttack ? '#ff4560' : '#94a3b8', face: 'Inter', size: 11, multi: true },
          shadow: isAttack,
        })
      }

      edgesArray.push({
        id: `edge-${idx}`,
        from: srcIp,
        to: 'target',
        color: {
          color: isBlocked ? 'rgba(255,69,96,0.6)' : isAttack ? 'rgba(255,165,0,0.5)' : 'rgba(0,227,150,0.3)',
          highlight: '#00d4ff',
        },
        dashes: isBlocked,
        width: isAttack ? 2 : 1,
        arrows: { to: { enabled: true, scaleFactor: 0.6 } },
      })
    })

    const data = {
      nodes: new DataSet(nodesArray),
      edges: new DataSet(edgesArray),
    }

    const options = {
      physics: {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -30,
          centralGravity: 0.01,
          springLength: 90,
          springConstant: 0.08,
        },
        stabilization: { iterations: 100 },
      },
      interaction: {
        hover: true,
        tooltipDelay: 200,
        zoomView: true,
        dragView: true,
      },
    }

    networkRef.current = new Network(containerRef.current, data, options)

    return () => {
      if (networkRef.current) {
        networkRef.current.destroy()
        networkRef.current = null
      }
    }
  }, [threats])

  return (
    <div style={{
      background: 'rgba(13,21,38,0.8)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 12,
      padding: '16px 20px',
      minWidth: 0,
      backdropFilter: 'blur(8px)',
      display: 'flex',
      flexDirection: 'column',
      height: 260,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <h3 style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Network Topology & Attack Graph
        </h3>
        <span style={{ fontSize: 11, color: '#00d4ff', fontFamily: 'monospace' }}>
          {threats.length} Active Nodes
        </span>
      </div>
      <div ref={containerRef} style={{ flex: 1, width: '100%', borderRadius: 8, background: 'rgba(5,11,26,0.6)' }} />
    </div>
  )
}
