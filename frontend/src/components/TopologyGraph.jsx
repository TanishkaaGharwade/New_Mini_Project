import { useEffect, useRef } from 'react'
import { Network } from 'vis-network'
import { DataSet } from 'vis-data'

const TARGET_ID = 'target'

const OPTIONS = {
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

function targetNode(ip) {
  return {
    id: TARGET_ID,
    label: `Protected Machine\n(${ip || 'this host'})`,
    shape: 'box',
    color: { background: '#0d1526', border: '#00d4ff', highlight: { background: '#0f1f38', border: '#00d4ff' } },
    font: { color: '#00d4ff', face: 'Inter', size: 12, multi: true },
    margin: 10,
    shadow: true,
  }
}

// Node colour shows the action taken, not the model's confidence:
// a rate rule blocks regardless of confidence, so blocked nodes can show "rule" or a low %
const BLOCKED_COLOR = '#ff4560'
const ALERT_COLOR = '#ffa500'

function describe(threat) {
  const conf = threat.confidence != null ? `${Math.round(threat.confidence * 100)}%` : 'n/a (rule)'
  const action = threat.action === 'blocked' ? 'Blocked' : (threat.action ?? '—').replace('_', ' ')
  return `${threat.src_ip} — ${threat.label}\nAction: ${action}\nTrigger: ${threat.trigger ?? '—'}\nModel confidence: ${conf}`
}

function attackerNode(threat) {
  const color = threat.action === 'blocked' ? BLOCKED_COLOR : ALERT_COLOR
  return {
    id: threat.src_ip,
    label: `${threat.src_ip}\n[${threat.label || '?'}]`,
    title: describe(threat),   // hover tooltip
    shape: 'diamond',
    size: 18,
    color: { background: color, border: color, highlight: { background: '#ffffff', border: '#00d4ff' } },
    font: { color, face: 'Inter', size: 11, multi: true },
    shadow: true,
  }
}

function attackEdge(threat) {
  const isBlocked = threat.action === 'blocked'
  return {
    id: `edge-${threat.src_ip}`,
    from: threat.src_ip,
    to: TARGET_ID,
    color: { color: isBlocked ? 'rgba(255,69,96,0.6)' : 'rgba(255,165,0,0.5)', highlight: '#00d4ff' },
    dashes: isBlocked,
    width: 2,
    arrows: { to: { enabled: true, scaleFactor: 0.6 } },
  }
}

function LegendItem({ color, text, hint }) {
  return (
    <span title={hint} style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#94a3b8', cursor: 'help' }}>
      <span style={{ width: 8, height: 8, background: color, transform: 'rotate(45deg)', display: 'inline-block' }} />
      {text}
    </span>
  )
}

/**
 * Force-directed graph: one node per attacking source IP, each pointing at the protected machine.
 * The vis-network instance is created once; new threats update its data in place, so the graph
 * does not flicker or reset its zoom every time an event arrives.
 *
 * @param {{ threats: object[], height?: number|string }} props
 */
export default function TopologyGraph({ threats = [], height = 260 }) {
  const containerRef = useRef(null)
  const networkRef = useRef(null)
  const nodesRef = useRef(null)
  const edgesRef = useRef(null)

  // Create the network once
  useEffect(() => {
    if (!containerRef.current) return undefined
    nodesRef.current = new DataSet([targetNode(null)])
    edgesRef.current = new DataSet([])
    networkRef.current = new Network(containerRef.current, { nodes: nodesRef.current, edges: edgesRef.current }, OPTIONS)
    return () => {
      networkRef.current?.destroy()
      networkRef.current = null
    }
  }, [])

  // Sync the data: newest record per source IP wins (threats are newest first)
  useEffect(() => {
    const nodes = nodesRef.current
    const edges = edgesRef.current
    if (!nodes || !edges) return

    const latest = new Map()
    for (const t of threats) {
      if (t.src_ip && !latest.has(t.src_ip)) latest.set(t.src_ip, t)
    }

    const wanted = new Set([TARGET_ID, ...latest.keys()])
    const staleNodes = nodes.getIds().filter(id => !wanted.has(id))
    if (staleNodes.length) {
      nodes.remove(staleNodes)
      edges.remove(staleNodes.map(id => `edge-${id}`))
    }

    nodes.update([targetNode(threats[0]?.dst_ip), ...[...latest.values()].map(attackerNode)])
    edges.update([...latest.values()].map(attackEdge))
  }, [threats])

  const sourceCount = new Set(threats.map(t => t.src_ip).filter(Boolean)).size

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
      height,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <h3 style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Network Topology & Attack Graph
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 11, whiteSpace: 'nowrap' }}>
          <LegendItem color={BLOCKED_COLOR} text="Blocked"
            hint="Blocked by a rate rule (any confidence), or by the model at 90% or more" />
          <LegendItem color={ALERT_COLOR} text="Alert only"
            hint="Model detection under 90% confidence: reported, not blocked" />
          <span style={{ color: '#00d4ff', fontFamily: 'monospace' }}>
            {sourceCount} attacking source{sourceCount !== 1 ? 's' : ''}
          </span>
        </div>
      </div>
      {/* minHeight 0 + overflow hidden keep the canvas from pushing its own container bigger */}
      <div ref={containerRef} style={{ flex: 1, minHeight: 0, width: '100%', overflow: 'hidden', borderRadius: 8, background: 'rgba(5,11,26,0.6)' }} />
    </div>
  )
}
