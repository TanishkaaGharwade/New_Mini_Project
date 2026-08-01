import { Settings, Shield, Sliders, Server, Cpu, Database } from 'lucide-react'

export default function SettingsView() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Settings size={20} color="#7c3aed" /> Engine & System Settings
        </h1>
        <p style={{ color: '#64748b', fontSize: 13 }}>
          Configure detection parameters, flow windows, whitelisted IPs, and ML model paths
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
        {/* Card 1: Capture & Aggregation */}
        <div style={{ background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: 24 }}>
          <h3 style={{ fontSize: 15, fontWeight: 600, color: '#00d4ff', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Sliders size={16} /> Packet Flow Thresholds
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13, color: '#cbd5e1' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Flow Window Packets</span>
              <span style={{ fontFamily: 'monospace', color: '#00d4ff' }}>30 packets</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Flow Window Duration</span>
              <span style={{ fontFamily: 'monospace', color: '#00d4ff' }}>3.0 seconds</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Min Packets for Firewall Block</span>
              <span style={{ fontFamily: 'monospace', color: '#ffa500' }}>5 packets</span>
            </div>
          </div>
        </div>

        {/* Card 2: ML Model Specs */}
        <div style={{ background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: 24 }}>
          <h3 style={{ fontSize: 15, fontWeight: 600, color: '#7c3aed', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Cpu size={16} /> ML Classification Model
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13, color: '#cbd5e1' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Model Algorithm</span>
              <span style={{ fontFamily: 'monospace', color: '#7c3aed' }}>Random Forest Classifier</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Feature Dataset</span>
              <span style={{ fontFamily: 'monospace', color: '#7c3aed' }}>NSL-KDD (21 Features)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Attack Categories</span>
              <span style={{ fontFamily: 'monospace', color: '#00e396' }}>20 Multi-Class Labels</span>
            </div>
          </div>
        </div>

        {/* Card 3: Windows Firewall */}
        <div style={{ background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: 24 }}>
          <h3 style={{ fontSize: 15, fontWeight: 600, color: '#ff4560', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Shield size={16} /> Active Prevention Engine
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13, color: '#cbd5e1' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Firewall System</span>
              <span style={{ fontFamily: 'monospace', color: '#ff4560' }}>Windows advfirewall (netsh)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Never-Block Safeguards</span>
              <span style={{ fontFamily: 'monospace', color: '#00e396' }}>127.0.0.1, Gateway, Cloud subnets</span>
            </div>
          </div>
        </div>

        {/* Card 4: Backend IPC Server */}
        <div style={{ background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: 24 }}>
          <h3 style={{ fontSize: 15, fontWeight: 600, color: '#00e396', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Server size={16} /> Real-Time IPC Server
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13, color: '#cbd5e1' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Streaming Protocol</span>
              <span style={{ fontFamily: 'monospace', color: '#00e396' }}>Server-Sent Events (SSE)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: 10 }}>
              <span>Local Endpoint</span>
              <span style={{ fontFamily: 'monospace', color: '#00d4ff' }}>http://localhost:5000/events</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
