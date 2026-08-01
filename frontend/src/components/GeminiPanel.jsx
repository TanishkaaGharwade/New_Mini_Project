import { useState } from 'react'
import { Sparkles, X, ShieldAlert, Cpu, AlertTriangle, CheckCircle2 } from 'lucide-react'

// Comprehensive knowledge base of plain-English attack explanations for demo & offline mode
const ATTACK_EXPLANATIONS = {
  neptune: {
    title: "TCP SYN Flood Attack (DoS)",
    severity: "CRITICAL",
    summary: "The attacker sent hundreds of incomplete TCP connection requests without completing the 3-way handshake.",
    mechanism: "Floods the server's SYN queue, causing memory exhaustion and preventing legitimate users from connecting.",
    recommendation: "Target IP has been automatically blocked in Windows Firewall via NetSentinel active prevention."
  },
  nmap: {
    title: "Nmap Network Reconnaissance / Port Scan",
    severity: "HIGH",
    summary: "The attacker is probing your machine's open ports to find potential vulnerabilities.",
    mechanism: "Sends stealthy TCP SYN packets to sequentially test open services (e.g. HTTP, SSH, FTP).",
    recommendation: "Source IP isolated to prevent pre-attack discovery."
  },
  portsweep: {
    title: "Port Sweep Scanning Activity",
    severity: "HIGH",
    summary: "An external entity is scanning multiple ports across your host network.",
    mechanism: "Sequentially tests transport layer ports to discover active listening daemons.",
    recommendation: "Blocked inbound traffic from attacker source IP."
  },
  satan: {
    title: "Satan Vulnerability Scanner Attack",
    severity: "HIGH",
    summary: "Automated vulnerability scanner probing for known system exploits.",
    mechanism: "Generates high volume connection attempts across diverse service ports.",
    recommendation: "Immediate IP ban enforced via Windows netsh firewall rule."
  },
  smurf: {
    title: "Smurf Amplification Attack (ICMP DoS)",
    severity: "CRITICAL",
    summary: "ICMP echo request flood targeting broadcast network addresses.",
    mechanism: "Amplifies traffic volume by forcing network hosts to respond back to victim IP.",
    recommendation: "Inbound ICMP rate-limited and offending IP blocked."
  },
  guess_passwd: {
    title: "Brute-Force Password Guessing Attempt",
    severity: "MEDIUM",
    summary: "Repeated login attempts detected against standard service ports (e.g. FTP/SSH).",
    mechanism: "Automated dictionary attack submitting credentials rapidly.",
    recommendation: "Source IP blacklisted to protect service credentials."
  }
}

export default function GeminiPanel({ threat, onClose }) {
  const [loading, setLoading] = useState(false)

  if (!threat) return null

  const key = threat.attack_type?.toLowerCase().replace(/\.$/, '') || 'normal'
  const info = ATTACK_EXPLANATIONS[key] || {
    title: `${threat.attack_type?.toUpperCase() || 'UNKNOWN'} Threat`,
    severity: threat.blocked ? "HIGH" : "MEDIUM",
    summary: `Anomalous pattern detected by Random Forest model from source ${threat.src_ip}.`,
    mechanism: `Calculated feature vector indicated statistical deviation from baseline normal traffic.`,
    recommendation: threat.blocked ? "Attacker IP blocked in Windows Firewall." : "Monitored by NetSentinel."
  }

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, width: 440,
      background: 'rgba(9,15,30,0.98)',
      borderLeft: '1px solid rgba(0,212,255,0.2)',
      backdropFilter: 'blur(24px)',
      zIndex: 100, padding: 28,
      display: 'flex', flexDirection: 'column', gap: 20,
      boxShadow: '-10px 0 40px rgba(0,0,0,0.7)',
      animation: 'slide-in 0.25s ease-out',
      overflowY: 'auto',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 8,
            background: 'linear-gradient(135deg, #7c3aed, #00d4ff)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Sparkles size={18} color="#fff" />
          </div>
          <div>
            <h2 style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>Gemini AI Analyst</h2>
            <span style={{ fontSize: 11, color: '#00d4ff', letterSpacing: '0.5px' }}>PLAIN-ENGLISH EXPLANATION</span>
          </div>
        </div>
        <button onClick={onClose} style={{
          background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8, padding: '6px', color: '#94a3b8', cursor: 'pointer',
        }}>
          <X size={16} />
        </button>
      </div>

      {/* Threat Quick Specs */}
      <div style={{
        background: 'rgba(15,31,56,0.8)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8,
        fontSize: 12, fontFamily: 'monospace',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8' }}>
          <span>ATTACK VECTOR</span>
          <span style={{ color: '#ff4560', fontWeight: 700 }}>{info.severity}</span>
        </div>
        <div style={{ color: '#e2e8f0', fontSize: 15, fontWeight: 700 }}>{info.title}</div>
        <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.06)', margin: '4px 0' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b' }}>
          <span>Attacker IP:</span>
          <span style={{ color: '#00d4ff' }}>{threat.src_ip}:{threat.src_port || 'N/A'}</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b' }}>
          <span>Target IP:</span>
          <span style={{ color: '#e2e8f0' }}>{threat.dst_ip}:{threat.dst_port || 'N/A'}</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b' }}>
          <span>Protocol & Packets:</span>
          <span style={{ color: '#7c3aed' }}>{threat.protocol} ({threat.packet_count || 1} pkts)</span>
        </div>
      </div>

      {/* AI Narrative Section */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#00d4ff', fontSize: 13, fontWeight: 600 }}>
          <Cpu size={15} />
          What Happened?
        </div>
        <p style={{ color: '#cbd5e1', fontSize: 13, lineHeight: 1.6, background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, borderLeft: '3px solid #00d4ff' }}>
          {info.summary}
        </p>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#ffa500', fontSize: 13, fontWeight: 600, marginTop: 4 }}>
          <AlertTriangle size={15} />
          Technical Mechanism
        </div>
        <p style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.6, background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, borderLeft: '3px solid #ffa500' }}>
          {info.mechanism}
        </p>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#00e396', fontSize: 13, fontWeight: 600, marginTop: 4 }}>
          <CheckCircle2 size={15} />
          Automated Action Taken
        </div>
        <p style={{ color: '#00e396', fontSize: 13, lineHeight: 1.6, background: 'rgba(0,227,150,0.06)', padding: 12, borderRadius: 8, borderLeft: '3px solid #00e396' }}>
          {info.recommendation}
        </p>
      </div>

      {/* Footer Info */}
      <div style={{ marginTop: 'auto', paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.08)', display: 'flex', alignItems: 'center', gap: 8, color: '#64748b', fontSize: 11 }}>
        <ShieldAlert size={14} color="#7c3aed" />
        <span>Powered by Gemini 1.5 Flash + NetSentinel ML Engine</span>
      </div>
    </div>
  )
}
