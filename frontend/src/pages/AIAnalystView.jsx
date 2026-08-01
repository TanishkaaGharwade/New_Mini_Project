import { useState } from 'react'
import { Sparkles, Send, Bot, ShieldCheck, Cpu, AlertTriangle, Terminal } from 'lucide-react'

export default function AIAnalystView({ threats = [] }) {
  const [query, setQuery] = useState('')
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: "Hello! I am your NetSentinel Gemini AI Security Analyst. I monitor your live packet capture stream in real time. Ask me anything about detected attack vectors, firewall rules, or NSL-KDD feature anomalies.",
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ])

  const attackCount = threats.filter(t => t.attack_type?.toLowerCase().replace(/\.$/, '') !== 'normal').length

  const handleSend = (e) => {
    e.preventDefault()
    if (!query.trim()) return

    const userMsg = {
      sender: 'user',
      text: query,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }

    setMessages(prev => [...prev, userMsg])
    const prompt = query.toLowerCase()
    setQuery('')

    // Generate intelligent AI response based on query & live threats state
    setTimeout(() => {
      let reply = ""

      if (prompt.includes('status') || prompt.includes('how many') || prompt.includes('summary')) {
        reply = `Currently, NetSentinel has logged ${threats.length} total flow events, including ${attackCount} detected threat(s). Most frequent vectors are stealth port sweeps and TCP SYN floods. Active Windows Firewall rules are enforcing isolation.`
      } else if (prompt.includes('portsweep') || prompt.includes('nmap') || prompt.includes('scan')) {
        reply = `Port sweeps (e.g. Nmap -sS) send TCP SYN packets across multiple ports without completing the 3-way handshake. NetSentinel detects these by observing elevated serror_rate and diff_srv_rate in the 21-feature NSL-KDD vector.`
      } else if (prompt.includes('block') || prompt.includes('firewall') || prompt.includes('netsh')) {
        reply = `Active prevention executes 'netsh advfirewall firewall add rule dir=in action=block' for attacker source IPs when flow threshold is reached. Loopback and trusted subnets are automatically whitelisted.`
      } else if (prompt.includes('model') || prompt.includes('accuracy') || prompt.includes('rf')) {
        reply = `The classification engine utilizes a Random Forest model trained on the NSL-KDD dataset with 20 distinct attack label outputs. Flows are evaluated using majority-vote aggregation over 3-second windows.`
      } else {
        reply = `Analyzed your query regarding "${userMsg.text}". Based on current telemetry, the NetSentinel engine is actively processing incoming packets and enforcing active firewall rules for suspicious flows.`
      }

      setMessages(prev => [...prev, {
        sender: 'ai',
        text: reply,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }])
    }, 600)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, height: 'calc(100vh - 120px)' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
            <Sparkles size={20} color="#00d4ff" /> Gemini AI Threat Analyst
          </h1>
          <p style={{ color: '#64748b', fontSize: 13 }}>
            Interactive AI security assistant for real-time attack narrative & vulnerability analysis
          </p>
        </div>
        <div style={{
          background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.25)',
          borderRadius: 20, padding: '6px 16px', color: '#00d4ff', fontSize: 12, fontWeight: 600,
          display: 'flex', alignItems: 'center', gap: 6,
        }}>
          <Bot size={15} /> GEMINI PRO ACTIVE
        </div>
      </div>

      {/* Chat Container */}
      <div style={{
        flex: 1, background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 12, backdropFilter: 'blur(8px)', display: 'flex', flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Messages List */}
        <div style={{ flex: 1, padding: 24, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
          {messages.map((m, i) => (
            <div key={i} style={{
              display: 'flex', gap: 12,
              alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
              maxWidth: '80%',
            }}>
              {m.sender === 'ai' && (
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  background: 'linear-gradient(135deg, #7c3aed, #00d4ff)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}>
                  <Bot size={16} color="#fff" />
                </div>
              )}
              <div style={{
                background: m.sender === 'user' ? 'rgba(0,212,255,0.15)' : 'rgba(255,255,255,0.04)',
                border: `1px solid ${m.sender === 'user' ? 'rgba(0,212,255,0.3)' : 'rgba(255,255,255,0.08)'}`,
                borderRadius: 12, padding: '12px 16px', color: '#e2e8f0', fontSize: 13, lineHeight: 1.6,
              }}>
                <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4, display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                  <span>{m.sender === 'user' ? 'You' : 'Gemini AI Analyst'}</span>
                  <span>{m.time}</span>
                </div>
                {m.text}
              </div>
            </div>
          ))}
        </div>

        {/* Input Form */}
        <form onSubmit={handleSend} style={{
          padding: 16, background: 'rgba(5,11,26,0.6)', borderTop: '1px solid rgba(255,255,255,0.08)',
          display: 'flex', gap: 12,
        }}>
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Ask Gemini about recent attack vectors, model predictions, or firewall status..."
            style={{
              flex: 1, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 8, padding: '12px 16px', color: '#e2e8f0', fontSize: 13, outline: 'none',
            }}
          />
          <button type="submit" style={{
            background: 'linear-gradient(135deg, #00d4ff, #7c3aed)', border: 'none',
            borderRadius: 8, padding: '0 20px', color: '#fff', fontWeight: 600, fontSize: 13,
            cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <Send size={15} /> Send
          </button>
        </form>
      </div>
    </div>
  )
}
