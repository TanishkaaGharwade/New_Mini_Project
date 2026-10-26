/**
 * AIAnalystView — AI chat page.
 *
 * Calls /api/chat with the user's Firebase ID token.
 * Disabled in demo mode and when signed out (with explanatory note).
 * All "Gemini" wording removed; uses neutral "AI Analyst" branding.
 */
import { useState, useRef, useEffect } from 'react'
import { Sparkles, Send, Bot, Lock, Radio } from 'lucide-react'
import { auth } from '../firebaseConfig'
import { useAuth } from '../context/AuthContext'

function buildContext(threats) {
  if (!threats || threats.length === 0) return 'No threats recorded yet.'
  const counts = {}
  const topIPs = {}
  threats.forEach(t => {
    counts[t.label] = (counts[t.label] ?? 0) + 1
    if (t.src_ip) topIPs[t.src_ip] = (topIPs[t.src_ip] ?? 0) + 1
  })
  const labelSummary = Object.entries(counts).map(([k, v]) => `${k}: ${v}`).join(', ')
  const ipSummary = Object.entries(topIPs).sort((a, b) => b[1] - a[1]).slice(0, 5)
    .map(([ip, n]) => `${ip} (${n})`).join(', ')
  const blockedCount = threats.filter(t => t.action === 'blocked').length
  return `Threat counts by label: ${labelSummary}. Top source IPs: ${ipSummary}. Blocked: ${blockedCount}/${threats.length} threats.`
}

export default function AIAnalystView({ threats = [], mode }) {
  const { user } = useAuth() ?? {}
  const isDemo = mode === 'demo'
  const isDisabled = isDemo || !user

  const [query, setQuery]     = useState('')
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: 'Hello! I am your CyberSentinel AI Security Analyst, powered by Groq. Ask me anything about the threats on your dashboard — attack patterns, recommended actions, or risk summaries.',
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ])
  const [loading, setLoading] = useState(false)
  const listRef = useRef(null)

  // Scroll only the message list (scrollIntoView would also scroll the whole page)
  useEffect(() => {
    const list = listRef.current
    if (list) list.scrollTo({ top: list.scrollHeight, behavior: 'smooth' })
  }, [messages, loading])

  const handleSend = async (e) => {
    e.preventDefault()
    if (!query.trim() || loading || isDisabled) return

    const userMsg = {
      sender: 'user',
      text: query,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }
    setMessages(prev => [...prev, userMsg])
    const question = query
    setQuery('')
    setLoading(true)

    try {
      const idToken = await auth?.currentUser?.getIdToken()
      const context = buildContext(threats)

      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(idToken ? { Authorization: `Bearer ${idToken}` } : {}),
        },
        body: JSON.stringify({ question, context }),
      })

      if (res.status === 401) throw new Error('Session expired. Please sign in again.')
      if (res.status === 429) throw new Error('Rate limit reached. Please wait a moment.')
      if (!res.ok) throw new Error(`Server error (${res.status}).`)

      const data = await res.json()
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: data.answer ?? '(No response)',
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }])
    } catch (err) {
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: `⚠️ ${err.message}`,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, height: 'calc(100vh - 120px)' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
            <Sparkles size={20} color="#00d4ff" /> AI Analyst
          </h1>
          <p style={{ color: '#64748b', fontSize: 13 }}>
            AI security assistant grounded in your live threat data
          </p>
        </div>
        <div style={{
          background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.25)',
          borderRadius: 20, padding: '6px 16px', color: '#00d4ff', fontSize: 12, fontWeight: 600,
          display: 'flex', alignItems: 'center', gap: 6,
        }}>
          <Radio size={14} /> AI ANALYST
        </div>
      </div>

      {/* Disabled notice */}
      {isDisabled && (
        <div style={{
          background: 'rgba(255,165,0,0.07)', border: '1px solid rgba(255,165,0,0.2)',
          borderRadius: 12, padding: '14px 20px', display: 'flex', alignItems: 'center', gap: 10,
          color: '#ffa500', fontSize: 13,
        }}>
          <Lock size={16} />
          {isDemo
            ? 'AI chat is disabled in demo mode. Sign in to use the AI Analyst with live data.'
            : 'Sign in to use the AI Analyst.'}
        </div>
      )}

      {/* Chat container */}
      <div style={{
        flex: 1, background: 'rgba(13,21,38,0.8)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 12, backdropFilter: 'blur(8px)', display: 'flex', flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Messages */}
        <div ref={listRef} style={{ flex: 1, padding: 24, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
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
                  <span>{m.sender === 'user' ? 'You' : 'AI Analyst'}</span>
                  <span>{m.time}</span>
                </div>
                {m.text}
              </div>
            </div>
          ))}
          {loading && (
            <div style={{ display: 'flex', gap: 12, alignSelf: 'flex-start', maxWidth: '80%' }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: 'linear-gradient(135deg, #7c3aed, #00d4ff)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <Bot size={16} color="#fff" />
              </div>
              <div style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '12px 16px', color: '#64748b', fontSize: 13 }}>
                Thinking…
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <form onSubmit={handleSend} style={{
          padding: 16, background: 'rgba(5,11,26,0.6)', borderTop: '1px solid rgba(255,255,255,0.08)',
          display: 'flex', gap: 12,
        }}>
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            disabled={isDisabled || loading}
            placeholder={isDisabled ? 'Sign in to use the AI Analyst…' : 'Ask about recent threats, attack patterns, or recommended actions…'}
            style={{
              flex: 1, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 8, padding: '12px 16px', color: '#e2e8f0', fontSize: 13, outline: 'none',
              opacity: isDisabled ? 0.5 : 1, cursor: isDisabled ? 'not-allowed' : 'text',
            }}
          />
          <button type="submit" disabled={isDisabled || loading} style={{
            background: isDisabled ? 'rgba(255,255,255,0.1)' : 'linear-gradient(135deg, #00d4ff, #7c3aed)',
            border: 'none', borderRadius: 8, padding: '0 20px', color: '#fff',
            fontWeight: 600, fontSize: 13, cursor: isDisabled ? 'not-allowed' : 'pointer',
            display: 'flex', alignItems: 'center', gap: 6, opacity: isDisabled ? 0.5 : 1,
          }}>
            <Send size={15} /> Send
          </button>
        </form>
      </div>
    </div>
  )
}
