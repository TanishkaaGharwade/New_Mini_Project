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

/**
 * Summary of the detections on screen, sent with each question. /api/chat expects
 * an object (it rejects plain text) of at most 6,000 characters of JSON.
 */
function buildContext(threats) {
  const count = (key) => threats.reduce((acc, t) => {
    const k = t[key] ?? 'unknown'
    acc[k] = (acc[k] ?? 0) + 1
    return acc
  }, {})
  const sources = Object.entries(count('src_ip')).sort((a, b) => b[1] - a[1]).slice(0, 5)
  return {
    total_detections: threats.length,
    by_label: count('label'),
    by_action: count('action'),
    top_sources: sources.map(([ip, n]) => ({ ip, detections: n })),
    latest: threats.slice(0, 10).map(t => ({
      time: t.timestamp, src_ip: t.src_ip, dst_port: t.dst_port, protocol: t.protocol,
      label: t.label, confidence: t.confidence, trigger: t.trigger, action: t.action,
    })),
  }
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

      const data = await res.json().catch(() => ({}))
      // The server explains every refusal in data.error; show that rather than a bare status code
      if (!res.ok) {
        const fallback = res.status === 404
          ? 'The AI service is not available here (no /api/chat). Restart "npm run dev", or use the deployed site.'
          : `Server error (${res.status}).`
        throw new Error(data.error || fallback)
      }

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
