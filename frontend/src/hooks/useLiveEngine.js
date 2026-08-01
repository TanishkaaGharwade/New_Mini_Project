import { useState, useEffect } from 'react'

const initialLiveStats = {
  totalPackets: 0,
  totalAttacks: 0,
  blockedIPs: 0,
  threatLevel: 0,
}

export function useLiveEngine() {
  const [threats, setThreats] = useState([])
  const [stats, setStats] = useState(initialLiveStats)
  const [isConnected, setIsConnected] = useState(false)

  useEffect(() => {
    let eventSource = null
    let reconnectTimeout = null

    function connect() {
      try {
        eventSource = new EventSource('http://localhost:5000/events')

        eventSource.onopen = () => {
          console.log('✅ Connected to NetSentinel Python Engine (http://localhost:5000/events)')
          setIsConnected(true)
        }

        eventSource.onmessage = (e) => {
          try {
            const message = JSON.parse(e.data)
            if (message.type === 'THREAT_EVENT' && message.data) {
              const { threat, stats: newStats } = message.data
              if (newStats) setStats(newStats)
              if (threat) {
                setThreats((prev) => {
                  // Keep top 100 live events
                  const exists = prev.some((t) => t.id === threat.id)
                  if (exists) return prev
                  return [threat, ...prev].slice(0, 100)
                })
              }
            }
          } catch (err) {
            console.error('SSE JSON parse error:', err)
          }
        }

        eventSource.onerror = () => {
          setIsConnected(false)
          eventSource?.close()
          // Retry connecting after 3 seconds
          reconnectTimeout = setTimeout(connect, 3000)
        }
      } catch (err) {
        setIsConnected(false)
        reconnectTimeout = setTimeout(connect, 3000)
      }
    }

    connect()

    return () => {
      if (eventSource) eventSource.close()
      if (reconnectTimeout) clearTimeout(reconnectTimeout)
    }
  }, [])

  const handleUnblock = async (ip) => {
    try {
      const res = await fetch('http://localhost:5000/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      })
      const data = await res.json()
      if (data.success) {
        // Update local state to show unblocked
        setThreats((prev) =>
          prev.map((t) => (t.src_ip === ip ? { ...t, blocked: false } : t))
        )
      }
      return data
    } catch (e) {
      console.error('Failed to call unblock API:', e)
      return { success: false, message: e.message }
    }
  }

  return { threats, stats, isConnected, handleUnblock }
}
