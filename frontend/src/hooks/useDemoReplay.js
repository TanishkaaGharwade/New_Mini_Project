/**
 * useDemoReplay — Demo mode data hook
 *
 * Fetches /demo/replay.json, plays events one by one using their delay_ms,
 * loops when it reaches the end, and returns the same shape as useFirestoreThreats:
 *   { threats, stats, engineOnline, mode, requestUnblock, error }
 *
 * - mode is always "demo"
 * - engineOnline is always true (simulated)
 * - requestUnblock is a no-op (returns a resolved promise immediately)
 * - threats grows event by event then resets on loop
 */
import { useState, useEffect, useRef, useCallback } from 'react'

const DEMO_URL = '/demo/replay.json'

const INITIAL_STATS = {
  total_packets: 0,
  total_flows:   0,
  total_attacks: 0,
  blocked_ips:   0,
  detect_only:   false,
  model_version: 'v1',
  updated_at:    null,
}

export function useDemoReplay({ speed = 1 } = {}) {
  const [threats, setThreats]   = useState([])
  const [stats, setStats]       = useState(INITIAL_STATS)
  const [error, setError]       = useState(null)
  const [ready, setReady]       = useState(false)

  const dataRef    = useRef(null)   // { model_version, events: [...] }
  const indexRef   = useRef(0)
  const timerRef   = useRef(null)
  const speedRef   = useRef(speed)
  speedRef.current = speed

  // Fetch the replay file once
  useEffect(() => {
    let cancelled = false
    fetch(DEMO_URL)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(data => {
        if (!cancelled) {
          dataRef.current = data
          setReady(true)
        }
      })
      .catch(err => {
        if (!cancelled) setError('Could not load demo file: ' + err.message)
      })
    return () => { cancelled = true }
  }, [])

  // Play events sequentially
  useEffect(() => {
    if (!ready || !dataRef.current) return
    const events = dataRef.current.events ?? []
    if (events.length === 0) return

    const modelVersion = dataRef.current.model_version ?? 'v1'
    let cycle = 0
    // "IPs Blocked" counts distinct addresses, like the engine's stats, not blocked records
    const blockedIps = new Set()

    function scheduleNext() {
      const idx = indexRef.current % events.length
      const event = events[idx]
      const delayMs = Math.max(0, (event.delay_ms ?? 1000) / speedRef.current)

      timerRef.current = setTimeout(() => {
        // Start of a new loop: clear the previous run so counters restart from zero.
        // Done here rather than right after the last event, so that event stays visible.
        if (idx === 0 && cycle > 0) {
          blockedIps.clear()
          setThreats([])
          setStats({ ...INITIAL_STATS, model_version: modelVersion })
        }

        // Unique id per playback, used as the table row key
        const threat = { id: `demo-${cycle}-${idx}`, ...(event.threat ?? event) }

        // keep newest 100
        setThreats(prev => [threat, ...prev].slice(0, 100))

        if (threat.action === 'blocked' && threat.src_ip) blockedIps.add(threat.src_ip)
        const blockedCount = blockedIps.size

        setStats(prev => {
          return {
            ...prev,
            model_version: modelVersion,
            total_flows:   prev.total_flows + 1,
            total_attacks: prev.total_attacks + 1,
            blocked_ips:   blockedCount,
            total_packets: prev.total_packets + (threat.packet_count ?? 1),
            updated_at:    new Date().toISOString(),
          }
        })

        indexRef.current = idx + 1
        if (indexRef.current >= events.length) {
          indexRef.current = 0
          cycle += 1
        }

        scheduleNext()
      }, delayMs)
    }

    scheduleNext()
    return () => clearTimeout(timerRef.current)
  }, [ready])

  /** No-op unblock in demo mode */
  const requestUnblock = useCallback(async (_ip) => {
    return { status: 'demo', message: 'Unblock is disabled in demo mode.' }
  }, [])

  return {
    threats,
    stats,
    engineOnline: ready,
    mode: 'demo',
    requestUnblock,
    error,
  }
}
