/**
 * useFirestoreThreats — Live mode data hook
 *
 * Returns { threats, stats, engineOnline, mode, requestUnblock, error }
 *
 * - threats  : newest-first array of threat records (Firestore contract format)
 * - stats    : mapped stats/live document fields
 * - engineOnline : true when stats/live.updated_at is < 2 minutes old
 * - mode     : always "live"
 * - requestUnblock(ip) : creates a commands/{id} document; returns a listener
 *                         that resolves with { status, message }
 * - error    : string if Firestore is unreachable
 *
 * NO dummy data fallback — if Firestore is unreachable the error state is set.
 */
import { useState, useEffect, useCallback } from 'react'
import {
  collection, onSnapshot, query, orderBy, limit, doc, where,
  addDoc, serverTimestamp,
} from 'firebase/firestore'
import { db, auth } from '../firebaseConfig'

/** Map Firestore stats/live field names → component-friendly names */
function mapStats(raw) {
  return {
    total_packets: raw?.total_packets ?? 0,
    total_flows:   raw?.total_flows   ?? 0,
    total_attacks: raw?.total_attacks ?? 0,
    blocked_ips:   raw?.blocked_ips   ?? 0,
    detect_only:   raw?.detect_only   ?? false,
    model_version: raw?.model_version ?? 'v1',
    updated_at:    raw?.updated_at    ?? null,
  }
}

/** Engine is online when the heartbeat is < 2 minutes old */
function checkOnline(updatedAt) {
  if (!updatedAt) return false
  const ts = updatedAt?.toDate ? updatedAt.toDate() : new Date(updatedAt)
  return Date.now() - ts.getTime() < 2 * 60 * 1000
}

/**
 * @param {{ sinceHours?: number|null }} options
 *   sinceHours — only detections from the last N hours; null or 0 for all of them.
 *   Records carry an ISO-8601 UTC timestamp string, which sorts like the time itself.
 */
export function useFirestoreThreats({ sinceHours = 24 } = {}) {
  const [threats, setThreats]           = useState([])
  const [stats, setStats]               = useState(mapStats(null))
  const [engineOnline, setEngineOnline] = useState(false)
  const [error, setError]               = useState(null)

  // The heartbeat only arrives while the engine runs, so a stopped engine sends
  // nothing. Re-check its age on a timer, or the badge would stay "online" forever.
  useEffect(() => {
    const id = setInterval(() => setEngineOnline(checkOnline(stats.updated_at)), 30_000)
    return () => clearInterval(id)
  }, [stats.updated_at])

  useEffect(() => {
    if (!db) {
      setError('Firebase is not configured. Check your .env file.')
      return
    }

    // --- Threats listener (latest 100 in the chosen window, newest first) ---
    const window = sinceHours
      ? [where('timestamp', '>=', new Date(Date.now() - sinceHours * 3600_000).toISOString().slice(0, 19) + 'Z')]
      : []
    const q = query(
      collection(db, 'threats'),
      ...window,
      orderBy('timestamp', 'desc'),
      limit(100),
    )
    const unsubThreats = onSnapshot(
      q,
      (snap) => {
        setThreats(snap.docs.map(d => ({ id: d.id, ...d.data() })))
        setError(null)
      },
      (err) => {
        console.error('Firestore threats listener error:', err.message)
        setError('Cannot reach Firestore: ' + err.message)
      },
    )

    // --- Stats / heartbeat listener ---
    const unsubStats = onSnapshot(
      doc(db, 'stats', 'live'),
      (snap) => {
        if (snap.exists()) {
          const raw = snap.data()
          setStats(mapStats(raw))
          setEngineOnline(checkOnline(raw.updated_at))
        } else {
          setEngineOnline(false)
        }
      },
      (err) => {
        console.warn('Firestore stats listener error:', err.message)
        setEngineOnline(false)
      },
    )

    return () => {
      unsubThreats()
      unsubStats()
    }
  }, [sinceHours])

  /**
   * requestUnblock(ip) — write a commands document and watch for status change.
   * Returns a promise that resolves with { status: 'done'|'failed', message? }
   * or rejects if the timeout is reached.
   */
  const requestUnblock = useCallback(async (ip) => {
    if (!db || !auth?.currentUser) throw new Error('Not signed in')

    const docRef = await addDoc(collection(db, 'commands'), {
      action:       'unblock',
      ip,
      requested_by: auth.currentUser.uid,
      requested_at: serverTimestamp(),
      status:       'pending',
    })

    // Poll / listen for status change (up to 25 seconds)
    return new Promise((resolve, reject) => {
      const TIMEOUT = 25_000
      let settled   = false

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true
          unsub()
          reject(new Error('Engine not responding'))
        }
      }, TIMEOUT)

      const unsub = onSnapshot(docRef, (snap) => {
        const data = snap.data()
        if (data?.status === 'done' || data?.status === 'failed') {
          settled = true
          clearTimeout(timer)
          unsub()
          resolve({ status: data.status, message: data.message })
        }
      })
    })
  }, [])

  return { threats, stats, engineOnline, mode: 'live', requestUnblock, error }
}
