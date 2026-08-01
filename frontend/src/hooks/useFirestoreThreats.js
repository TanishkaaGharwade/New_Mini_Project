import { useState, useEffect } from 'react'
import { collection, onSnapshot, query, orderBy, limit, doc } from 'firebase/firestore'
import { db } from '../firebaseConfig'
import { dummyThreats, dummyStats } from '../data/dummyThreats'

export function useFirestoreThreats() {
  const [threats, setThreats] = useState(dummyThreats)
  const [stats, setStats] = useState(dummyStats)
  const [isLive, setIsLive] = useState(false)

  useEffect(() => {
    let unsubscribeThreats
    let unsubscribeStats

    try {
      // 1. Real-time threats listener
      const q = query(collection(db, 'threats'), orderBy('timestamp', 'desc'), limit(50))
      unsubscribeThreats = onSnapshot(q, (snapshot) => {
        if (!snapshot.empty) {
          const liveThreats = snapshot.docs.map(d => ({ id: d.id, ...d.data() }))
          setThreats(liveThreats)
          setIsLive(true)
        }
      }, (err) => {
        console.warn('Firestore threats listener offline (using fallback demo data):', err.message)
      })

      // 2. Real-time stats listener
      unsubscribeStats = onSnapshot(doc(db, 'stats', 'live'), (docSnap) => {
        if (docSnap.exists()) {
          setStats(docSnap.data())
        }
      }, (err) => {
        console.warn('Firestore stats listener offline (using fallback demo data):', err.message)
      })

    } catch (e) {
      console.warn('Firestore initialization fallback to demo mode:', e)
    }

    return () => {
      if (unsubscribeThreats) unsubscribeThreats()
      if (unsubscribeStats) unsubscribeStats()
    }
  }, [])

  return { threats, stats, isLive }
}
