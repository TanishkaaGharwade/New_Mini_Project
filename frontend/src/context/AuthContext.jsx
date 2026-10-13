import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import {
  onAuthStateChanged,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signOut as firebaseSignOut,
} from 'firebase/auth'
import { doc, onSnapshot } from 'firebase/firestore'
import { auth, db, isConfigured } from '../firebaseConfig'

const AuthContext = createContext(null)

/**
 * Tracks the signed-in user and their role.
 *
 * `role` is 'admin' or 'viewer'. It is read from users/{uid} and follows changes
 * live, so a role edited by an admin takes effect without a new sign-in. A user
 * with no profile document is a viewer.
 *
 * `loading` stays true until both the sign-in state and the role are known, so
 * pages can wait instead of briefly treating a returning user as signed out.
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [role, setRole] = useState(null)
  const [loading, setLoading] = useState(isConfigured)

  useEffect(() => {
    if (!isConfigured) return undefined
    let stopProfile = () => {}

    const stopAuth = onAuthStateChanged(auth, (current) => {
      stopProfile()
      if (!current) {
        setUser(null)
        setRole(null)
        setLoading(false)
        return
      }
      setLoading(true)
      setUser(current)
      stopProfile = onSnapshot(
        doc(db, 'users', current.uid),
        (snapshot) => {
          setRole(snapshot.data()?.role === 'admin' ? 'admin' : 'viewer')
          setLoading(false)
        },
        () => {
          setRole('viewer')
          setLoading(false)
        },
      )
    })

    return () => {
      stopProfile()
      stopAuth()
    }
  }, [])

  const value = useMemo(() => ({
    user,
    role,
    loading,
    isAdmin: role === 'admin',
    signIn: (email, password) => signInWithEmailAndPassword(auth, email.trim(), password),
    signOut: () => firebaseSignOut(auth),
    resetPassword: (email) => sendPasswordResetEmail(auth, email.trim()),
  }), [user, role, loading])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/** { user, role, loading, isAdmin, signIn, signOut, resetPassword } */
export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside <AuthProvider>')
  return value
}
