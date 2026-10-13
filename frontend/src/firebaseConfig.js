import { initializeApp, getApps, getApp } from 'firebase/app'
import { getAuth } from 'firebase/auth'
import { getFirestore } from 'firebase/firestore'

// Values come from frontend/.env locally and from the host's environment variables
// when deployed (see frontend/.env.example). They are not secret: the Firestore
// security rules are what protect the data.
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
}

const REQUIRED = {
  apiKey: 'VITE_FIREBASE_API_KEY',
  authDomain: 'VITE_FIREBASE_AUTH_DOMAIN',
  projectId: 'VITE_FIREBASE_PROJECT_ID',
  appId: 'VITE_FIREBASE_APP_ID',
}

// Names of the settings that are missing; empty when the app is configured
export const missingConfig = Object.entries(REQUIRED)
  .filter(([key]) => !firebaseConfig[key])
  .map(([, name]) => name)

export const isConfigured = missingConfig.length === 0

const app = isConfigured ? (getApps().length > 0 ? getApp() : initializeApp(firebaseConfig)) : null

export const auth = app ? getAuth(app) : null
export const db = app ? getFirestore(app) : null
