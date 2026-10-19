import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// Suppress harmless ResizeObserver loop error overlay caused by Recharts / ResponsiveContainer
window.addEventListener('error', (e) => {
  if (
    e.message?.includes('ResizeObserver') ||
    e.message?.includes('ResizeObserver loop completed')
  ) {
    e.stopImmediatePropagation()
    e.preventDefault()
  }
})

createRoot(document.getElementById('app')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
