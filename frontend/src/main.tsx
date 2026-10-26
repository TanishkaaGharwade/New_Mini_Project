import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// "ResizeObserver loop completed with undelivered notifications" is a harmless browser
// warning from resizing charts. Listen in the capture phase so this runs before Vite's own
// error listener (registered earlier), which would otherwise report it as an unhandled error.
window.addEventListener('error', (e) => {
  if (e.message?.includes('ResizeObserver loop')) {
    e.stopImmediatePropagation()
    e.preventDefault()
  }
}, true)

createRoot(document.getElementById('app')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
