import './index.css'
import { BrowserRouter, Navigate, Outlet, Route, Routes } from 'react-router-dom'
import AccountBar from './components/AccountBar'
import { AdminRoute, ConfigGate, ProtectedRoute } from './components/RouteGuards'
import { AuthProvider } from './context/AuthContext'
import AuditLogPage from './pages/AuditLogPage'
import DashboardPage from './pages/DashboardPage'
import LandingPage from './pages/LandingPage'
import LoginPage from './pages/LoginPage'
import UsersPage from './pages/UsersPage'
import { useFirestoreThreats } from './hooks/useFirestoreThreats'
import { useDemoReplay } from './hooks/useDemoReplay'

/** Layout for signed-in users: AccountBar on top, page below */
function SignedInLayout() {
  return (
    <ProtectedRoute>
      <AccountBar />
      <Outlet />
    </ProtectedRoute>
  )
}

/**
 * Routes:
 *  /            → LandingPage (public)
 *  /demo        → DashboardPage with useDemoReplay (public)
 *  /login       → LoginPage (public)
 *  /app         → DashboardPage with useFirestoreThreats (signed-in)
 *  /app/users   → UsersPage (admin)
 *  /app/audit   → AuditLogPage (admin)
 */
export default function App() {
  // The landing page and demo need no Firebase settings, so only the login and
  // signed-in pages sit behind ConfigGate
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/demo" element={<DashboardPage dataHook={useDemoReplay} />} />
          <Route path="/login" element={<ConfigGate><LoginPage /></ConfigGate>} />

          {/* Protected routes */}
          <Route path="/app" element={<ConfigGate><SignedInLayout /></ConfigGate>}>
            <Route index element={<DashboardPage dataHook={useFirestoreThreats} />} />
            <Route path="users" element={<AdminRoute><UsersPage /></AdminRoute>} />
            <Route path="audit" element={<AdminRoute><AuditLogPage /></AdminRoute>} />
          </Route>

          {/* Fallback → landing */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
