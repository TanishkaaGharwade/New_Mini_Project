import './index.css'
import { BrowserRouter, Navigate, Outlet, Route, Routes } from 'react-router-dom'
import AccountBar from './components/AccountBar'
import { AdminRoute, ConfigGate, ProtectedRoute } from './components/RouteGuards'
import { AuthProvider } from './context/AuthContext'
import AuditLogPage from './pages/AuditLogPage'
import DashboardPage from './pages/DashboardPage'
import LoginPage from './pages/LoginPage'
import UsersPage from './pages/UsersPage'

/** Everything under /app: signed-in users only, with the account bar on top. */
function SignedInLayout() {
  return (
    <ProtectedRoute>
      <AccountBar />
      <Outlet />
    </ProtectedRoute>
  )
}

// Routes (PART_B_CLOUD_LOGIN_AI.md, step B9). Part C adds the public landing
// page at "/" and the demo at "/demo"; until then "/" leads to the live dashboard.
export default function App() {
  return (
    <BrowserRouter>
      <ConfigGate>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/app" element={<SignedInLayout />}>
              <Route index element={<DashboardPage />} />
              <Route path="users" element={<AdminRoute><UsersPage /></AdminRoute>} />
              <Route path="audit" element={<AdminRoute><AuditLogPage /></AdminRoute>} />
            </Route>
            <Route path="*" element={<Navigate to="/app" replace />} />
          </Routes>
        </AuthProvider>
      </ConfigGate>
    </BrowserRouter>
  )
}
