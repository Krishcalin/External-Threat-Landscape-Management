import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/tokens.css'
import { App } from './App'
import { AuthGate } from './components/AuthGate'

// The gate wraps the whole console rather than sitting inside it, so there is
// no arrangement of routes in which a panel renders before authentication has
// been decided.
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthGate>
      <App />
    </AuthGate>
  </StrictMode>,
)
