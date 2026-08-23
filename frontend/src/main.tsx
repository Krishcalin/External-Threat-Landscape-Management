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
    {/* The gate hands the session down rather than the console fetching it
        again: two components asking `/auth/session` separately can disagree
        about who is signed in, and the one drawing the sign-out control must
        not be the one that is wrong. */}
    <AuthGate>{(session) => <App session={session} />}</AuthGate>
  </StrictMode>,
)
