import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { Auth0Provider } from '@auth0/auth0-react';
import AuthGate from './auth/AuthGate';
import './index.css';
const domain = import.meta.env.VITE_AUTH0_DOMAIN;
const clientId = import.meta.env.VITE_AUTH0_CLIENT_ID;
const audience = import.meta.env.VITE_AUTH0_AUDIENCE;
const application = (
  <BrowserRouter>
    <App />
  </BrowserRouter>
);
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {domain && clientId && audience ? (
      <Auth0Provider
        domain={domain}
        clientId={clientId}
        authorizationParams={{ redirect_uri: window.location.origin, audience }}
        cacheLocation="memory"
      >
        <BrowserRouter>
          <AuthGate />
        </BrowserRouter>
      </Auth0Provider>
    ) : (
      application
    )}
  </StrictMode>,
);
