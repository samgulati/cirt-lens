import {useAuth0} from '@auth0/auth0-react';
import {useEffect} from 'react';
import App from '../App';
import {configureAccessTokenProvider} from '../api/client';

export default function AuthGate(){
  const {isLoading,isAuthenticated,error,loginWithRedirect,getAccessTokenSilently}=useAuth0();
  useEffect(()=>{configureAccessTokenProvider(isAuthenticated?()=>getAccessTokenSilently():undefined);return()=>configureAccessTokenProvider(undefined)},[isAuthenticated,getAccessTokenSilently]);
  if(isLoading)return <main className="min-h-screen grid place-items-center bg-slate-950 text-slate-200">Establishing secure session…</main>;
  if(error)return <main className="min-h-screen grid place-items-center bg-slate-950 text-red-300">Authentication failed: {error.message}</main>;
  if(!isAuthenticated)return <main className="min-h-screen grid place-items-center bg-slate-950 text-slate-100"><section className="max-w-md text-center space-y-6"><h1 className="text-4xl font-bold">CIRT Lens</h1><p className="text-slate-400">AI-assisted security incident response with tenant-scoped access control.</p><button className="rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-slate-950" onClick={()=>loginWithRedirect()}>Sign in securely</button></section></main>;
  return <App/>;
}
