import { useState, useEffect } from 'react';
import { Shield, KeyRound, User, Lock, Terminal, Activity } from 'lucide-react';

export function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [authStatus, setAuthStatus] = useState('AWAITING_INPUT'); // AWAITING_INPUT, VERIFYING, GRANTED
  const [logs, setLogs] = useState([]);

  const handleLogin = (e) => {
    e.preventDefault();
    if (!username || !password) return;

    setIsAuthenticating(true);
    setAuthStatus('VERIFYING');
    
    // Simulate auth sequence
    const sequence = [
      'Establishing secure tunnel...',
      'Verifying operator credentials...',
      'Checking clearance level...',
      'Decrypting handshake...',
      'ACCESS GRANTED.'
    ];

    let i = 0;
    const interval = setInterval(() => {
      setLogs(prev => [...prev, sequence[i]]);
      i++;
      if (i === sequence.length) {
        clearInterval(interval);
        setAuthStatus('GRANTED');
        setTimeout(() => {
          onLogin();
        }, 800);
      }
    }, 400);
  };

  return (
    <div className="h-screen w-full flex items-center justify-center bg-cyber-bg noise-bg overflow-hidden relative">
      {/* Scanline & Grid overlays */}
      <div className="scanline-overlay z-0" />
      <div className="absolute inset-0 hex-grid opacity-30 z-0" />

      {/* Decorative background elements */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-cyan-900/10 rounded-full blur-[100px] pointer-events-none z-0" />
      
      <div className="z-10 w-full max-w-md p-6">
        {/* Header/Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="relative mb-4">
            <Shield size={64} className="text-cyan-400 animate-float" style={{ filter: 'drop-shadow(0 0 15px rgba(0,212,255,0.6))' }} />
            <div className="absolute top-0 right-0 w-4 h-4 bg-red-500 rounded-full border-2 border-cyber-bg animate-pulse" />
          </div>
          <h1 className="text-4xl font-black tracking-tight text-white glow-text-accent mb-2">
            CSOC
          </h1>
          <div className="text-xs text-slate-400 font-semibold tracking-[0.3em] uppercase">
            Restricted Access
          </div>
        </div>

        {/* Login Card */}
        <div 
          className="panel relative overflow-hidden backdrop-blur-md rounded-xl p-8 border"
          style={{
            background: 'rgba(10, 15, 30, 0.7)',
            borderColor: 'rgba(0, 212, 255, 0.2)',
            boxShadow: '0 0 40px rgba(0, 212, 255, 0.05), inset 0 0 20px rgba(0,212,255,0.02)'
          }}
        >
          {/* Top accent line */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500/0 via-cyan-400 to-cyan-500/0" />

          {authStatus === 'AWAITING_INPUT' && (
            <form onSubmit={handleLogin} className="space-y-5">
              <div className="space-y-1.5">
                <label className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                  <User size={12} /> Operator ID
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-slate-900/50 border border-slate-700 rounded p-3 pl-10 text-slate-200 font-mono text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all placeholder-slate-600"
                    placeholder="Enter ID..."
                    autoFocus
                  />
                  <Terminal size={14} className="absolute left-3 top-3.5 text-slate-500" />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                  <KeyRound size={12} /> Passkey
                </label>
                <div className="relative">
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-slate-900/50 border border-slate-700 rounded p-3 pl-10 text-slate-200 font-mono text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all placeholder-slate-600"
                    placeholder="••••••••"
                  />
                  <Lock size={14} className="absolute left-3 top-3.5 text-slate-500" />
                </div>
              </div>

              <button
                type="submit"
                className="w-full relative group overflow-hidden rounded py-3 px-4 font-mono font-bold text-sm uppercase tracking-widest transition-all mt-4"
                style={{
                  background: 'rgba(0, 212, 255, 0.1)',
                  border: '1px solid rgba(0, 212, 255, 0.4)',
                  color: '#00d4ff',
                }}
              >
                <div className="absolute inset-0 w-full h-full bg-cyan-400/20 group-hover:bg-cyan-400/30 transition-all" />
                <span className="relative flex items-center justify-center gap-2">
                  Initiate Handshake <Activity size={14} />
                </span>
              </button>
            </form>
          )}

          {/* Auth Sequence Overlay */}
          {isAuthenticating && (
            <div className="flex flex-col items-center justify-center h-48 space-y-4">
              {authStatus === 'VERIFYING' ? (
                <div className="relative">
                  <div className="w-12 h-12 border-2 border-cyan-500/20 border-t-cyan-400 rounded-full animate-spin" />
                  <Lock size={16} className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-cyan-400 animate-pulse" />
                </div>
              ) : (
                <Shield size={48} className="text-green-400 drop-shadow-[0_0_10px_rgba(0,255,136,0.8)]" />
              )}
              
              <div className="w-full bg-black/40 rounded p-3 font-mono text-[10px] text-cyan-400 text-left h-24 overflow-y-hidden flex flex-col justify-end border border-cyan-900/50">
                {logs.map((log, i) => (
                  <div key={i} className={i === logs.length - 1 ? 'animate-pulse font-bold text-white' : 'opacity-70'}>
                    > {log}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer info */}
        <div className="mt-8 text-center text-[9px] font-mono text-slate-500 uppercase tracking-widest">
          <p>Unauthorised access is strictly prohibited</p>
          <p className="mt-1">All authentication attempts are logged and monitored</p>
        </div>
      </div>
    </div>
  );
}
