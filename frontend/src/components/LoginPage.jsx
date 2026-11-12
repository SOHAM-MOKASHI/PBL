import { useState } from 'react';
import { Shield, KeyRound, User, Lock, ArrowRight, CheckCircle2, AlertCircle } from 'lucide-react';

export function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('soham.analyst@csoc.internal');
  const [password, setPassword] = useState('••••••••••••');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Please provide valid analyst credentials');
      return;
    }

    setIsSubmitting(true);
    setError('');

    // Seamless professional sign-in transition
    setTimeout(() => {
      setIsSubmitting(false);
      onLogin();
    }, 600);
  };

  return (
    <div className="h-screen w-full flex flex-col justify-between bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Top minimal status bar */}
      <div className="px-6 py-3 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
          <span className="font-mono text-slate-300">SYSTEM STATUS: ALL TELEMETRY INGESTION PIPELINES NOMINAL</span>
        </div>
        <div className="text-[11px] font-mono text-slate-500">
          SECURE GATEWAY v1.2.0 • PORT 8000/5173
        </div>
      </div>

      {/* Center login box */}
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          {/* Brand header */}
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 rounded-lg bg-blue-600/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Shield size={22} />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                CSOC Console
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
                  Enterprise
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Cognitive Security Operations & Incident Response Platform
              </p>
            </div>
          </div>

          {/* Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
            <div className="mb-5 pb-4 border-b border-slate-800">
              <h2 className="text-sm font-semibold text-slate-200">Analyst Sign In</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Authenticate with your organizational security credentials
              </p>
            </div>

            {error && (
              <div className="mb-4 p-3 rounded-lg bg-red-950/40 border border-red-800/60 flex items-center gap-2 text-xs text-red-400">
                <AlertCircle size={14} className="shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Analyst Identity (Email or UID)
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                    <User size={15} />
                  </div>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors font-mono"
                    placeholder="analyst@domain.com"
                    autoFocus
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-medium text-slate-300">
                    Access Token / Password
                  </label>
                  <span className="text-[11px] text-blue-400 hover:underline cursor-pointer">
                    MFA Assisted
                  </span>
                </div>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                    <KeyRound size={15} />
                  </div>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors font-mono"
                    placeholder="••••••••••••"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-1 text-xs text-slate-400">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    defaultChecked
                    className="rounded bg-slate-950 border-slate-700 text-blue-600 focus:ring-blue-500"
                  />
                  <span>Keep session active</span>
                </label>
                <span className="text-[11px] font-mono text-slate-500">Demo Role: Tier-2 Lead</span>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full mt-2 py-2.5 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white rounded-lg font-medium text-sm flex items-center justify-center gap-2 transition-all shadow-md shadow-blue-900/20 disabled:opacity-60"
              >
                {isSubmitting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    <span>Authorizing Session...</span>
                  </>
                ) : (
                  <>
                    <span>Sign In to SOC Console</span>
                    <ArrowRight size={15} />
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Project & Governance Note */}
          <div className="mt-5 p-3 rounded-lg border border-slate-800/80 bg-slate-900/40 text-center">
            <p className="text-[11px] text-slate-400">
              Project-Based Learning (PBL-2) • Cybersecurity Operations Center Prototype
            </p>
            <p className="text-[10px] text-slate-500 mt-1">
              Developed by Soham Mokashi • Guided by Department of Computer Engineering
            </p>
          </div>
        </div>
      </div>

      {/* Clean footer */}
      <div className="px-6 py-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
        <span>Restricted to authorized enterprise cyber operations personnel.</span>
        <span>All sessions cryptographically signed and audited.</span>
      </div>
    </div>
  );
}
