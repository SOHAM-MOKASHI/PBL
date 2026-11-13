import { useState } from 'react';
import { Shield, Lock, User, ArrowRight, CheckCircle2 } from 'lucide-react';

export function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('soham.analyst');
  const [password, setPassword] = useState('password123');
  const [role, setRole] = useState('Student Security Analyst');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Please enter valid credentials');
      return;
    }

    setIsSubmitting(true);
    setError('');

    setTimeout(() => {
      setIsSubmitting(false);
      onLogin();
    }, 400);
  };

  return (
    <div className="min-h-screen w-full flex flex-col justify-between bg-slate-50 text-slate-800 font-sans">
      {/* Top Navigation Bar */}
      <header className="px-6 py-3.5 bg-white border-b border-slate-200 flex items-center justify-between shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center text-white font-bold shadow-sm">
            <Shield size={20} />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-900 leading-tight">
              Cognitive Security Operations Center (CSOC)
            </h1>
            <p className="text-xs text-slate-500">
              PBL-2 Project: AI-Powered Network Anomaly Detection System
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-600 bg-slate-100 px-3 py-1.5 rounded-full border border-slate-200">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>System Status: Telemetry Pipeline Ready</span>
        </div>
      </header>

      {/* Main Login Card */}
      <main className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-xl shadow-sm p-8">
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-blue-50 text-blue-600 mb-3 border border-blue-100">
              <Shield size={24} />
            </div>
            <h2 className="text-xl font-bold text-slate-900">Project Portal Sign In</h2>
            <p className="text-xs text-slate-500 mt-1">
              Sign in to monitor live network traffic and AI threat classifications
            </p>
          </div>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-600">
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Username / Analyst ID
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <User size={16} />
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-colors"
                  placeholder="Enter username"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <Lock size={16} />
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-colors"
                  placeholder="Enter password"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                User Role
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-colors"
              >
                <option value="Student Security Analyst">Student Security Analyst (Review & Triage)</option>
                <option value="Faculty / Project Evaluator">Faculty / Project Evaluator (Full Audit Access)</option>
                <option value="System Administrator">System Administrator (Threshold Calibration)</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg shadow-sm transition-colors flex items-center justify-center gap-2 disabled:opacity-60"
            >
              <span>{isSubmitting ? 'Signing in...' : 'Sign In to Dashboard'}</span>
              <ArrowRight size={16} />
            </button>
          </form>

          <div className="mt-6 pt-4 border-t border-slate-100 text-center text-xs text-slate-500">
            <p>Demo Credentials: <span className="font-mono text-slate-700">soham.analyst</span> / <span className="font-mono text-slate-700">password123</span></p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="px-6 py-3 bg-white border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-700">Developer:</span>
          <span>Soham Mokashi</span>
          <span>•</span>
          <span>SY B.Tech Computer Engineering (PBL-2)</span>
        </div>
        <div className="flex items-center gap-2">
          <span>Backend: FastAPI &amp; SQLite</span>
          <span>•</span>
          <span>AI Engine: Scikit-learn (Isolation Forest)</span>
        </div>
      </footer>
    </div>
  );
}
