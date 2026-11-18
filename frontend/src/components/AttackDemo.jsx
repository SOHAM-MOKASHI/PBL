/**
 * AttackDemo.jsx — Live Attack Simulation Panel
 * Lets the examiner test the vulnerable login and launch bulk attacks
 */
import { useState } from 'react';
import { Zap, AlertTriangle, Shield, Play, User, Lock, ExternalLink } from 'lucide-react';

const API_BASE = 'http://localhost:8000';

export function AttackDemo() {
  // Manual login form state
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loginResult, setLoginResult] = useState(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // Bulk attack state
  const [attackType, setAttackType] = useState('brute_force');
  const [attackCount, setAttackCount] = useState(20);
  const [attackResult, setAttackResult] = useState(null);
  const [isAttacking, setIsAttacking] = useState(false);

  // Attack log history
  const [attackLog, setAttackLog] = useState([]);

  const handleManualLogin = async (e) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setLoginResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      setLoginResult(data);
      setAttackLog(prev => [{
        time: new Date().toLocaleTimeString(),
        type: 'Manual Login',
        input: username,
        result: data.status,
      }, ...prev].slice(0, 50));
    } catch (err) {
      setLoginResult({ status: 'error', message: 'Connection failed' });
    }
    setIsLoggingIn(false);
  };

  const handleBulkAttack = async () => {
    setIsAttacking(true);
    setAttackResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/simulate-attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: attackType, count: attackCount }),
      });
      const data = await res.json();
      setAttackResult(data);
      setAttackLog(prev => [{
        time: new Date().toLocaleTimeString(),
        type: `Bulk ${attackType}`,
        input: `${attackCount} payloads`,
        result: `${data.details?.failed || 0} blocked`,
      }, ...prev].slice(0, 50));
    } catch (err) {
      setAttackResult({ message: 'Connection failed — is the backend running?' });
    }
    setIsAttacking(false);
  };

  const quickPayloads = [
    { label: "Wrong password", u: "admin", p: "wrongpassword" },
    { label: "SQL Injection", u: "' OR '1'='1", p: "hacked" },
    { label: "XSS Attack", u: "<script>alert('xss')</script>", p: "test" },
    { label: "Valid login", u: "admin", p: "admin123" },
  ];

  return (
    <div className="space-y-4">
      {/* Header notice */}
      <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 flex items-start gap-3">
        <AlertTriangle size={18} className="text-amber-600 mt-0.5 shrink-0" />
        <div>
          <p className="text-sm font-semibold text-amber-800">Attack Simulation Environment</p>
          <p className="text-xs text-amber-700 mt-0.5">
            This panel lets you test the CSOC's real-time detection. Each login attempt flows through
            the full 4-stage pipeline — check the Dashboard and Alerts tabs to see the CSOC react in real time.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left: Manual Login Test */}
        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-8 h-8 rounded-lg bg-blue-50 flex items-center justify-center">
              <User size={16} className="text-blue-600" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-800">Manual Login Test</h3>
              <p className="text-xs text-slate-500">Try different inputs and watch CSOC react</p>
            </div>
          </div>

          {/* Quick payload buttons */}
          <div className="flex flex-wrap gap-1.5 mb-3">
            {quickPayloads.map((qp, i) => (
              <button
                key={i}
                onClick={() => { setUsername(qp.u); setPassword(qp.p); }}
                className="px-2.5 py-1 text-[11px] font-medium rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50 hover:border-slate-300 transition-colors"
              >
                {qp.label}
              </button>
            ))}
          </div>

          <form onSubmit={handleManualLogin} className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">Username</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-2.5 flex items-center text-slate-400">
                  <User size={14} />
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-8 pr-3 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white"
                  placeholder="e.g. admin, ' OR '1'='1"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-2.5 flex items-center text-slate-400">
                  <Lock size={14} />
                </div>
                <input
                  type="text"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-8 pr-3 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white"
                  placeholder="e.g. admin123, <script>alert(1)</script>"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={isLoggingIn}
              className="w-full py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition-colors disabled:opacity-50"
            >
              {isLoggingIn ? 'Sending...' : 'Send Login Request'}
            </button>
          </form>

          {loginResult && (
            <div className={`mt-3 p-3 rounded-lg text-xs ${
              loginResult.status === 'success'
                ? 'bg-emerald-50 border border-emerald-200 text-emerald-700'
                : 'bg-red-50 border border-red-200 text-red-700'
            }`}>
              <span className="font-semibold">{loginResult.status === 'success' ? '✅' : '❌'} </span>
              {loginResult.message}
              {loginResult.attempts_last_60s && (
                <span className="ml-2 text-slate-500">
                  ({loginResult.attempts_last_60s} attempts in last 60s)
                </span>
              )}
            </div>
          )}

          {/* Link to standalone page */}
          <div className="mt-3 pt-3 border-t border-slate-100">
            <a
              href="http://localhost:8000/vulnerable-login"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-700 font-medium"
            >
              <ExternalLink size={12} />
              Open standalone vulnerable login page (for external attack tools)
            </a>
          </div>
        </div>

        {/* Right: Bulk Attack Simulation */}
        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-8 h-8 rounded-lg bg-red-50 flex items-center justify-center">
              <Zap size={16} className="text-red-600" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-800">Bulk Attack Simulation</h3>
              <p className="text-xs text-slate-500">Launch automated attack bursts</p>
            </div>
          </div>

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">Attack Type</label>
              <select
                value={attackType}
                onChange={(e) => setAttackType(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="brute_force">🔑 Brute Force (Password Guessing)</option>
                <option value="sql_injection">💉 SQL Injection Payloads</option>
                <option value="xss">⚡ Cross-Site Scripting (XSS)</option>
                <option value="mixed">🎯 Mixed Attack (All Types)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Number of Payloads: <span className="text-blue-600">{attackCount}</span>
              </label>
              <input
                type="range"
                min="5"
                max="50"
                value={attackCount}
                onChange={(e) => setAttackCount(Number(e.target.value))}
                className="w-full"
              />
              <div className="flex justify-between text-[10px] text-slate-400 mt-0.5">
                <span>5 (light)</span>
                <span>25 (moderate)</span>
                <span>50 (heavy)</span>
              </div>
            </div>

            <button
              onClick={handleBulkAttack}
              disabled={isAttacking}
              className="w-full py-2.5 bg-red-600 hover:bg-red-700 text-white text-sm font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <Play size={14} />
              {isAttacking ? 'Attack in progress...' : `Launch ${attackType.replace('_', ' ')} Attack`}
            </button>
          </div>

          {attackResult && (
            <div className="mt-3 p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700">
              <span className="font-semibold">Result: </span>
              {attackResult.message}
            </div>
          )}

          {/* Info box */}
          <div className="mt-3 p-3 rounded-lg bg-blue-50 border border-blue-100 text-xs text-blue-700">
            <p className="font-semibold mb-1">How it works:</p>
            <ol className="list-decimal list-inside space-y-0.5 text-blue-600">
              <li>Each attack payload is sent as a login attempt to <code>/api/login</code></li>
              <li>The backend detects the attack type (brute force / SQLi / XSS)</li>
              <li>A network log is generated and pushed into the CSOC pipeline</li>
              <li>The 4-stage pipeline scores, classifies, and generates XAI analysis</li>
              <li>Alerts appear live on the Dashboard and Alerts tab</li>
            </ol>
          </div>
        </div>
      </div>

      {/* Attack Activity Log */}
      {attackLog.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <h4 className="text-xs font-bold text-slate-700 mb-2 flex items-center gap-1.5">
            <Shield size={13} className="text-slate-500" />
            Attack Activity Log
          </h4>
          <div className="max-h-48 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 border-b border-slate-100">
                  <th className="pb-1.5 font-semibold">Time</th>
                  <th className="pb-1.5 font-semibold">Type</th>
                  <th className="pb-1.5 font-semibold">Input</th>
                  <th className="pb-1.5 font-semibold">Result</th>
                </tr>
              </thead>
              <tbody>
                {attackLog.map((entry, i) => (
                  <tr key={i} className="border-b border-slate-50">
                    <td className="py-1.5 font-mono text-slate-500">{entry.time}</td>
                    <td className="py-1.5">{entry.type}</td>
                    <td className="py-1.5 font-mono text-slate-700 max-w-[200px] truncate">{entry.input}</td>
                    <td className="py-1.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        entry.result === 'success'
                          ? 'bg-emerald-50 text-emerald-700'
                          : 'bg-red-50 text-red-700'
                      }`}>
                        {entry.result}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
