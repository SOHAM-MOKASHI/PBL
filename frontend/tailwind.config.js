/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      colors: {
        cyber: {
          bg: '#030712',
          panel: '#0a0f1e',
          card: '#0d1424',
          border: '#1a2744',
          accent: '#00d4ff',
          green: '#00ff88',
          red: '#ff2d55',
          orange: '#ff6b35',
          yellow: '#ffd700',
          purple: '#8b5cf6',
          dim: '#3d5a80',
        },
      },
      animation: {
        'pulse-fast': 'pulse 0.8s cubic-bezier(0.4,0,0.6,1) infinite',
        'flicker': 'flicker 0.15s infinite',
        'scanline': 'scanline 3s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'slide-in': 'slideIn 0.3s ease-out',
        'float': 'float 3s ease-in-out infinite',
      },
      keyframes: {
        flicker: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.85' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px #00d4ff44, 0 0 10px #00d4ff22' },
          '100%': { boxShadow: '0 0 20px #00d4ff88, 0 0 40px #00d4ff44' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-4px)' },
        },
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(0, 212, 255, 0.15)',
        'cyber-red': '0 0 30px rgba(255, 45, 85, 0.4)',
        'cyber-green': '0 0 20px rgba(0, 255, 136, 0.2)',
        'glow-accent': '0 0 15px rgba(0, 212, 255, 0.5)',
        'glow-red': '0 0 20px rgba(255, 45, 85, 0.6)',
      },
    },
  },
  plugins: [],
}
