/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'Consolas', 'Courier New', 'monospace'],
      },
      colors: {
        threat: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          safe: '#10b981',
        },
        cyber: {
          950: '#030712',
          900: '#090d16',
          850: '#0e1524',
          800: '#151f33',
          700: '#1e293b',
          600: '#334155',
          500: '#64748b',
          emerald: '#10b981',
          cyan: '#06b6d4',
          crimson: '#f43f5e',
          amber: '#f59e0b',
          purple: '#8b5cf6',
          blue: '#3b82f6'
        }
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'radar-sweep': 'radar 3s linear infinite',
        'glow-line': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        radar: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' }
        },
        glow: {
          '0%': { opacity: '0.4', filter: 'drop-shadow(0 0 4px #06b6d4)' },
          '100%': { opacity: '1', filter: 'drop-shadow(0 0 12px #06b6d4)' }
        }
      }
    },
  },
  plugins: [],
};
