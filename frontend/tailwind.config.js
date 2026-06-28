/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'sestina': {
          'bg': '#0A0A0A',
          'surface': '#171717',
          'surface-alt': '#262626',
          'border': '#262626',
          'text': '#E5E5E5',
          'text-dim': '#737373',
        },
        'byte': {
          'null': '#262626',
          'ascii': '#D97706',
          'nop': '#DC2626',
          'opcode': '#E5E5E5',
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "'Fira Code'", "'Courier New'", 'monospace'],
      },
      animation: {
        'scanline': 'scanline 8s linear infinite',
        'glow-pulse': 'glow-pulse 2s ease-in-out infinite alternate',
        'flicker': 'flicker 0.15s infinite',
        'data-stream': 'data-stream 1.5s ease-in-out infinite',
      },
      keyframes: {
        'scanline': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'glow-pulse': {
          '0%': { opacity: '0.4' },
          '100%': { opacity: '1' },
        },
        'flicker': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.8' },
        },
        'data-stream': {
          '0%, 100%': { opacity: '0.5' },
          '50%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
