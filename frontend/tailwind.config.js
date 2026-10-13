/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#070b14',
          900: '#0a0f1d',
          850: '#0c1427',
          800: '#0f172a',
          750: '#15203b',
          700: '#1e293b',
          600: '#334155',
        },
        cyber: {
          blue: '#3b82f6',
          sky: '#38bdf8',
          cyan: '#06b6d4',
          indigo: '#6366f1',
          emerald: '#10b981',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
    },
  },
  plugins: [],
};
