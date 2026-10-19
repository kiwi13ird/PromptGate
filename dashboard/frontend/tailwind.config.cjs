/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './index.html',
    './src/**/*.{ts,tsx}',
    './components/ui/button.tsx',
    './components/ui/input.tsx',
    './components/ui/dialog.tsx',
    './components/ui/table.tsx',
    './components/ui/skeleton.tsx',
  ],
  theme: { extend: {} },
  plugins: [],
};
