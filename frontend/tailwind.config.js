/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: { sans: ["Inter", "system-ui", "Segoe UI", "Arial", "sans-serif"] },
      colors: {
        ink: { DEFAULT: "#0F2344", 800: "#16305A", 700: "#1E3D6E", 500: "#475569", 400: "#64748B" },
        brand: { DEFAULT: "#00A3AE", 700: "#007B83", 50: "#E6F7F8", 100: "#C7EEF0" },
        canvas: "#F4F7FB",
        line: "#E2E8F0",
        safe: { DEFAULT: "#15803D", bg: "#EAF7EE", line: "#BBE5C8" },
        warn: { DEFAULT: "#B45309", bg: "#FEF3E2", line: "#F8D9A8" },
        danger: { DEFAULT: "#C62828", bg: "#FDECEC", line: "#F5C2C2" },
        info: { DEFAULT: "#1C5CA0", bg: "#EAF2FB", line: "#C6DBF2" },
      },
      boxShadow: { card: "0 1px 2px rgba(15,35,68,.06), 0 4px 14px rgba(15,35,68,.05)" },
      keyframes: {
        pulseRing: { "0%": { transform: "scale(.9)", opacity: ".7" }, "100%": { transform: "scale(1.9)", opacity: "0" } },
        fadeUp: { "0%": { opacity: 0, transform: "translateY(6px)" }, "100%": { opacity: 1, transform: "translateY(0)" } },
      },
      animation: { pulseRing: "pulseRing 1.6s ease-out infinite", fadeUp: "fadeUp .25s ease-out both" },
    },
  },
  plugins: [],
};
