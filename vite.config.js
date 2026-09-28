import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

export default defineConfig({
  plugins: [react()],
  assetsInclude: ["**/*.glb"],
  server: {
    // API Email Guard chạy riêng bằng Python (server/app.py), Vite chuyển tiếp /api sang đó
    proxy: {
      "/api": { target: "http://127.0.0.1:3305", xfwd: true },
    },
  },
})
