import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En développement, /api et /health sont relayés vers l'API FastAPI locale.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
