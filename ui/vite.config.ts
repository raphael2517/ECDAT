import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies to the API so `npm run dev` behaves like production,
// where nginx serves the bundle on / and forwards /api to uvicorn.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
