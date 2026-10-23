import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The UI calls the backend through this dev-server proxy (/api → AEGIS), so the browser talks to
// one origin and the backend needs no CORS. Point it elsewhere with AEGIS_API=http://host:port.
const backend = process.env.AEGIS_API || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": { target: backend, changeOrigin: true },
    },
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    proxy: {
      "/api": { target: backend, changeOrigin: true },
    },
  },
});
