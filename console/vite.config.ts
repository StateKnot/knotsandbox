import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { target: "es2023", sourcemap: false, assetsInlineLimit: 0 },
  server: { host: "127.0.0.1", strictPort: true, port: 5173 },
  preview: { host: "127.0.0.1", strictPort: true, port: 4173 },
});
