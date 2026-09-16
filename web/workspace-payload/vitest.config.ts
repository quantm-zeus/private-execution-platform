import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";

export default defineConfig({
  plugins: [solid()],
  resolve: {
    conditions: ["development", "browser"],
    alias: [
      // The package has no `exports` map; Node/Vitest resolution otherwise picks
      // the UMD `main`, whose `klinecharts` global is undefined in jsdom. Force
      // the ESM entry the production build already uses.
      { find: /^@klinecharts\/pro$/, replacement: "@klinecharts/pro/dist/klinecharts-pro.js" },
    ],
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    restoreMocks: true,
  },
});
