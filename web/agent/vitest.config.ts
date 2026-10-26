import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    environment: 'happy-dom',
    // happy-dom 20+ no longer runs <script> content by default; these tests inject the vendored agent.
    environmentOptions: { happyDOM: { settings: { enableJavaScriptEvaluation: true } } },
    setupFiles: ['test/setup.ts'],
  },
});
