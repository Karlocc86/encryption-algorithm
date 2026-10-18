import { defineConfig } from 'vitest/config';

// base './' para que dist/ se abra desde cualquier carpeta
export default defineConfig({
  base: './',
  test: { environment: 'node' },
});
