// Vitest setup: register jest-dom matchers on Vitest's `expect` and clean up the
// React Testing Library DOM between tests. Imported via vite.config.ts test.setupFiles.
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// jsdom has no ResizeObserver; Recharts' ResponsiveContainer needs one.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver

afterEach(() => {
  cleanup()
})
