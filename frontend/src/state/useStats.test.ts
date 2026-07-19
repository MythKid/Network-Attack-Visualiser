import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { STATS_POLL_MS } from '../config.ts'
import { makeStats } from '../test/factories.ts'
import { useStats } from './useStats.ts'

vi.mock('../api/client.ts', () => ({ getStats: vi.fn() }))
const { getStats } = await import('../api/client.ts')
const getStatsMock = vi.mocked(getStats)

beforeEach(() => {
  getStatsMock.mockReset()
  getStatsMock.mockResolvedValue(makeStats())
})

describe('useStats', () => {
  it('loads immediately with a provenance-scoped query', async () => {
    const { result } = renderHook(({ p, n }) => useStats(p, n), {
      initialProps: { p: 'all' as const, n: 0 },
    })
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.data).not.toBeNull()
    expect(getStatsMock).toHaveBeenCalledWith({ source_type: null }, expect.any(AbortSignal))
  })

  it('refetches with the new provenance and clears data on a provenance change', async () => {
    const { result, rerender } = renderHook(({ p, n }) => useStats(p, n), {
      initialProps: { p: 'all' as 'all' | 'synthetic', n: 0 },
    })
    await waitFor(() => expect(result.current.data).not.toBeNull())
    rerender({ p: 'synthetic', n: 0 })
    await waitFor(() =>
      expect(getStatsMock).toHaveBeenCalledWith({ source_type: 'synthetic' }, expect.any(AbortSignal)),
    )
  })

  it('refetches when the reconnect nonce changes', async () => {
    const { result, rerender } = renderHook(({ p, n }) => useStats(p, n), {
      initialProps: { p: 'all' as const, n: 0 },
    })
    await waitFor(() => expect(result.current.data).not.toBeNull())
    const before = getStatsMock.mock.calls.length
    rerender({ p: 'all', n: 1 })
    await waitFor(() => expect(getStatsMock.mock.calls.length).toBeGreaterThan(before))
  })

  it('reports an error when the request fails, keeping prior data', async () => {
    getStatsMock.mockRejectedValueOnce(new Error('boom'))
    const { result } = renderHook(() => useStats('all', 0))
    await waitFor(() => expect(result.current.error).toBe(true))
  })

  it('synchronously masks the previous provenance data on a provenance change', async () => {
    getStatsMock.mockImplementation((query) =>
      query?.source_type === null
        ? Promise.resolve(makeStats()) // 'all' resolves
        : new Promise(() => {}), // 'synthetic' stays pending
    )
    const { result, rerender } = renderHook(({ p, n }) => useStats(p, n), {
      initialProps: { p: 'all' as 'all' | 'synthetic', n: 0 },
    })
    await waitFor(() => expect(result.current.data).not.toBeNull())
    rerender({ p: 'synthetic', n: 0 })
    // The synthetic fetch is still pending, but the previous 'all' data must not show.
    expect(result.current.data).toBeNull()
    expect(result.current.loading).toBe(true)
  })

  it('does not retain previous provenance data when the first new-provenance request fails', async () => {
    vi.useFakeTimers()
    try {
      let syntheticCalls = 0
      getStatsMock.mockImplementation((query) => {
        if (query?.source_type === null) return Promise.resolve(makeStats()) // 'all' loads
        syntheticCalls += 1
        // First 'synthetic' request fails; a later poll succeeds.
        return syntheticCalls === 1
          ? Promise.reject(new Error('synthetic boom'))
          : Promise.resolve(makeStats())
      })
      const { result, rerender } = renderHook(({ p, n }) => useStats(p, n), {
        initialProps: { p: 'all' as 'all' | 'synthetic', n: 0 },
      })
      await act(async () => {
        await Promise.resolve()
        await Promise.resolve()
      })
      expect(result.current.data).not.toBeNull() // 'all' loaded successfully

      rerender({ p: 'synthetic', n: 0 })
      await act(async () => {
        await Promise.resolve()
        await Promise.resolve()
      })
      // The old 'all' data must not be exposed, and it must not be stuck loading.
      expect(result.current.data).toBeNull()
      expect(result.current.loading).toBe(false)
      expect(result.current.error).toBe(true)
      expect(result.current.stale).toBe(false)

      // A later successful 'synthetic' poll recovers normally.
      await act(async () => {
        vi.advanceTimersByTime(STATS_POLL_MS)
        await Promise.resolve()
        await Promise.resolve()
      })
      expect(result.current.data).not.toBeNull()
      expect(result.current.error).toBe(false)
      expect(result.current.stale).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('retains data and marks it stale after a polling failure, clearing on success', async () => {
    vi.useFakeTimers()
    try {
      const { result } = renderHook(() => useStats('all', 0))
      await act(async () => {
        await Promise.resolve()
      })
      expect(result.current.data).not.toBeNull()
      expect(result.current.stale).toBe(false)

      getStatsMock.mockRejectedValueOnce(new Error('poll failed'))
      await act(async () => {
        vi.advanceTimersByTime(STATS_POLL_MS)
        await Promise.resolve()
      })
      expect(result.current.data).not.toBeNull() // retained
      expect(result.current.stale).toBe(true)

      await act(async () => {
        vi.advanceTimersByTime(STATS_POLL_MS)
        await Promise.resolve()
      })
      expect(result.current.stale).toBe(false) // success clears the stale flag
    } finally {
      vi.useRealTimers()
    }
  })

  it('keeps a single slow request in flight across poll ticks, never aborting or replacing it', async () => {
    vi.useFakeTimers()
    try {
      const signals: AbortSignal[] = []
      const resolvers: ((value: ReturnType<typeof makeStats>) => void)[] = []
      getStatsMock.mockImplementation((_query, signal) => {
        if (signal) signals.push(signal)
        return new Promise((resolve) => {
          resolvers.push(resolve)
        })
      })
      const { result } = renderHook(() => useStats('all', 0))
      expect(getStatsMock).toHaveBeenCalledTimes(1)

      // Two full poll intervals elapse while the first request is still pending.
      await act(async () => {
        vi.advanceTimersByTime(STATS_POLL_MS)
        await Promise.resolve()
      })
      await act(async () => {
        vi.advanceTimersByTime(STATS_POLL_MS)
        await Promise.resolve()
      })
      expect(getStatsMock).toHaveBeenCalledTimes(1) // no replacement started
      expect(signals[0].aborted).toBe(false) // the slow request was never aborted

      // Settling it starts at most ONE queued follow-up (both ticks coalesced).
      await act(async () => {
        resolvers[0](makeStats())
        await Promise.resolve()
        await Promise.resolve()
      })
      expect(result.current.data).not.toBeNull()
      expect(getStatsMock).toHaveBeenCalledTimes(2) // exactly one follow-up
      expect(signals[1].aborted).toBe(false)
      // Settling the follow-up with no further ticks starts nothing else.
      await act(async () => {
        resolvers[1](makeStats())
        await Promise.resolve()
        await Promise.resolve()
      })
      expect(getStatsMock).toHaveBeenCalledTimes(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('still aborts the superseded request on a provenance change', async () => {
    const signals: AbortSignal[] = []
    getStatsMock.mockImplementation((_query, signal) => {
      if (signal) signals.push(signal)
      return new Promise(() => {}) // stays pending
    })
    const { rerender } = renderHook(({ p, n }) => useStats(p, n), {
      initialProps: { p: 'all' as 'all' | 'synthetic', n: 0 },
    })
    expect(getStatsMock).toHaveBeenCalledTimes(1)
    rerender({ p: 'synthetic', n: 0 })
    expect(signals[0].aborted).toBe(true) // effect cleanup aborted the old scope
    expect(getStatsMock).toHaveBeenCalledTimes(2) // the new provenance request started
    expect(getStatsMock).toHaveBeenLastCalledWith(
      { source_type: 'synthetic' },
      expect.any(AbortSignal),
    )
    expect(signals[1].aborted).toBe(false)
  })

  it('polls on an interval while the tab is visible', async () => {
    vi.useFakeTimers()
    try {
      const { unmount } = renderHook(() => useStats('all', 0))
      await act(async () => {
        await Promise.resolve()
      })
      const initial = getStatsMock.mock.calls.length
      await act(async () => {
        vi.advanceTimersByTime(STATS_POLL_MS)
        await Promise.resolve()
      })
      expect(getStatsMock.mock.calls.length).toBe(initial + 1)
      unmount()
    } finally {
      vi.useRealTimers()
    }
  })
})

afterEach(() => {
  vi.useRealTimers()
})
