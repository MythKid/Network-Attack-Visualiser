import { describe, expect, it } from 'vitest'

import { ALERT_PAGE_LIMIT } from '../config.ts'
import { makeAlert } from '../test/factories.ts'
import {
  admitCreated,
  applyUpdate,
  emptyAlertsState,
  installSnapshot,
  removeRow,
  selectAlerts,
} from './alertsReducer.ts'

describe('installSnapshot', () => {
  it('rebuilds membership, order and total from REST', () => {
    const a = makeAlert({ alert_id: 'a' })
    const b = makeAlert({ alert_id: 'b' })
    const state = installSnapshot(emptyAlertsState(), [a, b], 2)
    expect(state.order).toEqual(['a', 'b'])
    expect(state.total).toBe(2)
    expect(state.pendingReconcile).toBe(false)
    expect(selectAlerts(state).map((x) => x.alert_id)).toEqual(['a', 'b'])
  })

  it('drops a locally held row that is absent from the snapshot', () => {
    const local = installSnapshot(emptyAlertsState(), [makeAlert({ alert_id: 'gone' })], 1)
    const next = installSnapshot(local, [makeAlert({ alert_id: 'kept' })], 1)
    expect(next.byId.has('gone')).toBe(false)
    expect(next.order).toEqual(['kept'])
  })

  it('keeps a higher local version over a lower snapshot payload', () => {
    const local = installSnapshot(
      emptyAlertsState(),
      [makeAlert({ alert_id: 'x', occurrence_count: 5, severity: 'critical' })],
      1,
    )
    const next = installSnapshot(
      local,
      [makeAlert({ alert_id: 'x', occurrence_count: 2, severity: 'low' })],
      1,
    )
    expect(next.byId.get('x')?.occurrence_count).toBe(5)
    expect(next.byId.get('x')?.severity).toBe('critical')
  })
})

describe('admitCreated', () => {
  it('prepends a new row and marks the page pending reconcile', () => {
    const base = installSnapshot(emptyAlertsState(), [makeAlert({ alert_id: 'old' })], 1)
    const next = admitCreated(base, makeAlert({ alert_id: 'new' }))
    expect(next.order).toEqual(['new', 'old'])
    expect(next.pendingReconcile).toBe(true)
    // total is authoritative from REST only: unchanged by the optimistic insert.
    expect(next.total).toBe(1)
  })

  it('trims the page to ALERT_PAGE_LIMIT, dropping the oldest recorded', () => {
    const seed = Array.from({ length: ALERT_PAGE_LIMIT }, (_v, i) =>
      makeAlert({ alert_id: `seed-${i}` }),
    )
    let state = installSnapshot(emptyAlertsState(), seed, ALERT_PAGE_LIMIT)
    state = admitCreated(state, makeAlert({ alert_id: 'newest' }))
    expect(state.order).toHaveLength(ALERT_PAGE_LIMIT)
    expect(state.order[0]).toBe('newest')
    expect(state.byId.has(`seed-${ALERT_PAGE_LIMIT - 1}`)).toBe(false)
  })

  it('is idempotent for a duplicate created (no downgrade)', () => {
    const base = admitCreated(emptyAlertsState(), makeAlert({ alert_id: 'x', occurrence_count: 3 }))
    const dup = admitCreated(base, makeAlert({ alert_id: 'x', occurrence_count: 1 }))
    expect(dup.byId.get('x')?.occurrence_count).toBe(3)
    expect(dup.order).toEqual(['x'])
  })

  it('replaces in place for a higher-version duplicate created', () => {
    const base = admitCreated(emptyAlertsState(), makeAlert({ alert_id: 'x', occurrence_count: 1 }))
    const higher = admitCreated(base, makeAlert({ alert_id: 'x', occurrence_count: 4 }))
    expect(higher.byId.get('x')?.occurrence_count).toBe(4)
    expect(higher.order).toEqual(['x'])
  })
})

describe('applyUpdate', () => {
  it('replaces a loaded row in place for a higher version', () => {
    const base = installSnapshot(
      emptyAlertsState(),
      [makeAlert({ alert_id: 'x', occurrence_count: 1, severity: 'medium' })],
      1,
    )
    const next = applyUpdate(base, makeAlert({ alert_id: 'x', occurrence_count: 2, severity: 'high' }))
    expect(next.byId.get('x')?.severity).toBe('high')
    expect(next.order).toEqual(['x'])
  })

  it('never downgrades on a stale or equal version', () => {
    const base = installSnapshot(
      emptyAlertsState(),
      [makeAlert({ alert_id: 'x', occurrence_count: 5 })],
      1,
    )
    expect(applyUpdate(base, makeAlert({ alert_id: 'x', occurrence_count: 3 }))).toBe(base)
    expect(applyUpdate(base, makeAlert({ alert_id: 'x', occurrence_count: 5 }))).toBe(base)
  })

  it('never inserts an unknown row', () => {
    const base = installSnapshot(emptyAlertsState(), [makeAlert({ alert_id: 'x' })], 1)
    const next = applyUpdate(base, makeAlert({ alert_id: 'unknown' }))
    expect(next).toBe(base)
    expect(next.byId.has('unknown')).toBe(false)
  })
})

describe('removeRow', () => {
  it('removes a row and marks the page pending reconcile', () => {
    const base = installSnapshot(
      emptyAlertsState(),
      [makeAlert({ alert_id: 'a' }), makeAlert({ alert_id: 'b' })],
      2,
    )
    const next = removeRow(base, 'a')
    expect(next.order).toEqual(['b'])
    expect(next.byId.has('a')).toBe(false)
    expect(next.pendingReconcile).toBe(true)
  })

  it('is a no-op for an unknown id', () => {
    const base = installSnapshot(emptyAlertsState(), [makeAlert({ alert_id: 'a' })], 1)
    expect(removeRow(base, 'missing')).toBe(base)
  })
})
