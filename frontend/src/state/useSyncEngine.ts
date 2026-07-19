/**
 * React binding for {@link SyncEngine}.
 *
 * The engine is a self-contained external store; this hook wires it to React via
 * useSyncExternalStore and manages its lifecycle. It is StrictMode-safe: the dev
 * double-invoke disposes the first engine, and the hook transparently replaces a
 * disposed engine on remount.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { useSyncExternalStore } from 'react'

import { WS_URL } from '../config.ts'
import { DEFAULT_SCOPE, type Scope } from '../types/filters.ts'
import { SyncEngine, type EngineState } from './syncEngine.ts'

function createEngine(scope: Scope): SyncEngine {
  return new SyncEngine({ wsUrl: WS_URL, scope })
}

export interface UseSyncEngineResult {
  state: EngineState
  scope: Scope
  setScope: (scope: Scope) => void
  /** Retry the REST snapshot/data plane (alert-feed error); never replaces the socket. */
  retryData: () => void
  /** Retry/replace the WebSocket connection (capped/offline/blocked). */
  retryConnection: () => void
}

export function useSyncEngine(): UseSyncEngineResult {
  const [scope, setScopeState] = useState<Scope>(DEFAULT_SCOPE)
  const scopeRef = useRef(scope)
  scopeRef.current = scope

  const [engine, setEngine] = useState<SyncEngine>(() => createEngine(DEFAULT_SCOPE))

  useEffect(() => {
    if (engine.isDisposed()) {
      // A previous StrictMode cycle disposed this engine; replace it.
      setEngine(createEngine(scopeRef.current))
      return
    }
    engine.start()
    return () => engine.dispose()
  }, [engine])

  const state = useSyncExternalStore(
    useCallback((onChange) => engine.subscribe(onChange), [engine]),
    useCallback(() => engine.getState(), [engine]),
  )

  const setScope = useCallback(
    (next: Scope) => {
      setScopeState(next)
      engine.setScope(next)
    },
    [engine],
  )

  const retryData = useCallback(() => {
    engine.retryData()
  }, [engine])

  const retryConnection = useCallback(() => {
    engine.retryConnection()
  }, [engine])

  return { state, scope, setScope, retryData, retryConnection }
}
