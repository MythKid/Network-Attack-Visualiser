/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the Phase 3 backend REST API (see config.ts). */
  readonly VITE_API_BASE_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
