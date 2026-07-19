/**
 * Primitive runtime guards shared by the REST and WebSocket validators.
 *
 * TypeScript interfaces do not validate JSON at runtime, so untrusted responses
 * pass through these guards before they are trusted. Finiteness is enforced
 * recursively, mirroring the backend's rejection of NaN/±Infinity in evidence
 * and threshold snapshots (docs/ALERT_SCHEMA.md §2.1).
 */

/** Raised when untrusted data does not match the expected schema. */
export class ValidationError extends Error {
  readonly path: string

  constructor(message: string, path = '') {
    super(path ? `${message} (at ${path})` : message)
    this.name = 'ValidationError'
    this.path = path
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

export function isString(value: unknown): value is string {
  return typeof value === 'string'
}

export function isEnum<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value)
}

/**
 * True when `value` is JSON-serialisable and free of non-finite numbers at every
 * nesting depth. NaN and ±Infinity are rejected, never coerced to null.
 */
export function isFiniteJson(value: unknown): boolean {
  if (value === null) return true
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return true
    case 'number':
      return Number.isFinite(value)
    case 'object':
      if (Array.isArray(value)) {
        return value.every(isFiniteJson)
      }
      if (isRecord(value)) {
        return Object.values(value).every(isFiniteJson)
      }
      return false
    default:
      return false
  }
}

// --- field accessors that throw ValidationError with a field path ------------

export function requireRecord(value: unknown, path: string): Record<string, unknown> {
  if (!isRecord(value)) throw new ValidationError('expected an object', path)
  return value
}

export function requireFiniteNumber(value: unknown, path: string): number {
  if (!isFiniteNumber(value)) throw new ValidationError('expected a finite number', path)
  return value
}

export function requireString(value: unknown, path: string): string {
  if (!isString(value)) throw new ValidationError('expected a string', path)
  return value
}

export function requireEnum<T extends string>(
  value: unknown,
  allowed: readonly T[],
  path: string,
): T {
  if (!isEnum(value, allowed)) {
    throw new ValidationError(`expected one of ${allowed.join(', ')}`, path)
  }
  return value
}

export function requireStringOrNull(value: unknown, path: string): string | null {
  if (value === null) return null
  return requireString(value, path)
}

export function requireFiniteJsonRecord(value: unknown, path: string): Record<string, unknown> {
  const record = requireRecord(value, path)
  if (!isFiniteJson(record)) {
    throw new ValidationError('contains a non-finite or non-JSON value', path)
  }
  return record
}

export function requireInteger(value: unknown, path: string): number {
  const n = requireFiniteNumber(value, path)
  if (!Number.isInteger(n)) throw new ValidationError('expected an integer', path)
  return n
}
