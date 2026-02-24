/**
 * TTL Cache Layer for Threat Intelligence Queries
 *
 * Backed by the existing `cache` table in the SQLite DB.
 * Transparent to callers — hit returns the full IntelResult<T> envelope.
 *
 * TTLs (by design):
 *   OTX     — 2 hours  (infrastructure rarely rotates inside a session)
 *   abuse.ch — 30 min  (higher churn, new uploads happen constantly)
 *
 * Cache misses and write failures are always silent — never block a query.
 */

import { runQuery, runStatement } from '../../db/connection.js';

/** TTL in seconds for OTX (AlienVault) responses */
export const OTX_TTL = 7_200;   // 2 hours

/** TTL in seconds for all abuse.ch services (URLhaus, ThreatFox, MalwareBazaar) */
export const ABUSECH_TTL = 1_800; // 30 minutes

// ---------------------------------------------------------------------------
// Core primitives
// ---------------------------------------------------------------------------

/**
 * Return a cached value by key if it exists and has not expired.
 * Returns null on miss, expiry, or any DB error.
 */
export function getCached<T>(key: string): T | null {
  try {
    const rows = runQuery<{ value: string; expires_at: string | null }>(
      'SELECT value, expires_at FROM cache WHERE key = ?',
      [key],
    );

    if (!rows[0]) return null;

    // Expiry check
    if (rows[0].expires_at !== null) {
      const expiresAt = new Date(rows[0].expires_at);
      if (expiresAt <= new Date()) {
        // Delete stale entry — best effort, ignore failures
        try {
          runStatement('DELETE FROM cache WHERE key = ?', [key]);
        } catch { /* ignore */ }
        return null;
      }
    }

    return JSON.parse(rows[0].value) as T;
  } catch {
    return null;
  }
}

/**
 * Write a value to the cache with a TTL.
 * Silently does nothing on DB error (cache write is never fatal).
 */
export function setCached(key: string, value: unknown, ttlSeconds: number): void {
  try {
    const expiresAt = new Date(Date.now() + ttlSeconds * 1_000).toISOString();
    runStatement(
      'INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)',
      [key, JSON.stringify(value), expiresAt],
    );
  } catch {
    // Non-fatal — cache write failure never prevents a real query
  }
}

/**
 * Evict all expired entries. Call this opportunistically during startup
 * or after a large pivot session.
 */
export function evictExpiredCache(): void {
  try {
    runStatement('DELETE FROM cache WHERE expires_at IS NOT NULL AND expires_at <= ?', [
      new Date().toISOString(),
    ]);
  } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// High-level wrapper — used inside abusech.ts and otx.ts
// ---------------------------------------------------------------------------

/**
 * Wraps an async function with cache check-before / write-after logic.
 *
 * On cache HIT:  returns the cached IntelResult with a fresh queried_at timestamp.
 * On cache MISS: calls fn(), caches the result if successful, and returns it.
 * On fn() error: propagates the error result un-cached.
 *
 * @param cacheKey  Unique cache key (use makeCacheKey() to build it)
 * @param fn        Async factory that performs the real API call
 * @param ttl       TTL in seconds (use OTX_TTL or ABUSECH_TTL)
 */
export async function withCache<T>(
  cacheKey: string,
  fn: () => Promise<T & { success: boolean; queried_at: string }>,
  ttl: number,
): Promise<T & { success: boolean; queried_at: string }> {
  const cached = getCached<T & { success: boolean; queried_at: string }>(cacheKey);
  if (cached !== null) {
    // Return the cached payload but stamp it with NOW so callers know it was served from cache
    return { ...cached, queried_at: new Date().toISOString() };
  }

  const result = await fn();

  // Only cache successful results — errors are transient (network down, 429, etc.)
  if (result.success) {
    setCached(cacheKey, result, ttl);
  }

  return result;
}

/**
 * Build a normalised, lowercase cache key.
 *
 * @example
 * makeCacheKey('otx', 'ip', '45.33.32.156')
 * // → 'otx:ip:45.33.32.156'
 *
 * makeCacheKey('abusech', 'urlhaus:url', 'HTTP://Evil.Com/Payload.exe')
 * // → 'abusech:urlhaus:url:http://evil.com/payload.exe'
 */
export function makeCacheKey(service: string, type: string, value: string): string {
  return `${service}:${type}:${value.toLowerCase().trim()}`;
}
