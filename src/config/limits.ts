// Response-size budget.
//
// How many rows a tool should return is a property of the *deployment*, not of
// the tool. Claude Desktop has a 200K window and 50 detection rules is a
// convenience; Gemma 4 26B-A4B served by vLLM at the recommended
// --max-model-len 16384 has a 16K window, and a single list_by_mitre call at
// the same default measured 15,874 bytes — about 4,500 tokens, 28% of the
// entire context, for one call. A realistic six-call authoring session
// consumed 90% of the window before the model wrote a token.
//
// So the cap is configurable rather than baked in, and it applies to the
// caller's explicit `limit` too. A request for 200 results is exactly the case
// that needs bounding — it is also the case a per-tool default cannot catch,
// since the tool's own default is not what was asked for.

const DEFAULT_MAX_RESULTS = 50;
const FLOOR = 1;
const CEILING = 500;

let cached: number | null = null;
let warned = false;

/**
 * The most rows any list-shaped tool may return.
 *
 * Set HAWKEYE_MAX_RESULTS to fit the context the model is actually served
 * with. Measured guidance:
 *
 *   --max-model-len   8192  ->  5   (the tool definitions alone are 55% of it)
 *   --max-model-len  16384  ->  10
 *   --max-model-len  32768  ->  15
 *   131072 and above        ->  leave unset
 *
 * An unparseable value falls back to the default and says so once, rather than
 * silently becoming NaN and letting Math.min pass everything through.
 */
export function maxResults(): number {
  if (cached !== null) return cached;

  const raw = process.env.HAWKEYE_MAX_RESULTS;
  if (raw === undefined || raw.trim() === '') {
    cached = DEFAULT_MAX_RESULTS;
    return cached;
  }

  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < FLOOR) {
    if (!warned) {
      warned = true;
      console.error(
        `[config] HAWKEYE_MAX_RESULTS="${raw}" is not a positive integer — ` +
        `using the default of ${DEFAULT_MAX_RESULTS}.`
      );
    }
    cached = DEFAULT_MAX_RESULTS;
    return cached;
  }

  cached = Math.min(n, CEILING);
  return cached;
}

/**
 * Resolve a tool's effective row limit.
 *
 * `requested` is what the caller asked for and `fallback` is the tool's own
 * default; whichever applies is then clamped by the deployment budget. The
 * budget wins in both directions, which is the point — a tool whose own
 * default is 50 returns 10 on a 16K deployment without every call site
 * needing to know that.
 */
export function resolveLimit(requested: unknown, fallback: number): number {
  const budget = maxResults();
  const n = typeof requested === 'number' && Number.isFinite(requested) && requested >= 1
    ? Math.floor(requested)
    : fallback;
  return Math.max(1, Math.min(n, budget));
}

/** Reset the cache. Tests only — the environment does not change at runtime. */
export function resetLimitCacheForTests(): void {
  cached = null;
  warned = false;
}
