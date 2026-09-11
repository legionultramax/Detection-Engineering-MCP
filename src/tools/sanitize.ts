// Defence against a specific, documented upstream bug.
//
// Gemma 4 does not serialise tool calls as JSON. It uses a custom format in
// which string values are wrapped in a delimiter token:
//
//     <|tool_call>call:search_detections{query:<|"|>certutil<|"|>}<tool_call|>
//
// vLLM's `gemma4` tool parser is supposed to strip those delimiters when it
// converts the call into OpenAI-shaped `tool_calls`. It does not always
// succeed: the delimiters leak into argument values, reported against
// vLLM 0.19.0 and in streaming mode.
//
//   https://github.com/vllm-project/vllm/issues/39468  (open)
//   https://github.com/vllm-project/vllm/issues/44522
//
// The consequence here is silent and bad. `search_detections` receives
// `<|"|>certutil<|"|>` instead of `certutil`, matches nothing, and answers
// "no detections found" — which a reader takes as coverage information rather
// than as a broken argument. `validate_query` receives a query wrapped in
// delimiters and reports syntax findings about characters the author never
// typed.
//
// So the delimiters are stripped, and — because a server that quietly repairs
// its input teaches nobody anything — the first occurrence is reported on
// stderr with the issue link, so the operator learns their tool parser is
// misconfigured or unpatched rather than living with degraded results.
//
// These sequences carry no meaning in any detection query, rule ID, technique
// ID or search term, so removing them cannot damage a legitimate argument.

/** The delimiter forms observed in the upstream reports. */
const GEMMA_DELIMITERS = /<\|"\|>|<\|"\||\|"\|>/g;

/** Tool-call envelope markers, in case a whole call leaks into one argument. */
const GEMMA_ENVELOPE = /<\|tool_call>|<tool_call\|>/g;

let reported = false;

function scrub(value: string): string {
  return value.replace(GEMMA_ENVELOPE, '').replace(GEMMA_DELIMITERS, '');
}

/**
 * Strip Gemma 4 tool-call delimiters from string arguments.
 *
 * Returns the original object when nothing needed changing, so the common path
 * allocates nothing. Recurses one level into arrays and plain objects, which is
 * as deep as any tool schema in this server goes.
 */
export function sanitizeToolArgs(
  toolName: string,
  args: Record<string, unknown>
): Record<string, unknown> {
  if (!args || typeof args !== 'object') return args;

  let changed = false;
  const out: Record<string, unknown> = {};

  const clean = (v: unknown): unknown => {
    if (typeof v === 'string') {
      const s = scrub(v);
      if (s !== v) changed = true;
      return s;
    }
    if (Array.isArray(v)) return v.map(clean);
    if (v && typeof v === 'object') {
      const nested: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) nested[k] = clean(val);
      return nested;
    }
    return v;
  };

  for (const [k, v] of Object.entries(args)) out[k] = clean(v);

  if (!changed) return args;

  if (!reported) {
    reported = true;
    console.error(
      `[tools] Stripped Gemma 4 tool-call delimiters from arguments to ${toolName}. ` +
      'The model or serving layer is leaking its tool-call syntax into argument values — ' +
      'see https://github.com/vllm-project/vllm/issues/39468. Arguments were repaired so the ' +
      'call could proceed, but update or reconfigure the tool-call parser: unrepaired, this ' +
      'makes searches silently return nothing.'
    );
  }
  return out;
}

/** Test hook. The warning is once-per-process by design. */
export function resetSanitizeNoticeForTests(): void {
  reported = false;
}
