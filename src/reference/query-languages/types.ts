// Shared shape for the query-language specifications.
//
// A spec exists to be handed to a model that is about to write a query in that
// language, and to drive the deterministic checks in validate_query. Everything
// here is therefore either (a) small enough to fit in a prompt without crowding
// out the actual task, or (b) machine-checkable.

/** How much a given claim can be trusted. */
export type Confidence = 'confirmed' | 'community' | 'unconfirmed';

/**
 * Whether an operator can use the engine's index.
 *
 * This is the single most useful fact about an operator for someone writing a
 * detection: an index-backed match over a large table is a lookup, and a
 * substring scan over the same table is a table scan.
 */
export interface OperatorRow {
  operator: string;
  indexed: 'yes' | 'partial' | 'no';
  use: string;
}

/** Relative expense of a construct, for reasoning about unbounded queries. */
export interface CostRow {
  cost: 'cheap' | 'medium' | 'expensive' | 'very expensive';
  construct: string;
  note?: string;
}

/**
 * A rule the validator enforces.
 *
 * Severity is graded deliberately. An unbounded time range is `blocking`
 * because it costs money and may never return; using `contains` where `has`
 * would work is a `warning` because the query is correct, only slow. Treating
 * both as errors trains a model to ignore both.
 */
export interface Prohibition {
  /** Stable identifier, so a caller can suppress or test one rule specifically. */
  id: string;
  severity: 'blocking' | 'warning';
  title: string;
  /** Why this matters — surfaced to the model so it can correct rather than guess. */
  reason: string;
  /** What to do instead. */
  fix?: string;
  /**
   * Matching a query means the rule fires. Kept as a source string rather than
   * a RegExp literal so specs stay serialisable and a spec can be returned to a
   * model as JSON.
   */
  pattern: string;
  flags?: string;
  /**
   * Fires when the pattern does NOT match. Used for "the query must contain a
   * time bound" style rules, where absence is the defect.
   */
  invert?: boolean;
}

export interface SpecExample {
  /** Rule shape this demonstrates, matched against a detection's logsource category. */
  shape: string;
  title: string;
  query: string;
  notes?: string;
}

export interface LanguageSpec {
  id: 'kql' | 'spl' | 'cql' | 'aql';
  name: string;
  engine: string;
  confidence: Confidence;
  /** Where to verify anything this spec asserts. */
  authority: string;
  /** How data is organised and how a source is selected. Prose, kept short. */
  dataModel: string;
  operators: OperatorRow[];
  cost: CostRow[];
  prohibitions: Prohibition[];
  examples: SpecExample[];
  /** Anything a generator must know that does not fit the categories above. */
  notes: string[];
}

/**
 * Principles that hold regardless of platform.
 *
 * Kept in one place rather than restated per language — three copies of the
 * same advice is three things to drift.
 */
export const SHARED_PRINCIPLES: string[] = [
  'Filter early. Reduce event volume before joins, aggregations and regex.',
  'Prefer indexed fields. Every platform distinguishes indexed from search-time-extracted.',
  'Avoid regex where a string function, wildcard or term match will do.',
  'Bound the time range to the minimum needed.',
  'Project or select only the fields you need, before joins and aggregations.',
  'Put the rare condition first, so the engine can skip non-matching events early.',
  'Test at realistic volume. Two seconds over one day can time out over thirty.',
];
