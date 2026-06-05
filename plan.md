# Header Fuzz Support Plan

## Goals

1. Allow selected request headers to enter `parameter_pool` as fuzzable parameters.
2. Support `HEADER` parameters in attack generation and parameter combinations.
3. Allow the Param Recommender to recommend header values from the parameter pool.
4. Improve user workflow so `Users -> Headers` provides the base identity headers and `Match/Replace` can override specific headers afterward.

## Design

### Global Header Fuzz Keys

- Add one global `Header Fuzz Keys` configuration area under `Authorization -> Users`.
- Users fill this once, not per user.
- Accepted format: one key per line or comma-separated.
- These keys define which headers should be extracted from traffic into `parameter_pool`.

### Header Key Sources

For each request being extracted, fuzzable header keys are:

1. Global Header Fuzz Keys.
2. The current request user's `Match/Replace` rules where type is `Header Add/Set:`.

This keeps global keys easy to manage while still respecting per-user MR usage.

### Parameter Extraction

- Extend extraction to read request headers from `raw_requests`.
- If a header key matches the candidate fuzz key set, write it to `parameter_pool` with `location = HEADER`.
- Preserve the original header key casing in `param_name`.
- Match header names case-insensitively.

### Attack Generation

- Treat `HEADER` parameters like `QUERY`, `PATH`, and `BODY_JSON` during combination generation.
- When applying a generated attack combination, set or add the matching header in the attack request.

### Param Recommender

- Since recommendations are based on `parameter_pool`, adding `HEADER` rows enables header recommendations automatically.
- `Use selected` should continue to create a `Header Add/Set:` MR rule for header recommendations.

### Users Headers and Match/Replace Order

- Apply `Users -> Headers` first as the base user context.
- Apply `Users -> Match/Replace` second so precise rules can override or add headers.
- Update conflict messaging from warning semantics to info semantics: MR header rules override Users headers.

## Implementation Steps

1. Add `plan.md` and `update_log.md`.
2. Inspect current user-tab layout, save/restore behavior, extractor SQL, attacker request reconstruction, and authorization rule application.
3. Add global Header Fuzz Keys UI and persistence.
4. Add extractor logic to insert `HEADER` parameters.
5. Add attacker logic to include and mutate `HEADER` parameters.
6. Change rule application order to Users Headers first, Match/Replace second.
7. Run targeted syntax checks.
