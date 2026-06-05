# Update Log

## Header Fuzz Feature

- Add a global Header Fuzz Keys configuration so users can mark headers such as `X-Instance-Id`, `X-Tenant-Id`, or `X-Scenario-Id` as fuzzable parameters.
- Extract matching request headers into `parameter_pool` with `location = HEADER`.
- Include header parameters in IDOR attack parameter combinations.
- Allow generated attacks to set or add header values during request reconstruction.
- Let Param Recommender find and use header-sourced recommendations from the parameter pool.
- Change user-context application order so `Users -> Headers` are applied first and `Match/Replace` rules override them afterward.
