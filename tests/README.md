# Cross-component tests

* `fixtures/`: small golden documents. **Synthetic data only.** Never commit
  real personal or company data. `fixtures/private/` is git-ignored for local
  experiments.
* Synthetic corpus generators and end-to-end suites arrive with Phases 2–3
  (see docs/TESTING.md).

Unit tests live next to their component: `engine/tests`, `apps/desktop/src/**/*.test.tsx`
and `apps/desktop/src-tauri/src/**` (`#[cfg(test)]`).
