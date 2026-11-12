# Changelog

## 1.0.1 — 11 November 2026

- Count failed and warning-bearing recipient lookups in coverage and incomplete results.
- Preserve cached recipient lookup outcomes without hiding failures or counting them repeatedly.
- Stop subsequent network reads after throttling, including recipient and control queries; retain data already returned.
- Add publisher attribution, a simulated contact-resolution example and explicit Power Automate/application scope boundaries.
- Pass 25 offline tests, including recipient failure, caching and throttling regressions.

The first public GitHub release uses the previously validated v1.0.1 package unchanged. Repository documentation, a synthetic example and the portable offline test runner accompany it.

## 1.0.0 — 11 November 2026

Initial review build: read-only forwarding inventory, explicit query coverage, numeric Inbox-rule limit, unsupported-rule review list and HTML/CSV/JSON reports.
