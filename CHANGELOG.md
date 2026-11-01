# Changelog

## 1.0.0 — First release

- Native CoreDNS plugin that applies Blockinator `/api/v1/decision` policy before cache, rewrites and answer-producing plugins, with NXDOMAIN, REFUSED, NODATA and zero-address responses.
- Fresh policy check per query, including cached answers, so client scopes and policy edits apply without flushing the DNS cache.
- Configurable `fail_mode`, total request `timeout`, `max_concurrent` limit and `server_id`; policy key read from an environment variable.
- Certificate verification against the system trust store; redirects and ambient proxies are never used.
- Reply NOTIMP to non-QUERY opcodes and FORMERR to responses or multi-question packets without calling the policy API.
- Reuse keep-alive connections after non-200 policy responses.
- Rate-limited failure warnings name the failure class (HTTP status, timeout, oversized or invalid reply) and the number of suppressed failures, without logging keys, URLs or query names.
- Unknown or duplicate options are named in configuration errors.
- Build script for CoreDNS v1.14.7, unit tests and live UDP/TCP integration tests in CI.
