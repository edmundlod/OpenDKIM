## _FFR_DNSSEC — DNSSEC validation support (future work)
The `_FFR_DNSSEC` guards are intentionally preserved. This feature adds DNSSEC
validation of DNS responses used in DKIM key lookups. It was partially implemented
but not completed. Future work:
- Audit existing `_FFR_DNSSEC` blocks for correctness
- Wire up the resolver to pass DNSSEC-validated status through to the policy engine
- Add test coverage
- Once complete, promote to unconditional (remove guards) or make a configure option

## _FFR_DB_HANDLE_POOLS — DB connection pooling (needs CMake integration)
The pooling implementation in `opendkim-db.c` provides connection reuse for
database backends (MySQL, PostgreSQL, etc.) in high-volume deployments.
The code exists behind `_FFR_DB_HANDLE_POOLS` guards but was never wired
into the build system — no configure option or CMake option exists for it.

Future work:
- Audit the pooling code in opendkim-db.c for correctness
- Add a CMake option: -DENABLE_DB_HANDLE_POOLS=ON (default OFF)
- Add the corresponding define to the generated build-config.h
- Test under concurrent load with MySQL/PostgreSQL backends
- If validated, make it the default and remove the guards

## Database backends — full audit and modernisation

### Phase 1 — audit (Sonnet, no code changes)

Produce AUDIT-BACKENDS.md covering:

**Existing backends in opendkim-db.c — for each, document:**
- What it actually does (key lookup? policy lookup? signing table?
  all of the above?)
- Which CMake USE_* flag gates it
- Whether it is wired into the current CMakeLists.txt or silently
  excluded
- Upstream library status (maintained/abandoned/forked)
- Real-world deployment relevance in 2026

**Backends to assess:**
- Flat file / refile (always present)
- LDAP (`USE_LDAP`) — already on SCOPE removal list; confirm status
- SQL via OpenDBX (`USE_ODBX`) — already on SCOPE removal list
- BerkeleyDB (`USE_BDB` / `USE_LIBDB`)
- LMDB (`USE_MDB`)
- memcached (`USE_LIBMEMCACHED`)
- Erlang (`USE_ERLANG`)

**Modern backends — research only, no implementation yet:**
- PostgreSQL — native libpq, no OpenDBX wrapper
- MySQL/MariaDB — native connector
- SQLite — embedded, zero-daemon dependency
- MongoDB — libmongoc
- Redis — hiredis; would replace memcached use case

For each modern backend answer:
- Is there a C client library with a stable API and active upstream?
- What is the natural opendkim use case (signing table? key cache?
  policy store?)
- What would a minimal read-only implementation look like?

**Also document:**
- What dkimf_db_get / dkimf_db_open / dkimf_db_close actually
  abstract — is the interface clean enough to add new backends
  without touching existing code?
- Whether the current abstraction layer needs refactoring before
  new backends are added

### Phase 2 — decision (after reading AUDIT-BACKENDS.md)

Remove dead/abandoned backends. Decide which modern backends
are worth implementing. Design first, then implement.

