# Authorized scope (Phase C1)

Open a saved Draft Assessment and select **Continue Setup**. The scope view is protected by the existing analyst session. Creators can change scope in Draft, and analysts with explicit assignments can view it. Other roles and unassigned users have no access. Mutations require a trusted origin and session CSRF token.

Scope entries accept strict IPv4, IPv4 CIDR, ASCII hostnames, and HTTP or HTTPS URLs. IPv6 and internationalized Unicode names are outside this phase. Use ASCII DNS names when available. CIDRs with host bits are rejected. Scheme and hostname case are normalized and explicit ports, trailing DNS dots, and URL paths and queries are retained. Enter boundary URLs without embedded credentials, fragments, or secret-bearing paths or query parameters. Scope data and audit history persist the normalized values. Validation performs no DNS or network operations.

The API returns the current scope revision with the entries. Mutations send that revision and return the new list. A stale write must reload first. Removal requires explicit confirmation. Each accepted mutation records actor, assessment, entry, action, timestamp, revision, and before/after snapshots in the same transaction.

Phase C2 must register targets separately and bind any scope-membership decision to the current scope revision. An older decision must block testing until revalidated against all entries. The impact preview and confirmation for actual affected targets require that model. C1 returns zero affected targets because no target records exist.

Migration `0006_authorized_scope.py` depends on `0005`. Upgrading preserves existing assessments and accounts. Downgrading removes the scope entries, revisions, and scope audit history. Use disposable PostgreSQL for rollback testing.
