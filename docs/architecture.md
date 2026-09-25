# Architecture

The canonical architecture document lives at the repository root: [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

It covers:

1. Design principles (ports & adapters, transport-agnostic domain logic, append-only audit state,
   ground-truth quarantine)
2. The twelve logical services and their M2 vs M3+ forms
3. The verified M2 request path
4. The signed envelope
5. The persistence data model
6. Local → cloud mapping, and where that analogy breaks
7. Failure handling (timeouts, retries, circuit breaker, health checks, quarantine)
