# Thunder — graph-based guard dog

Standard-library-only Python tool. It turns a code base into a typed graph and enforces rules on it.

    PYTHONPATH=packages/thunder python3 -m thunder scan
    PYTHONPATH=packages/thunder python3 -m thunder blast packages/vault/infinity_vault/vault.py
    PYTHONPATH=packages/thunder python3 -m thunder why tests/vault/test_vault.py packages/vault/infinity_vault/vault.py

Rules: trust-boundary (forbidden imports, direct or transitive, with the path as evidence), layering, import cycles
(Tarjan SCC), dangerous calls, untested public API of critical packages (reachability from tests; importing a
module is not coverage), dependency pins / undeclared / unused, dangling doc references, unpinned GitHub Actions,
secret patterns.

Limits: static and name-based. It cannot see dynamic dispatch, reflection or runtime behaviour. A clean scan means
none of its rules fired. It does not replace audits or cryptographic review.

Portable: copy this folder and `.claude/agents/thunder.md` into another project, run `python3 -m thunder init`.
