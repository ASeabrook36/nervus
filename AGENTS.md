# nervus

nervus is an MCP bastion: it gives any AI agent, from any project, programmatic SSH access to the operator's home fleet, with per-client tokens and an append-only audit log. See `decisions/0001-mcp-bastion.md` for the founding decision and `CURRENT_STATE.md` for what phase this project is in right now.

## Operating rules

1. One step at a time. A step is one file, or one module with its tests. State the reasoning, do the step, wait for confirmation.
2. Never act on a machine from documented facts; read state off the machine first. Documented facts may be recorded only with their provenance stated.
3. Verify behaviour, not exit codes. Truncated output is not evidence.
4. Documentation is committed immediately after state changes, not in advance. ADRs precede or immediately follow execution. Procedures are written as executed.
5. Each substantive change is its own commit, message says what and why.
6. `decisions/` is the authoritative record. A decision not in an ADR is not a decision. If a design question arises that ADR-0001 does not answer, stop and report it; do not resolve it.
7. Secrets never enter the repository. `secrets/` is gitignored from the first commit.
8. Do not run ahead of `CURRENT_STATE.md`.
9. Until nervus is running, sessions that touch the fleet run from the operator's Mac. Remote sessions do repository-only work.
10. The operator is a systems thinker, not a programmer. Lead with why. No hedging. Define jargon. Own errors immediately.
11. Decision records and code name no system of the operator's: no host, address, hardware or network. An ADR says what testing showed and cites the procedure by number; numbers in it are nervus's defaults, not one machine's. Code learns what a host is for from the inventory, never from its name. The specifics, with their provenance (rule 2), belong in the deployment record: `procedures/`, `CURRENT_STATE.md`, `hosts.yaml` and `deployment/`. See ADR-0019.
