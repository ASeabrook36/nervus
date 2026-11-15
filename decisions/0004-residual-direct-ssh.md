# ADR-0004: moved to the deployment record

**Status:** Moved 2026-10-16, by ADR-0019 decision B.

This number held a record of how the operator's own direct access to their machines sits beside
nervus on one running instance. That is about operating that instance, not about nervus, so it
is kept in the instance's deployment record (`deployment/0004-residual-direct-ssh.md`), which is
not published. The number is not reused. Anything citing ADR-0004 means that note.

One general point from it is part of nervus's reasoning, and ADR-0005 carries it: **SSH that
does not go through nervus leaves no record in nervus's audit log**, and a gap there is invisible
rather than obviously absent. That is why each target's own `sshd` journal matters as a second,
independent record.
