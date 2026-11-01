# Research: Fitting a policy to the host

- **R1 Consumer practice.** a consumer harness's `fit`: match on
  construct, parse the gap subject to find the rule, set a flag, retry at
  most twice, build a notice with a hand-written cause. Two causes, one
  of them was wrong at first.
- **R2 Lift by re-lowering.** `lower` is pure; lowering the original policy
  for `Linux { T1, abi }` and for `Linux { tier, a }` with `a` up to the
  backend maximum answers "what lifts this gap" exactly for every gap the
  lowering produces. Gaps found at spawn (data classes reaching the home
  directories, Linux) are not reproduced; the lift is then unknown.
  Alternative: a static table per construct: rejected (drifts from the
  lowering).
- **R3 Relaxation semantics.** One meaning per construct, chosen to be the
  smallest change: drop the one rule the gap names; waive exactly the named
  class; stricter alternatives where they exist (no sockets, no network);
  `same-user` for signals (row 030). Approximations stay in
  `LowerOptions::allow_degrade`: they are a different consent ("enforced
  differently"), not "not enforced".
