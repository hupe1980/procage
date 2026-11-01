# Data model

- `Relaxation` (non-exhaustive): `LeaveOutProtect` (fs-protect),
  `LeaveOutHide` (fs-hide), `Waive(HardDenyClass)` (its hd-* construct),
  `NoUnixSockets` (ipc-unix-sockets), `SignalsSameUser`
  (signals-self-and-children), `NoLoopback` (net-loopback).
- `Relax`: a set of relaxations.
- `Lift { tier1: bool, landlock_abi: Option<u8> }`; unknown = neither.
- `Relaxed { gap: CapabilityGap, relaxation: Relaxation, lift: Lift }`.
