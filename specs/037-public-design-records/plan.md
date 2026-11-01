# Implementation Plan: Public design records

**Branch**: `037-public-design-records` (local planning; commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- **Rewrite** the 20 procage rows (001–010, 024, 026–030, 032, 034, 036–038)
  by one rulebook (below), in four parallel batches; then re-merge each threat
  model with itself (refreshes the source hashes), render, and `check`.
  `security/incoming-threat-model.yaml` files are inputs of the generator,
  not records: removed.
- **`.specify/`**: constitution amended (2.2.0: public design records, private
  notes, consumers unnamed); caches ignored; `feature.json` kept (the active
  feature).
- **`.gitignore`**: track `specs/` and `.specify/`; ignore
  `.specify/extensions/.cache/`, `specs/**/security/incoming-*`.
- **Gate** (`just planning-paths`): the crates never cite a planning path
  (unchanged); README, SECURITY and the site may link `specs/` but never the
  private notes; `specs/` and `.specify/memory/` contain no private-note
  directory or id (decisions, questions, feedback), research-note path,
  planning reference, consumer or other private project name, home-directory
  path or e-mail address (the exact pattern lives in the justfile).
- **Docs**: `specs/README.md`; one link from README ("Design records") and the
  site (testing page).

## Rulebook (for every record)

1. Keep the substance: requirements, acceptance scenarios, measurements,
   threat ids, verdicts, file paths in this repository.
2. Remove ids of private notes (decisions, questions, feedback items,
   planning items, research notes, the notes directory). Where the note gave
   a reason the record
   needs, write the reason in one sentence.
3. Never name the consumer project or its paths. Its name becomes "a
   consumer harness" (or "the consumer"); its feedback items become what they
   asked for.
4. No home-directory paths, user names, other private projects.
5. Tasks that only updated private notes (logging a decision there) become
   "record the decision" or are dropped if nothing public remains.
6. Plain English, the records' existing style; no new claims.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| Honest docs | Records stay history; README names authoritative docs | PASS |
| Local planning rule | Amended explicitly (2.2.0), gate enforces the new rule | PASS |

## Project Structure

```text
specs/{001…038}/ (20 rows), specs/README.md
.specify/memory/constitution.md, .gitignore, justfile, README.md, site/content/docs/testing.md
```

## Complexity Tracking

None.
