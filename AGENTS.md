# AGENTS.md

Instructions for AI coding agents working in this repository. `README.md` and `docs/config.md`
describe what whimbrel does.

## Engineering Practices

- **Think first.** State your assumptions, and name the simpler alternative when there is one. Ask
  when the request is ambiguous and the answer changes what you build; otherwise take the
  conventional default and say which one you took.
- **Simplest thing (YAGNI).** Write the least code that meets the request: no unrequested
  features, abstractions, configurability or speculative error handling. If 200 lines could be 50,
  write the 50.
- **Surgical.** Every changed line traces to the request. Match the surrounding style and leave
  working neighbours alone. Remove the orphans your change created; report unrelated dead code
  rather than deleting it.
- **Goal-driven.** Before the change, turn the task into a check that goes red on the problem
  ("fix the bug" becomes a test that reproduces it), then loop until it is green. In a multi-step
  plan, each step names its check. Code gets its test first.
- **Craft is the other 80%.** Working code is a fifth of the job. Before calling it done, read your
  own diff for: names that say what a thing is; one job per function, side effects visible;
  failures that surface (nothing swallowed, inputs validated, no unrecoverable panic); interfaces
  testable without real dependencies; new behaviour added without risky edits to old; logs that
  show it working in production; comments that say *why*; docs updated in the same change.
  Extract shared behaviour once a requirement repeats.
- **Self-contained commits**, with formatting kept apart from logic. Messages follow
  [Conventional Commits](https://www.conventionalcommits.org/) with a lowercase subject, as the
  history does, and the body says *why* when the diff doesn't.
