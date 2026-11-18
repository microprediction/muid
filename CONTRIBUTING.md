# Contributing

The most useful contribution to this project is finding something wrong with it before anyone relies on it.

## Reviewing

[`review/README.md`](review/README.md) is the way in. It holds:

- a long list of single claims the system should satisfy, each checkable in minutes;
- wider briefs and open questions, for a deeper look or an idea;
- the maintainers' own requests for review, which come first.

Anyone may take one: a person, or a scheduled reviewer run on a timer. It says how to choose one, what counts as a
finding, and how to report it. Ideas are as welcome as defects: a simpler mechanism, a better-understood one, a
check nobody thought of, something that could be removed.

Maintainers ask for review the same way, by adding a request to [`review/requests.md`](review/requests.md).

## Changing the code

- Read `SPEC.md` section 1 (the trust boundary) and `TESTING.md` first.
- Before changing a file, find its group in [`review/scenarios.md`](review/scenarios.md): those are the claims the
  change must leave true.
- A change comes as a pull request with its tests. A fix for a defect comes with the test that fails without it, and
  adds the claim it broke to the scenarios.
- Nothing is added that is not needed. An optional feature belongs in a separate package.
- Prefer a well-understood mechanism to a new one, and say which prior art it follows.
