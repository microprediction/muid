# Review

What this system must do, written so that anyone can check a piece of it: a person, a scheduled reviewer, or
whoever is about to change a file. Start here.

| File | What it holds | Size of one piece of work |
|---|---|---|
| [`scenarios.md`](scenarios.md) | A long numbered list of single claims that should be true of the system, grouped by the files that make them true | One claim: minutes |
| [`requests.md`](requests.md) | Specific things a maintainer has asked to have looked at | One request: as long as it takes |
| [`briefs.md`](briefs.md) | Wider ways to look for a defect in one area, and open questions where thinking is wanted | One brief or question: an hour |

Read `SPEC.md` section 1 (the trust boundary) before either.

## Ways to use it

- **A scheduled review, first.** If `requests.md` has an open request, take the first one instead of anything below.
- **A scheduled review, hourly.** Count the scenarios (`N`) and take number
  `(whole hours since 2026-01-01T00:00Z mod N) + 1`. Find the code that makes it true and the test that would fail if
  it stopped being true.
- **A scheduled review, daily.** Count the briefs and take number `(day of the year mod count) + 1`; or take an open
  question.
- **Asking for a review.** Add a request to `requests.md`: what to read, the question, and why it is asked now.
  Whoever changes something they are unsure of should ask.
- **Before changing a file.** Find the group in `scenarios.md` whose heading names that file. Those are the claims
  the change must leave true, and each should have a test that says so.
- **After finding a defect anywhere.** Add the claim it broke to `scenarios.md`, with the fix. The list is the
  record of what has been thought of.
- **With an idea.** A better design, a simpler mechanism, a check nobody thought of, a claim in these files that is
  itself wrong: all welcome.

## What to do with what is found

- **A finding** is a concrete input, sequence of requests, or stored state that makes the code break a claim; or a
  claim that holds with no test that would notice if it stopped holding. A suspicion with no reproduction is not a
  finding.
- **File one issue** titled `[automated review] <what is wrong, in one line>` (leave the prefix off if you are a
  person), with: the scenario or brief number, the file and line, the exact steps or a failing test that reproduces
  it, and what should happen instead. Search open and closed issues first and do not file a duplicate.
- **An idea** is filed as `[automated review] idea: <one line>`, with the reasoning, the prior art it rests on, and
  what it would cost.
- **A pull request** is welcome where the change is small and its tests come with it.
- **Nothing found, nothing filed.** Where a scenario cannot arise at all, that is a fine answer.

Scenarios and briefs are added, reworded and retired as the code changes. One that has found nothing for a long time
is not evidence the area is sound: it may only mean it is too narrow.
