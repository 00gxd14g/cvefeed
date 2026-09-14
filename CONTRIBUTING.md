# Contributing

Bug reports and pull requests are welcome. Please read the licence first: the
source is [source-available](LICENSE), not OSI open source, and contributions
are accepted under those same terms.

## Before opening a pull request

```bash
make lint      # go vet + gofmt
make test      # hermetic unit tests
make verify    # full gate: PostgreSQL-backed tests, race detector, staticcheck, govulncheck, image
```

`make verify` needs Docker for the disposable database and the image build.
Without Docker, point it at a PostgreSQL you already run and skip the image:

```bash
CVEFEED_VERIFY_PG_DSN='postgres://cvefeed:test@127.0.0.1:5432/cvefeed?sslmode=disable' \
CVEFEED_VERIFY_SKIP_IMAGE=1 make verify
```

CI runs the same steps on every push and pull request.

## Ground rules

- Keep the direct dependency set small; prefer the standard library.
- The matcher must stay conservative: a bound it cannot order is reported as
  undecidable, never guessed. Add a test for every new ordering rule or
  identity edge.
- A new collector needs a cursor, an air-gap recording path through the
  `Fetcher` interface, and an entry in the attribution notices.
- Do not add upstream data or credentials to the repository. Fixtures live under
  `testdata/` and `internal/*/testdata/` and should be small.
- Keep commit messages in the existing style: `area: what changed and why`.
