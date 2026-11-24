# Golden files for the report's JSON form

These files are copied unchanged from tinfoil-go's `verify/testdata/report-json`
(tinfoilsh/tinfoil-go#346), so the text below describes them as Go does. In
this package, `test/report-json.test.ts` checks every case: the ones that name
a vector when `TINFOIL_CONFORMANCE_FIXTURES` points at the suite's `vectors/v3`
directory, and the others by building the same input as the Go test that the
description names. To update them, regenerate them in a tinfoil-go checkout
with the commands at the end, and copy them here.

Each file is one case of the JSON form that `VerificationReport.MarshalJSON`
writes:

- `description` says what the case shows.
- `vector`, when present, names a full-verify vector of the shared
  conformance suite, relative to its `vectors/` directory. The case's report
  is what verifying that vector gives, at the vector's verification time.
  `verify/conformance` checks these cases when `TINFOIL_CONFORMANCE_VECTORS`
  is set.
- Without `vector`, the description names the Go test that builds the input,
  and `verify` checks the case.
- `report` is the expected JSON form.

Compare a report with `report` as JSON values, not as bytes: the order of
an object's members carries no meaning. Go compares every member. Another SDK
that reuses these files compares every member except the step messages,
which are each SDK's own text, and `metadata`, which describes the run. It
compares times as instants.

To regenerate the files after an intended change to the form, run
`go test ./verify -run Golden -update` and, with the vectors,
`go test -tags tinfoil_conformance ./verify/conformance -run TestReportJSONGolden -update`.
