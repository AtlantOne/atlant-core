# Contributing to Atlant

Questions about setup belong in [Discussions](https://github.com/AtlantOne/atlant-core/discussions/categories/q-a).
Use [Ideas](https://github.com/AtlantOne/atlant-core/discussions/categories/ideas)
for proposals and Issues for reproducible bugs. English and Russian are welcome.
You do not need to submit code to help: a clear reproduction or a measurement
with its setup documented is useful too.

## Reporting a bug

Include the application and server versions, OS, selected transport, expected
behavior and the shortest steps that reproduce the problem. A small redacted
log is more useful than a whole configuration dump. Never publish subscription
links, keys, passwords, user data or raw packet captures. Security-sensitive
reports should follow [SECURITY.md](SECURITY.md), not a public issue.

## Sending a change

Keep a pull request focused and explain what it changes. Use disposable users
and an isolated test server, never a production account. From the repository root:

```sh
go -C shared test ./...
go -C server test ./...
go -C client/linux test ./...
go -C client/android test -tags atlanttest ./...
python3 -m unittest discover -s scripts -p 'test_release_audit.py'
```

Run the relevant module's `go vet ./...` too. Protocol changes need positive
interoperability checks and negative authentication tests; say whether both
ends need updating. Include your actual test results in the pull request.
Android UI, Windows GUI and panel changes belong in their separate repositories.

Tests stay in source control. Runtime profiles, signing keys, databases, private
logs, captures and local build outputs do not. Follow the directory's license
and preserve upstream notices; see [LICENSING.md](LICENSING.md).
