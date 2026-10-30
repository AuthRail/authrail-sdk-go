# Releasing

This guide is for maintainers. Public installation instructions are in the README.
The coordinated documentation refresh targets **0.1.1**; published versions are
immutable, so never move a released tag or replace an existing package.

## Check a candidate

Run the **Release** workflow from `main` with publishing disabled:

```sh
gh workflow run release.yml --ref main -f version=0.1.1 -F publish=false
```

The workflow runs CI and builds reviewable artifacts, retained for 14 days.
Inspect the run and download its artifacts. Checksum files accompany them.
These temporary artifacts are not registry releases.

## Publish a checked version

Confirm the release commit and tested SDK/sidecar combination, and create the
matching `v0.1.1` tag at that exact main commit. The workflow rejects a missing or
mismatched tag. Its publishing environment allows only `main`.

```sh
gh workflow run release.yml --ref main -f version=0.1.1 -F publish=true
```

An explicit publish run automatically follows successful CI with publishing.
There is no additional GitHub reviewer approval. Pull requests, ordinary pushes
and check-only runs do not publish. Inspect both registry availability and the
GitHub release afterward; do not blindly repeat a partially completed upload.

## Go

Module: [github.com/AuthRail/authrail-sdk-go](https://pkg.go.dev/github.com/AuthRail/authrail-sdk-go).
GitHub environment: **release**. There is no separate Go publisher account.
Pushing the version tag makes the module available to Go tooling, so tag creation
is itself a publication step. The workflow never creates or moves tags.

The check-only run builds a source archive and compiles an independent consumer.
After the tag exists, the publish run checks that version through the public Go
proxy and creates its GitHub release.

Verify `go get github.com/AuthRail/authrail-sdk-go@v0.1.1` in an empty module and
exercise the connected Runtime flow.

[Publishing Go modules](https://go.dev/doc/modules/publishing)
