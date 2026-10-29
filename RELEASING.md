# Releasing

This guide is for maintainers. Public setup remains in the README. The initial
release version is **0.1.0**. Preparing a release does not publish it.

## Check a candidate

After the release preparation has merged, run the **Release** workflow from
`main`, with version `0.1.0` and **publish unchecked**:

```sh
gh workflow run release.yml --ref main -f version=0.1.0 -F publish=false
```

The workflow runs CI, builds the distributions and retains reviewable artifacts
for 14 days. Open its run in Actions, check every job, and download the artifacts.
These artifacts are temporary review downloads, not public releases.

## Before publishing

Complete the connected release checks, confirm the exact main commit and tested
sidecar/SDK combination, and obtain the owner's release approval. Create only
that approved `v0.1.0` tag; never move a published tag. The publish workflow
requires the tag to point to the exact main commit being run. An intervening
main commit requires reviewing the release identity again.

Configure the GitHub environment below with the owner as a required reviewer
and deployment branches restricted to `main`. Publishing is a separate manual
Release workflow run with **publish checked**. A pull request, ordinary push
or check-only run cannot publish.

## Go setup

Use GitHub environment **release**. There is no separate Go publisher account.
Pushing the version tag makes the module available to Go tooling, so tag creation
is itself a publication step and needs release approval.

The check-only artifact is a source archive compiled by an independent consumer.
After the approved tag exists, the publish job checks that version through the
public Go proxy, verifies the archive checksum and creates a GitHub release.
It never creates or moves the tag for you.

Verify `go get github.com/AuthRail/authrail-sdk-go@v0.1.0` in an empty module and
exercise the connected Runtime flow before updating the public install guide.

[Publishing Go modules](https://go.dev/doc/modules/publishing)
