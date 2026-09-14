# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem in cvefeed itself.
Use GitHub's private vulnerability reporting on this repository ("Security"
tab, "Report a vulnerability"). If that is unavailable, open an issue that
asks for a private contact without describing the problem.

You can expect an acknowledgement within a week. There is no bug bounty.

## Scope

In scope: the `cvefeed` binary, the HTTP API, the container image and the
compose stack in this repository.

Out of scope: the accuracy of upstream vulnerability data (report that to the
originating CNA, NVD, OSV, GHSA or vendor), and hosts you scan with
`cvefeed scan -target` without authorisation.

## Deployment notes

- Set `CVEFEED_API_TOKEN`; without it every `/v1` endpoint is open to anyone
  who can reach the port.
- Leave `CVEFEED_TARGET_SCAN_ENABLED=false` unless API callers are trusted to
  make the server connect to arbitrary reachable hosts.
- Keep the container's PostgreSQL bound to loopback (the default compose file
  does this).
