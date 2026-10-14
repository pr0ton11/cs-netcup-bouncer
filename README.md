# cs-netcup-bouncer

A CrowdSec bouncer that blocks banned addresses in the [netcup firewall](https://www.netcup.com/en/helpcenter/documentation/server/firewall), so their traffic never reaches the server.

It polls the CrowdSec local API and rewrites one netcup firewall policy from the active bans: `INGRESS DROP` rules for the banned addresses first, then ACCEPT rules. Attaching a user policy switches netcup's implicit rules to `DROP_ALL`, so the default ACCEPT rules accept all traffic.

- Addresses stay in memory and on netcup's firewall only, never on disk or in logs. On shutdown the DROP rules are removed.
- At most `NETCUP_MAX_RULES` effective rules (netcup counts each address once). If there are more bans than fit, the longest-lasting are kept.
- Never blocks `NEVER_BLOCK`, private addresses, or ranges wider than /16 (IPv4) or /32 (IPv6).
- Writes only on change, at most every `SYNC_INTERVAL`, and backs off on errors.

Image: `ghcr.io/pr0ton11/cs-netcup-bouncer` (linux/amd64, linux/arm64, distroless).

## Configuration

| Variable | Default |
|---|---|
| `NETCUP_USER_ID`, `NETCUP_SERVER_ID`, `NETCUP_INTERFACE_MAC` | required |
| `NETCUP_REFRESH_TOKEN_FILE` | `/run/secrets/netcup-refresh-token` |
| `CROWDSEC_LAPI_URL` | `http://127.0.0.1:8080` |
| `CROWDSEC_LAPI_KEY_FILE` (or `CROWDSEC_LAPI_KEY`) | `/run/secrets/netcup-bouncer-lapi-key` |
| `NETCUP_POLICY_NAME` | `crowdsec-bouncer` |
| `NETCUP_ACCEPT_RULES_FILE` | accept all (see `deploy/accept-rules.example.json`) |
| `NETCUP_DROP_PROTOCOLS` | `TCP,UDP` |
| `NETCUP_MAX_RULES` | `400` |
| `NEVER_BLOCK` | comma-separated addresses or prefixes |
| `POLL_INTERVAL`, `SYNC_INTERVAL`, `DRIFT_CHECK_INTERVAL` | `30s`, `2m`, `1h` |
| `DRY_RUN`, `ACCEPT_ONLY`, `CLEAR_ON_EXIT`, `DEBUG` | `false`, `false`, `true`, `false` |

`NETCUP_USER_ID` is the `id` claim printed by `go run github.com/pr0ton11/netcup-scp-go/cmd/scp-login`, not the customer number.

## Run

The bouncer needs to reach the CrowdSec LAPI, for example by sharing its network namespace:

```sh
cscli bouncers add netcup -o raw > lapi-key
chown 65532 lapi-key netcup-refresh-token && chmod 400 lapi-key netcup-refresh-token  # the image runs as uid 65532
docker run -d --name netcup-bouncer --restart always --network container:crowdsec \
  -v ./lapi-key:/run/secrets/netcup-bouncer-lapi-key:ro \
  -v ./netcup-refresh-token:/run/secrets/netcup-refresh-token:ro \
  -e NETCUP_USER_ID=... -e NETCUP_SERVER_ID=... -e NETCUP_INTERFACE_MAC=... \
  -e NEVER_BLOCK=<server addresses> -e ACCEPT_ONLY=true \
  ghcr.io/pr0ton11/cs-netcup-bouncer:0.1.0
```

Roll out with the SCP console open: `DRY_RUN=true` first, then `ACCEPT_ONLY=true`, then neither.

## Development

```sh
go test -race ./...
podman build -t localhost/cs-netcup-bouncer:dev .
```

## License

Apache License 2.0, see [LICENSE](LICENSE).
