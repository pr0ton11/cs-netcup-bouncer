# cs-netcup-bouncer

A CrowdSec bouncer that blocks banned addresses in the [netcup firewall](https://www.netcup.com/en/helpcenter/documentation/server/firewall), so their traffic never reaches the server.

It polls the CrowdSec local API and only adds blocks; your own firewall rules keep working. It owns two policies:

| Policy | Rules | Attached |
|---|---|---|
| `<NETCUP_POLICY_NAME>` | `INGRESS DROP` for the banned addresses | first among the user policies |
| `<NETCUP_POLICY_NAME>-fallback` | accept all, both directions | last, and only while you have no user policy of your own |

Attaching any user policy switches netcup's implicit rules to `DROP_ALL`. If you have no policy of your own, the fallback restores what the interface did before. If you do, your policies decide what is allowed, exactly as without the bouncer. When you attach or detach one later, the next drift check adds or removes the fallback.

User policies apply in the order they are attached (live-tested), so the DROP policy goes first. Copied policies such as "netcup Ping allow" seem to come before all user policies: with it attached, an ICMP block did not stop ping. Keep that in mind before adding ICMP to `NETCUP_DROP_PROTOCOLS`.

- Addresses stay in memory and on netcup's firewall only, never on disk or in logs. On shutdown the DROP policy is emptied; the fallback stays.
- At most `NETCUP_MAX_RULES` effective rules (netcup counts each address once). If there are more bans than fit, the longest-lasting are kept.
- Never blocks `NEVER_BLOCK`, private addresses, or ranges wider than /16 (IPv4) or /32 (IPv6).
- Writes only on change, at most every `SYNC_INTERVAL`, and backs off on errors.

Image: `ghcr.io/pr0ton11/cs-netcup-bouncer` (linux/amd64, linux/arm64, distroless).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `NETCUP_USER_ID` | required | SCP user ID: the `id` claim printed by `go run github.com/pr0ton11/netcup-scp-go/cmd/scp-login`, not the customer number |
| `NETCUP_SERVER_ID` | required | ID of the server in the SCP |
| `NETCUP_INTERFACE_MAC` | required | MAC address of the server's public interface |
| `NETCUP_REFRESH_TOKEN_FILE` | `/run/secrets/netcup-refresh-token` | File with the SCP offline refresh token; only read, never written |
| `NETCUP_POLICY_NAME` | `crowdsec-bouncer` | Name of the DROP policy; the fallback is `<name>-fallback` |
| `NETCUP_DROP_PROTOCOLS` | `TCP,UDP` | Protocols that get DROP rules for banned addresses |
| `NETCUP_MAX_RULES` | `400` | Budget of effective rules for the DROP policy (netcup allows 500 per policy and counts each address once) |
| `NETCUP_API_URL` | `https://www.servercontrolpanel.de/scp-core` | Base URL of the SCP REST API |
| `CROWDSEC_LAPI_URL` | `http://127.0.0.1:8080` | URL of the CrowdSec local API |
| `CROWDSEC_LAPI_KEY_FILE` | `/run/secrets/netcup-bouncer-lapi-key` | File with the bouncer API key from `cscli bouncers add` |
| `CROWDSEC_LAPI_KEY` | | Bouncer API key; overrides `CROWDSEC_LAPI_KEY_FILE` |
| `NEVER_BLOCK` | | Comma-separated addresses or prefixes that are never blocked, such as the server's own |
| `POLL_INTERVAL` | `30s` | How often to pull decisions from the LAPI |
| `SYNC_INTERVAL` | `2m` | Minimum time between two policy writes |
| `DRIFT_CHECK_INTERVAL` | `1h` | How often to read the policy and its assignment back and correct changes |
| `ACCEPT_ONLY` | `false` | Keep the DROP policy empty, for a safe first rollout |
| `DRY_RUN` | `false` | Log the policy instead of calling netcup; needs no netcup credentials |
| `CLEAR_ON_EXIT` | `true` | Empty the DROP policy on shutdown |
| `LOG_FORMAT` | `json` | Log format: `json` or `text` |
| `DEBUG` | `false` | Log at debug level |

## Run

The bouncer needs to reach the CrowdSec LAPI, for example by sharing its network namespace:

```sh
cscli bouncers add netcup -o raw > lapi-key
chown 65532 lapi-key netcup-refresh-token && chmod 400 lapi-key netcup-refresh-token  # the image runs as uid 65532
docker run -d \
  --name netcup-bouncer \
  --restart always \
  --network container:crowdsec \
  -v ./lapi-key:/run/secrets/netcup-bouncer-lapi-key:ro \
  -v ./netcup-refresh-token:/run/secrets/netcup-refresh-token:ro \
  -e NETCUP_USER_ID=<scp-user-id> \
  -e NETCUP_SERVER_ID=<server-id> \
  -e NETCUP_INTERFACE_MAC=<interface-mac> \
  -e NEVER_BLOCK=<server-addresses> \
  -e ACCEPT_ONLY=true \
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
