# cs-netcup-bouncer

cs-netcup-bouncer is a CrowdSec bouncer for the [netcup firewall](https://www.netcup.com/en/helpcenter/documentation/server/firewall). A bouncer is a program that applies the bans that CrowdSec decides. This bouncer adds the banned addresses to the firewall of a netcup server, so that their traffic does not reach the server.

## How it works

The bouncer reads the active bans from the CrowdSec local API (LAPI), by default every 30 seconds. It writes them to the netcup firewall through the API of the netcup Server Control Panel (SCP). netcup puts firewall rules into policies. A policy that you create is a user policy. The bouncer creates two user policies and attaches them to the network interface of the server:

| Policy | Rules | Position |
|---|---|---|
| `<NETCUP_POLICY_NAME>` | `INGRESS DROP` rules for the banned addresses | First of all user policies |
| `<NETCUP_POLICY_NAME>-fallback` | Rules that accept all traffic in both directions | Last, and only if you have no user policy of your own |

netcup applies the first rule that matches a packet. The policies apply in the order in which they are attached to the interface. A live test on a netcup server showed this order. The DROP policy is first, so an ACCEPT rule in a later policy cannot let a banned address through.

The fallback policy exists because of the implicit rules. An implicit rule is the default for traffic that no rule matches. If an interface has no user policy, the implicit rules accept all traffic. If you attach a user policy, netcup changes the implicit rules to `DROP_ALL`. If you have no policy of your own, the fallback accepts the traffic that the implicit rules accepted before. If you have policies of your own, they decide what is allowed, and the bouncer does not attach the fallback.

The bouncer reads its two policies and the interface back every `DRIFT_CHECK_INTERVAL`. This drift check corrects all changes that somebody made to the two policies. If you attach or detach a policy of your own, the drift check adds or removes the fallback.

A copied policy is a policy that netcup supplies, for example "netcup Ping allow". Copied policies probably apply before all user policies. In a test, an ICMP DROP rule did not stop ping while "netcup Ping allow" was attached. If you add ICMP to `NETCUP_DROP_PROTOCOLS`, a copied policy can accept the ICMP traffic before the DROP rule.

## Privacy and limits

The bouncer keeps the banned addresses in memory and in the netcup firewall only. It does not write them to disk or to the logs. By default, the bouncer removes all DROP rules when it stops. It keeps the fallback, so that the server stays reachable.

netcup allows 500 effective rules in one policy. An effective rule is one address in one rule. The DROP policy uses at most `NETCUP_MAX_RULES` effective rules. If more bans are active than fit, the bouncer keeps the bans that last longest.

The bouncer never blocks these addresses:

- The addresses and prefixes in `NEVER_BLOCK`
- Private, loopback, link-local and multicast addresses
- Ranges wider than /16 for IPv4 or /32 for IPv6

The bouncer writes to netcup only when the rules change, and at most once in each `SYNC_INTERVAL`. If a call to netcup fails, the bouncer waits between 1 and 30 minutes before it tries again.

## Configuration

You configure the bouncer with environment variables. The three required variables have no default, and the bouncer does not start without them.

| Variable | Default | Description |
|---|---|---|
| `NETCUP_USER_ID` | required | Your SCP user ID. `go run github.com/pr0ton11/netcup-scp-go/cmd/scp-login` prints it as the `id` claim. It is not your customer number. |
| `NETCUP_SERVER_ID` | required | The ID of the server in the SCP |
| `NETCUP_INTERFACE_MAC` | required | The MAC address of the public network interface of the server |
| `NETCUP_REFRESH_TOKEN_FILE` | `/run/secrets/netcup-refresh-token` | The file with the SCP refresh token. The bouncer reads this file and never writes it. |
| `NETCUP_POLICY_NAME` | `crowdsec-bouncer` | The name of the DROP policy. The fallback policy gets the name `<name>-fallback`. |
| `NETCUP_DROP_PROTOCOLS` | `TCP,UDP` | The protocols that get DROP rules for the banned addresses |
| `NETCUP_MAX_RULES` | `400` | The maximum number of effective rules in the DROP policy |
| `NETCUP_API_URL` | `https://www.servercontrolpanel.de/scp-core` | The base URL of the SCP API |
| `CROWDSEC_LAPI_URL` | `http://127.0.0.1:8080` | The URL of the CrowdSec LAPI |
| `CROWDSEC_LAPI_KEY_FILE` | `/run/secrets/netcup-bouncer-lapi-key` | The file with the API key that `cscli bouncers add` makes |
| `CROWDSEC_LAPI_KEY` | | The API key itself. If you set it, the bouncer ignores `CROWDSEC_LAPI_KEY_FILE`. |
| `CROWDSEC_ORIGINS` | | A comma-separated list of origins, for example `crowdsec,cscli`. The bouncer blocks only the bans from these origins. If the list is empty, it blocks the bans from all origins. The names are case-sensitive. |
| `NEVER_BLOCK` | | A comma-separated list of addresses and prefixes that the bouncer never blocks, for example the addresses of the server |
| `POLL_INTERVAL` | `30s` | The time between two reads from the LAPI |
| `SYNC_INTERVAL` | `2m` | The minimum time between two writes to a policy |
| `DRIFT_CHECK_INTERVAL` | `1h` | The time between two drift checks |
| `ACCEPT_ONLY` | `false` | If `true`, the bouncer keeps the DROP policy empty. Use it for the first start. |
| `DRY_RUN` | `false` | If `true`, the bouncer logs the DROP policy and does not call netcup. It needs no netcup credentials. |
| `CLEAR_ON_EXIT` | `true` | If `true`, the bouncer empties the DROP policy when it stops |
| `LOG_FORMAT` | `json` | The log format: `json` or `text` |
| `DEBUG` | `false` | If `true`, the bouncer also writes debug messages |

## Run

The bouncer must connect to the CrowdSec LAPI. In this example, the bouncer container uses the network of the `crowdsec` container. The image runs as user ID 65532, so this user must be able to read the two secret files.

1. On the CrowdSec host, make an API key for the bouncer: `cscli bouncers add netcup -o raw > lapi-key`.
2. Get a refresh token for the SCP: `go run github.com/pr0ton11/netcup-scp-go/cmd/scp-login -o netcup-refresh-token`.
3. Give user 65532 read access to the two files, and start the container:

```sh
chown 65532 lapi-key netcup-refresh-token && chmod 400 lapi-key netcup-refresh-token
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
  ghcr.io/pr0ton11/cs-netcup-bouncer:0.1.1
```

Open the SCP console in a browser before the first start. If the firewall blocks your access to the server, you can change the policies there. Then start the bouncer in three stages:

1. Start it with `DRY_RUN=true`. Make sure that the log shows the number of bans that you expect.
2. Start it with `ACCEPT_ONLY=true`. Make sure that all services and SSH are reachable from outside.
3. Remove `ACCEPT_ONLY`. The bouncer starts to block the banned addresses.

## Development

Run the tests and build a local image with these commands. A push of a `v*` tag builds the images for linux/amd64 and linux/arm64. The images are published on GHCR as `ghcr.io/pr0ton11/cs-netcup-bouncer`.

```sh
go test -race ./...
podman build -t localhost/cs-netcup-bouncer:dev .
```

The code is available under the Apache License 2.0. See [LICENSE](LICENSE).
