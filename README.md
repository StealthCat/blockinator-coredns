# Blockinator CoreDNS

A native Go plugin that applies [Blockinator](https://github.com/StealthCat/blockinator-web)
DNS policies before CoreDNS resolves or forwards a query. It supports client
scopes, lists, whitelist rules, schedules and query logging through Blockinator's
existing `/api/v1/decision` API. No changes to the Blockinator server are required.

## Build

CoreDNS external plugins are **compiled into the CoreDNS binary**. Adding a
Corefile directive to a stock CoreDNS image is not enough, and this is not a
runtime-loadable `.so` plugin.

Install Git and Go 1.27.1 (the version exercised by CI), then run:

```bash
git clone https://github.com/StealthCat/blockinator-coredns.git
cd blockinator-coredns
bash tools/build.sh
./build/coredns -plugins
```

The build script downloads **CoreDNS v1.14.7**, adds this local plugin to
`plugin.cfg`, runs the upstream generator, and builds `build/coredns`. It leaves
the source in `build/coredns-source` for inspection. Move or remove that generated
source directory before running the script again; it will not overwrite an
existing build checkout. The plugin module's minimum Go version is 1.25, while CI
uses 1.27.1. The generated upstream build may resolve newer compatible transitive
dependencies; retain its `go.mod` and `go.sum` if reproducing a deployment exactly.

For an existing customized CoreDNS build, add this line to `plugin.cfg`
**immediately before `local:local`**, then add the module dependency and regenerate:

```text
blockinator:github.com/StealthCat/blockinator-coredns
```

```bash
go get github.com/StealthCat/blockinator-coredns@COMMIT_SHA
go generate
go mod tidy
go build
```

Replace `COMMIT_SHA` with the plugin commit you intend to deploy. Plugin execution
order comes from `plugin.cfg`, **not the order of directives in the Corefile**.
Blockinator must run before `cache` and answer-producing plugins. The supplied
build also places it before rewrites so the API sees the original question.
Error and query logging remain earlier in the chain. If you change plugin order,
repeat the integration tests before deployment.

## Configure

Install Blockinator using its [Docker Compose instructions](https://github.com/StealthCat/blockinator-web#readme).
Set the same policy API key in the CoreDNS process environment; do not use your
administrator password. For an interactive test, this avoids putting the key in
shell history:

```bash
read -rsp 'Blockinator policy API key: ' POLICY_API_KEY; echo
export POLICY_API_KEY
./build/coredns -conf examples/Corefile
```

The example listens on **127.0.0.1:1053** and expects Blockinator's HTTP endpoint
on the same host at port 8080:

```corefile
.:1053 {
    bind 127.0.0.1
    errors
    blockinator http://127.0.0.1:8080/api/v1/decision {
        api_key_env POLICY_API_KEY
        server_id coredns-1
        timeout 250ms
        fail_mode open
        max_concurrent 128
    }
    cache 30
    loop
    forward . 1.1.1.1 9.9.9.9
}
```

Choose upstream resolvers appropriate for your network. To serve LAN clients,
change the bind address and port, then restrict access using your firewall or
CoreDNS ACLs. Do not expose an unrestricted recursive resolver to the internet.
For a systemd deployment, supply the key through a root-owned environment file
with mode 0600. For containers, inject it into the CoreDNS container's environment;
localhost inside that container refers to the container, not the Docker host.

Use an `https://.../api/v1/decision` endpoint when crossing an untrusted network.
The plugin verifies certificates using the operating system's trust store. It
rejects redirects, ignores ambient HTTP proxy settings, and does not provide a
TLS verification bypass. If Caddy redirects HTTP to HTTPS, use the final HTTPS
URL directly. For a private CA, install that CA in the CoreDNS host/container's
trust store.

Ensure the endpoint's hostname resolves independently of this CoreDNS policy
path (for example, a static hosts entry). Otherwise a lookup for Blockinator
itself can create a DNS/policy loop.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `api_key_env` | Required | Name of an environment variable containing the existing policy API key, at least 24 printable characters |
| `server_id` | `coredns-1` | Identifier shown in Blockinator query logs; up to 255 bytes |
| `timeout` | `250ms` | Total HTTP deadline, including connection/pool wait and response body; greater than zero, at most `10s` |
| `fail_mode` | `open` | `open`: continue normal resolution on policy failure; `closed`: return SERVFAIL |
| `max_concurrent` | `128` | Maximum concurrent policy requests per plugin instance, from 1 to 4096; excess requests immediately use `fail_mode` |

Only one `blockinator` directive is allowed per server block. Unknown or duplicate
options fail startup. The policy key is read when the configuration loads;
restart CoreDNS after changing the key or its environment.

### DNS responses

The response mode is selected in Blockinator's settings:

| Mode | Response |
| --- | --- |
| `nxdomain` | NXDOMAIN |
| `refused` | REFUSED |
| `nodata` | NOERROR with no answers |
| `zero` | `0.0.0.0` for IN/A, `::` for IN/AAAA, no answers for other questions |

Synthetic address records have TTL 0, are not DNSSEC-authenticated, and do not
enter the downstream CoreDNS cache. NXDOMAIN/NODATA replies do not include a
synthetic SOA. Allowed queries continue to the normal plugin chain, including
its DNS cache. A Blockinator allow decision does not override denials from
another CoreDNS plugin.

Client IP/port, transport, question name/type/class and server ID are sent to
Blockinator. IPv4 and IPv6 are supported. Scope identity comes from the client
address visible to CoreDNS, not untrusted EDNS Client Subnet data. NAT and DNS
proxies may cause multiple clients to share one identity. Raw wire packets and
EDNS metadata are not sent. Invalid query shape (including multiple questions)
receives FORMERR without calling the policy API.

The plugin checks the original question, not every CNAME target returned by an
upstream. Blockinator's ignored record types return an allow decision without a
Blockinator query-log entry; CoreDNS continues resolving them normally.

## Reliability and cache behavior

Each query reaching this plugin gets a fresh policy check, even when its allowed
DNS answer is already cached. HTTP connections are reused; no separate policy
cache is added. Consequently policy edits and client scopes are enforced without
flushing CoreDNS's DNS cache. Client-side caches can still retain earlier answers.

Non-200 responses, malformed or oversized replies, redirects, TLS errors,
timeouts and concurrency overload use `fail_mode`. Failure warnings are limited
to one per minute per plugin instance and omit keys and queried names. Fail-open
queries may resolve without a Blockinator log entry during an outage. Size the
API service for your query rate, and choose fail-closed if allowing DNS during a
policy outage is unacceptable.

## Verify and test

Create a Blockinator blacklist entry for `blocked.example` and assign it to the
testing client's scope. Then run:

```bash
dig @127.0.0.1 -p 1053 blocked.example A
dig @127.0.0.1 -p 1053 blocked.example AAAA
dig +tcp @127.0.0.1 -p 1053 blocked.example A
dig @127.0.0.1 -p 1053 example.com A
```

Check the results and Blockinator query history. Repeat from a client outside the
blocking scope. For automated tests:

```bash
go test -race ./...
COREDNS_BINARY="$PWD/build/coredns" go test -race -count=1 ./...
go vet ./...
```

Without `COREDNS_BINARY`, the live binary test is skipped. With it, tests start
isolated CoreDNS processes, a mock HTTP policy API and a local DNS upstream. They
verify UDP/TCP, client isolation, policy changes, failure modes and reuse of
allowed DNS answers from cache. Unit tests also cover IPv6 metadata, strict
configuration, malformed replies, certificate verification, request cancellation
and bounded concurrency. CI builds the actual upstream binary and runs both.

To disable the integration, remove its Corefile directive and restart CoreDNS.
To update, pull the intended plugin revision, rebuild the binary, repeat tests,
and replace your deployed binary using your normal service restart process.

## License

[GNU GPL v3.0](LICENSE).

## Upstream documentation

- [CoreDNS external plugins and configuration](https://coredns.io/manual/toc/)
- [Compile-time plugin ordering](https://github.com/coredns/coredns/blob/v1.14.7/plugin.cfg)
