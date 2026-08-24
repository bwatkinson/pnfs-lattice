# Metadata search: `mds-find`, `mds-apid`, and `lattice-find`

NFSv4 has no query verb. Answering "which files under this namespace are
larger than 1 GiB and changed in the last day" over NFS means walking the
tree with `LOOKUP` / `READDIR` / `GETATTR` — millions of RPCs, hours of
wall time on a large namespace, and a metadata server that is too busy
serving the walk to serve anything else.

The metadata already lives in one transactional store. This feature asks
it directly: one backend table scan with the predicates evaluated on the
data nodes.

Three pieces:

- **`mds-find`** — CLI with find(1)-style predicates, run on a host that
  can reach the metadata backend.
- **`mds-apid`** — read-only HTTP/JSON service exposing the same query.
- **`lattice-find`** — client-side wrapper that gives the same CLI syntax
  to hosts that can reach neither the backend nor an NFS mount.

```
 ┌────────────┐  HTTPS + Bearer   ┌────────────┐   backend   ┌─────────┐
 │ NFS client │ ────────────────▶ │ mds-apid   │ ──────────▶ │  RonDB  │
 │lattice-find│ ◀──────────────── │ (MDS/admin)│ ◀────────── │ cluster │
 └────────────┘   results JSON    └────────────┘    rows     └─────────┘
```

## Read the security model first

**The bearer token is an administrative credential.** A holder can
enumerate the entire namespace — every filename, size, owner, and
timestamp — regardless of POSIX traversal permissions. It is *not*
equivalent to what `find` would show that user.

This is a deliberate v1 scope decision, not an oversight. Treat the token
the way you would treat read access to the metadata backend itself:

- Distribute it to operators and trusted automation, not to general
  users, unless you have accepted that consequence.
- Keep the token file `0600`. `mds-apid` refuses to start if the file is
  readable beyond its owner.
- Per-token UID/GID scoping is the natural next step if you need to hand
  this to end users.

The service is strictly read-only. No route mutates the catalogue, so a
leaked token cannot be used to change or delete metadata — only to read
all of it.

## `mds-find` (CLI)

Runs against the backend directly, using the same `mds.conf` as the
daemon.

```sh
mds-find -type f -size +1G -name '*.parquet'
mds-find -type f -mtime -7
mds-find -uid 1000 -mtime +90 --limit 500
mds-find --json -inum 1000-2000
```

Predicates — all optional, AND-combined:

| Flag | Meaning |
| --- | --- |
| `-type f\|d\|l\|b\|c\|p\|s` | file type (reg/dir/symlink/blk/chr/fifo/sock) |
| `-size +N\|-N` | larger (`+`) or smaller (`-`) than N; N takes a `K`/`M`/`G`/`T`/`P` suffix (binary) |
| `-mtime +N\|-N` | modified more than N days ago (`+`) or within the last N days (`-`) |
| `-ctime +N\|-N` | changed more than / within N days |
| `-uid N` / `-gid N` | owner uid / gid |
| `-name GLOB` | entry-name glob (`*`, `?`, and `[...]` classes) |
| `-inum N` / `-inum N-M` | exact fileid, or an inclusive fileid range |
| `--limit N` | max results, `1..10000000` (default `10000`) |
| `--config PATH` | mds.conf path (default `/etc/pnfs-mds/mds.conf`) |
| `--json` | JSON-lines output |

## `mds-apid` (service)

Run it where it *can* reach the backend, and let clients that cannot call
it over HTTP.

```sh
mds-apid \
  --bind 10.0.0.10 --port 9810 \
  --config /etc/pnfs-mds/mds.conf \
  --tls-cert /etc/pnfs-mds/apid.crt \
  --tls-key  /etc/pnfs-mds/apid.key \
  --token-file /etc/pnfs-mds/apid.token
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--bind ADDR` | `127.0.0.1` | IPv4 address to listen on |
| `--port N` | `9810` | TCP port |
| `--config PATH` | `/etc/pnfs-mds/mds.conf` | backend configuration |
| `--token-file PATH` | — | bearer token; required for `/api/v1/…` when set |
| `--tls-cert PATH` | — | server certificate (PEM) |
| `--tls-key PATH` | — | server private key (PEM) |
| `--tls-ca PATH` | — | CA bundle used to verify client certificates |
| `--require-client-cert` | off | require a client certificate (mutual TLS) |
| `--insecure` | off | allow a non-loopback bind without TLS |

Generate a token:

```sh
umask 077
head -c 32 /dev/urandom | base64 > /etc/pnfs-mds/apid.token
chmod 600 /etc/pnfs-mds/apid.token
```

### Guardrails

- **Cleartext exposure is refused.** Binding anything other than loopback
  without TLS fails at startup unless `--insecure` is passed, so a
  mistaken `--bind 0.0.0.0` cannot quietly serve the catalogue to the
  network.
- **Weak token files are refused.** A token file readable by group or
  other is rejected at startup.
- **Tokens are compared in constant time**, over a fixed-length window,
  so neither the token's length nor its content leak through timing.
- **Unknown query parameters are rejected.** A typo like `mtime_afetr`
  returns 400 rather than silently widening the search.

### Endpoints

`GET /healthz` — liveness probe, never requires a token, returns `ok`.

`GET /api/v1/find` — search. All parameters optional and AND-combined.

| Param | Example | Meaning |
| --- | --- | --- |
| `type` | `type=f` | file type: `f`, `d`, `l`, `b`, `c`, `p`, `s` |
| `name` | `name=%2A.parquet` | entry-name glob; URL-encode `*` as `%2A` |
| `size_gt` | `size_gt=1048576` | size ≥ N bytes |
| `size_lt` | `size_lt=4096` | size ≤ N bytes |
| `mtime_after` | `mtime_after=1750000000` | mtime ≥ epoch seconds |
| `mtime_before` | `mtime_before=1750000000` | mtime ≤ epoch seconds |
| `ctime_after` / `ctime_before` | | same, for ctime |
| `uid` / `gid` | `uid=1000` | owner uid / gid |
| `inum` | `inum=1234` | exact fileid, or the low end of a range |
| `inum_max` | `inum_max=2000` | high end of a fileid range |
| `limit` | `limit=500` | max results, `1..10000000` (default `10000`) |

Time bounds are **absolute epoch seconds**; the CLIs take relative days
and convert for you.

Response:

```json
{"results":[
  {"fileid":1234,"type":"f","mode":"rw-r--r--","nlink":1,
   "uid":1000,"gid":1000,"size":2147483648,
   "mtime_sec":1750000000,"ctime_sec":1750000000,
   "parent_fileid":12,"name":"big.parquet"}
],"count":1,"truncated":false}
```

`truncated` is `true` when the service stopped early to stay under its
32 MiB response cap; narrow the query or lower `limit`. Errors return
`{"error":"…"}` with `400` (bad parameter), `401` (missing/invalid
token), `404` (unknown endpoint), or `405` (non-GET).

### systemd unit

```ini
[Unit]
Description=Lattice read-only metadata query API
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/mds-apid --bind 10.0.0.10 --port 9810 \
          --config /etc/pnfs-mds/mds.conf \
          --tls-cert /etc/pnfs-mds/apid.crt \
          --tls-key /etc/pnfs-mds/apid.key \
          --token-file /etc/pnfs-mds/apid.token
User=pnfs-mds
Group=pnfs-mds
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

## `lattice-find` (client)

Same predicate syntax as `mds-find`, but over HTTP. Requires `bash` and
`curl`; `jq` is optional and gives a readable table instead of raw JSON.

Pre-seed the fleet once via `/etc/profile.d/lattice-find.sh`:

```sh
export LATTICE_API_URL=https://lattice-api.internal
export LATTICE_API_TOKEN_FILE=/etc/pnfs-mds/apid.token
```

Then:

```sh
lattice-find -type f -size +1G -name '*.parquet'
lattice-find -uid 1000 -mtime +90 --limit 500
lattice-find --json -inum 1000-2000
lattice-find --dry-run -type d -name 'project-*'   # inspect, send nothing
```

The token is passed to `curl` through a config file on stdin, so it never
appears in the process list or on disk. `--dry-run` prints the request
without the token's value.

## Performance and operational limits

**Every query is a full fragment scan.** Predicate pushdown means
non-matching rows are discarded on the data nodes and never cross the
wire, which cuts bandwidth dramatically — but it does not reduce the rows
scanned. Cost is O(rows scanned), and that work competes with the NFS hot
path for backend CPU.

Consequences worth planning around:

- Run `mds-apid` on an admin node with its own backend API slot rather
  than on a busy MDS.
- Keep broad queries bounded with `limit`.
- Scans use committed-read semantics and take no row locks, so a query
  cannot block a mutation. It can still compete for CPU.
- The service handles one request at a time. Queries are scans, so
  serving them concurrently multiplies backend load instead of reducing
  latency. Front it with a proxy if you need concurrency.

This is far better than an NFS namespace walk, but it is not the
sub-second billion-file behaviour targeted by the GUFI mirror design in
[`design-gufi-integration.md`](design-gufi-integration.md) — that
document's Option B, chosen here for its much lower cost and complexity.
The two are complementary: this answers ad-hoc queries today with no
extra storage and no sync lag, while a mirror remains the route to
interactive analytics at extreme scale.

## Behaviour notes

- **Results are in backend scan order**, which is not stable between
  runs. Sort client-side if you need determinism.
- **Names, not paths.** Each result carries `parent_fileid` and the entry
  name. Reconstructing a full path costs one keyed read per ancestor per
  result, so it is not done by default. A result whose name cannot be
  resolved (the root, or an entry removed concurrently with the scan) is
  reported as `?` by the CLIs and as `""` by the API.
- **Name matching is exact `fnmatch(3)`**, matching find(1) — including
  `[...]` classes and `*` matching a leading dot. The backend LIKE filter
  is only ever a bandwidth optimisation and is deliberately built as a
  superset, so it can never change which entries match.
- **An exact `-inum N` is served by a single keyed read**, not a scan.
