# The Sentinel agent protocol

Version 2. This is what the agent answers and what the apps may rely on.

## Transport

The app opens one SSH session to the server and sends one *exec request* per call. The key it
uses is installed as a forced command:

```
restrict,command="/usr/local/bin/sentinel-agent" ssh-ed25519 AAAA… sentinel-iphone
```

so the command line the app sends never reaches a shell. It arrives in `$SSH_ORIGINAL_COMMAND`,
is split with `shlex`, and is held to the whitelist below. At most 4 arguments, each at most 128
characters.

Every call prints **exactly one line of JSON** on stdout and exits 0. A failure is
`{"ok": false, "error": "…"}`, not an exit status: the app has to render something either way.
The app reads the last line that starts with `{`, so a login banner printed before it is
harmless.

## Compatibility rules

- **Fields are only ever added.** A field keeps its name, its type and its meaning for as long as
  the protocol number is 2 or lower. Apps decode leniently: an unknown field is ignored and a
  missing one takes its default. A field that changed shape would silently blank a screen, so that
  never happens.
- `protocol` goes up when something is added that a client may want to test for. Version 1 is
  agent 1.x (the single-server R620 edition). Version 2 is agent 2.x.
- Numbers may arrive as `126` or `126.0`. Clients accept both.
- `null` means "not known", never zero. A fan at 0 RPM is an emergency; a fan nobody can read is
  a quirk.

## Commands

| Command | What it does | Cost |
|---|---|---|
| `ping` | identity, version, what this agent can do | instant |
| `snapshot` | everything the main screens show | ~0.3 s (one CPU sample) |
| `brief` | `snapshot` without rates, container stats or process list | ~0.1 s + stale checks |
| `checks` | every check, refreshing those older than `checks_interval_s` | up to ~3 s |
| `hw` | the full hardware detail | up to ~2 s with a BMC; cached `hw_cache_s` |
| `sel [n]` | the BMC event log, newest first | ~1 s, IPMI only |
| `logs <unit> [n]` | journal lines of a watched unit | |
| `dlogs <container> [n]` | log lines of a watched container | |
| `action <start\|stop\|restart> <unit>` | control a unit on the control list | |
| `daction <start\|stop\|restart> <container>` | control a container on the control list | |
| `check <start\|stop\|restart\|sleep> <key>` | control a check (a game server) | up to 8 min |
| `game …` | the protocol-1 name of `check` | |

## `ping`

```json
{
  "ok": true, "version": "2.0.0", "protocol": 2,
  "hostname": "web1", "time": 1761400000,
  "control": true,
  "units": ["nginx.service", "postgresql@16-main.service"],
  "containers": ["app", "redis"],
  "control_units": ["nginx.service"],
  "control_containers": ["app"],
  "features": ["checks", "sensors", "smart"],
  "controls": {"mc": ["restart", "start", "stop"]},
  "model": {"vendor": "Dell Inc.", "name": "PowerEdge R620", "virt": null},
  "unwatched": 2
}
```

- `features` lists what this server has, from `checks`, `sensors`, `ipmi`, `smart` and `gpu`.
  A client hides what is not listed.
- `controls` maps a check's key to the verbs it allows. It is empty when control is off.
- `control_units` and `control_containers` are what `action` and `daction` accept. Protocol-1
  agents did not send them; a client that finds them missing treats every watched unit as
  controllable when `control` is true.
- `model.virt` names a hypervisor (`kvm`, `vmware`, `microsoft`, …) when the server is a VM.
- `unwatched` counts the containers that exist but are not watched. The installer's `--detect`
  adds them.

## `snapshot`

Everything protocol 1 had, unchanged, plus `hardware`, `control_units`, `control_containers`
and `unwatched`.

```json
{
  "ok": true, "version": "2.0.0", "protocol": 2, "time": 1761400000,
  "control": true, "controls": {"mc": ["restart", "start", "stop"]},
  "control_units": ["…"], "control_containers": ["…"], "unwatched": 0,
  "host": {
    "hostname": "web1", "uptime_s": 86400, "load": [0.12, 0.2, 0.18], "ncpu": 4,
    "cpu_pct": 7.5, "cores": [5.0, 9.1, 6.2, 9.7], "window_s": 5.0,
    "psi_cpu": 0.5, "psi_io": 0.0, "psi_mem": 0.0,
    "mem": {"total_mb": 7951, "used_mb": 2100, "available_mb": 5851, "cached_mb": 3900,
            "swap_total_mb": 2047, "swap_used_mb": 0},
    "disks": [{"mount": "/", "device": "/dev/sda1", "total_gb": 80.0, "used_gb": 21.4,
               "free_gb": 55.2, "used_pct": 31.0}],
    "net": [{"iface": "eth0", "rx_bps": 1200.0, "tx_bps": 800.0, "rx_total": 123, "tx_total": 456}],
    "top": [{"pid": 1234, "name": "postgres", "cpu_pct": 3.1, "rss_mb": 120.5}],
    "primary_iface": "eth0"
  },
  "hardware": { … see below … },
  "hw": { … protocol 1, BMC only … },
  "hw_error": null, "hw_source": "bmc",
  "services": [{"unit": "nginx.service", "description": "…", "active": "active", "sub": "running",
                "enabled": "enabled", "loaded": "loaded", "restarts": 0, "mem_mb": 12.0,
                "pid": 812, "since": "Fri 2026-10-24 21:00:01 CET", "result": "success"}],
  "docker": {"error": null, "list": [{"name": "app", "image": "ghcr.io/x/app:1", "state": "running",
             "status": "Up 3 days (healthy)", "health": "healthy", "running_for": "3 days ago",
             "cpu_pct": 0.4, "mem": "120MiB / 7.7GiB", "mem_pct": 1.5}]},
  "games": [], "sites": [], "status_error": null
}
```

- `primary_iface` is the interface of the default route, not a configured name.
- `hw`, `hw_error` and `hw_source` are the protocol-1 BMC summary. They are `null` on a server
  without a BMC. New clients read `hardware` instead.
- `games`, `sites` and `status_error` come from a `dashboard` check (below) and are empty without
  one. New clients read `checks` instead. `status_error` is only ever set when a dashboard check
  exists and did not answer.

### `hardware`

One block for every source. A source that is not configured is absent from `sources`; one that
is configured but failed carries its error.

```json
{
  "model": {"vendor": "Dell Inc.", "name": "PowerEdge R620", "virt": null},
  "sources": {"sensors": null, "ipmi": null, "smart": null, "gpu": "nvidia-smi: not found"},
  "temps": [
    {"label": "Package id 0", "group": "cpu", "celsius": 51.0, "warn": 87.0, "crit": 97.0, "source": "sensors"},
    {"label": "Inlet", "group": "inlet", "celsius": 22.0, "warn": 42.0, "crit": 47.0, "source": "ipmi"}
  ],
  "fans": [{"label": "Fan 1A", "rpm": 4680.0, "source": "ipmi"}],
  "watts": 126.0,
  "drives": [{"device": "/dev/sda", "model": "ST4000NM0035", "health": "passed", "celsius": 33.0,
              "hours": 41022, "wear_pct": null, "realloc": 0, "pending": 0, "state": "active",
              "age_s": 640}],
  "gpus": [{"index": 0, "name": "NVIDIA GeForce RTX 4060 Ti", "celsius": 41.0, "util_pct": 3.0,
            "mem_used_mb": 812.0, "mem_total_mb": 16380.0, "watts": 14.2, "fan_pct": 0.0}]
}
```

- `sources` maps each configured source to `null` when it answered and to an error string when
  it did not.
- `temps` carries every temperature from every source. Each one has:
  - `group` — one of `cpu`, `board`, `drive`, `gpu`, `inlet`, `exhaust`, `other`;
  - `warn` and `crit` — the sensor's own thresholds (hwmon `_max`/`_crit`, the thermal zone's
    trip points, the config's overrides), or `null`. The app falls back to its defaults: CPU
    80/90, drive 55/65, GPU 85/95, inlet 42/47;
  - `status` — what a BMC itself makes of the reading against its own thresholds: `ok`,
    `warn` (non-critical) or `crit` (critical / non-recoverable). It is `null` for sources that
    have no opinion. When it is set it wins over the numbers, which is how any vendor's
    thresholds reach the app without anybody typing them in.
- `fans` are in RPM, and carry the same `status`. The kernel's own sensors leave out fans reading
  0: a Super-I/O chip reports 0 for every empty header, so a 0 there means nothing. A BMC's 0 is
  kept, because it is real.
- `watts` is the chassis draw from a BMC, or `null`.
- `drives` come from SMART, read with `-n standby` so a sleeping disk is never spun up. Each one
  has:
  - `state` — `active`, `standby` (the last reading is kept) or `error`;
  - `health` — `passed`, `failed` or `null`;
  - `wear_pct` — NVMe "percentage used", `null` for SATA;
  - `realloc` and `pending` — the reallocated and pending sector counts;
  - `age_s` — how old the reading is (SMART is read at most every 30 minutes per drive).

## `brief`

The same shape as `snapshot` without the expensive parts. It does not have:

- `host.cpu_pct`, `host.cores`, `host.top` and `host.net` (they need a second sample);
- `docker.list[].cpu_pct`, `mem` and `mem_pct` (`docker stats` blocks for a second);
- any hardware source other than kernel sensors, which are read fresh. The other sources come
  from cache.

It adds `checks` (as in `checks`, refreshing stale ones), so a background check needs one call.

## `checks`

```json
{
  "ok": true,
  "checks": [
    {"key": "site", "kind": "http", "label": "example.com", "target": "https://example.com",
     "up": true, "state": "up", "ms": 84, "error": null, "hint": null,
     "detail": {"code": 200, "cert_days": 61},
     "controls": [], "container": null, "hints": {}, "checked": 1761400000},
    {"key": "mc", "kind": "minecraft", "label": "Minecraft", "target": "127.0.0.1:25565",
     "up": true, "state": "up", "ms": 3, "error": null, "hint": null,
     "detail": {"online": 2, "max": 20, "version": "1.21.10", "motd": "…"},
     "controls": ["restart", "start", "stop"], "container": null,
     "hints": {"start": "about a minute until it can be joined"}, "checked": 1761400000}
  ]
}
```

- **`kind`** is one of:
  - `http` — `detail.code`, plus `detail.cert_days` for https;
  - `tcp` — no detail;
  - `minecraft` — `detail.online`, `max`, `version` and `motd`;
  - `a2s` — the Steam query: `detail.online`, `max`, `map`, `name` and `version`;
  - `game` and `site` — imported from a dashboard check, carrying the dashboard's own fields in
    `detail`. The dashboard's `uptime` is copied to the top level.
- **`state`** is `up` or `down`. A dashboard may also say `sleeping`, `waking` or `paused`: none
  of these is an outage, so none of them is an alert.
- **`controls`** are the verbs `check` accepts for this key, `[]` when control is off.
  `container` names the watched container the check runs in: that container is never stopped or
  restarted bare, only through the check. `unit` names the watched unit that runs it (for its
  logs). `hints` holds one plain sentence per verb, shown while it runs.
- **`checked`** is when the result was taken. Results are reused for `checks_interval_s` (60 s by
  default).

## `hw`

```json
{"ok": true, "age_s": 0, "error": null, "hw": { …protocol 1 BMC detail, or null… },
 "hardware": { …the full `hardware` block, every sensor… }, "sel": true}
```

`hw` is the protocol-1 BMC detail (`temps`, `fans`, `psus`, `watts`, `fan_redundancy`,
`ps_redundancy`) and is `null` without a BMC. `sel` says whether `sel` will work.

## Controls

- **`action` and `daction`** accept only units and containers on the control list. A **lifeline**
  can only be restarted, never stopped, because a phone that stops it can lock everyone out. The
  lifelines are ssh/sshd, tailscaled, NetworkManager, systemd-networkd, networking,
  wpa_supplicant, docker, containerd, cloudflared, wg-quick@…, openvpn… and zerotier-one.
- **`check <verb> <key>`** runs what the config says for that check:
  - `{"unit": "x.service"}` — `start` = `systemctl enable --now`, `stop` = `systemctl disable --now`
    (so a stopped game reads as switched off, not down), `restart` = `systemctl restart`;
  - `{"commands": {"start": [argv], …}}` — exactly those commands, through sudo. Only the verbs
    listed are offered.
- **Every answer** is `{"ok": true, …}` or `{"ok": false, "error": "…"}`. A unit action also
  returns the unit's new state as `state`.
