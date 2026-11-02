# Axion

Axion is a passive network traffic intelligence application written in Rust. It groups observed TCP and UDP packets into flows, extracts visible TLS ClientHello metadata, and presents local heuristics and optional Cloudflare Workers AI assessments in an embedded, local web dashboard.

Axion observes copies of traffic. It does **not** inject, modify, block, or decrypt packets. Detection is heuristic: a fingerprint, SNI, port, or model score does not prove that a connection uses a particular protocol. Test only networks and captures you are authorized to inspect.

## Quick start

```sh
axion
```

Axion loads your settings, starts the local dashboard, and attempts to select and capture from an interface. Open the URL printed in the terminal; the browser does not open automatically unless enabled in settings or with `--open-browser`. The default is `http://127.0.0.1:8080/`; if the port is occupied, Axion tries the next ten ports. A capture-permission or interface-selection error leaves the dashboard available so you can choose an interface or restart Axion in demo/replay mode. Press Ctrl+C to shut down.

```sh
axion interfaces                         # list capture interfaces
axion capture --interface auto --web-port 8080
axion capture --interface eth0           # choose a specific interface
axion demo                               # simulated data, no capture permission
axion replay --file capture.pcap         # offline data, no capture permission
axion --help
```

Demo traffic is explicitly marked as simulated; cloud analysis is disabled in demo mode. Replay reads the PCAP as quickly as it can process it and keeps the dashboard available afterwards. The pause control pauses display updates, not packet capture. In live mode the capture controls start, stop, restart, or switch a source; capture errors are displayed in the dashboard. Live capture controls are unavailable in demo and replay modes; restart Axion to change modes.

## Install a binary

Download an archive from [GitHub Releases](https://github.com/braydos-h/Axion/releases), when available. Release archives contain the executable, this README, and the GPL license; the dashboard assets are embedded in the executable. The automated release workflow targets Linux x86-64 and Linux ARM64 on native Ubuntu 24.04 runners; each archive is published only after its build and tests pass. Those binaries need a compatible Linux system with glibc 2.39 or later and the libpcap runtime. Windows and macOS release archives are not currently provided because their capture build and runtime setup has not been verified by this pipeline.

For example, on Ubuntu 24.04, download the archive for your architecture and the release's `SHA256SUMS`, then:

```sh
sudo apt-get update
sudo apt-get install libpcap0.8t64
sha256sum --ignore-missing --check SHA256SUMS  # run alongside your downloaded archive
# Substitute the actual version and architecture in the filename:
tar -xzf axion-v0.1.0-linux-x86_64.tar.gz
./axion
```

Older distributions may call the runtime package `libpcap0.8`; binaries built against newer glibc may need to be built from source on those systems. Install the executable in a directory on your `PATH` if desired. The checksum file lists every release archive; `--ignore-missing` verifies only archives you downloaded. Do not run the binary if verification fails.

## Build from source

Linux is the primary supported platform. Install a [Rust toolchain](https://rustup.rs/) and the libpcap development package:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libpcap-dev
cargo build --release --locked
./target/release/axion
```

Fedora users can install `gcc`, `pkgconf-pkg-config`, and `libpcap-devel`. On Windows, libpcap-compatible capture requires Npcap and its SDK at build time; on macOS, libpcap and the appropriate toolchain are required. These source builds are not covered by the release matrix. No source checkout or separate web files are required to run a built binary.

## Interface selection and permissions

`auto` prefers the interface whose address is used for the system route, then a single active non-loopback candidate. It does not exclude VPN or virtual adapters. If no suitable interface is found or the choice is ambiguous, select one in the dashboard or pass its name with `--interface`; `axion interfaces` shows available devices. Some adapters cannot be captured from even if they are listed. If an adapter disappears or capture fails, inspect the displayed error and select or restart a source.

Live capture requires permission to open the adapter. On Linux an administrator can grant the executable `CAP_NET_RAW` and `CAP_NET_ADMIN`, for example `sudo setcap cap_net_raw,cap_net_admin=eip /path/to/axion`; grant capabilities only if you understand the security implications. Rebuilding or replacing the executable may remove capabilities. Alternatively run it with appropriate administrator privileges. Containers may also need host networking and capture capabilities. Npcap must be installed on Windows. Demo and replay do not require live-capture privileges, although the libpcap runtime is still needed.

## Dashboard and configuration

The dashboard binds to loopback by default and has no built-in user authentication. Axion only accepts loopback bind addresses; remote access requires an independently authenticated, secured reverse proxy. Browser Host and origin checks protect local controls. Treat flow metadata as sensitive.

```sh
axion --web-port 8090        # preferred port; tries up to ten higher ports if occupied
axion --web-port 8080 --strict-port  # fail if 8080 is unavailable
axion --web-port 0           # let the operating system assign a port
axion --open-browser         # open the actual dashboard URL
axion --no-browser           # disable browser opening
```

The actual address and port are printed on startup. IPv6 loopback can be selected with `--web-host ::1` where supported. CLI arguments take precedence over environment variables, then saved settings, then defaults. The dashboard settings persist the preferred interface, automatic selection, host and port, browser and startup choices, AI state, flow limits, and logging preference. Settings that cannot be applied to the running listener or analysis worker require a restart; the interface identifies those settings.

The configuration file is user-specific:

- Linux: `$XDG_CONFIG_HOME/axion/config.json`, or `~/.config/axion/config.json` when `XDG_CONFIG_HOME` is unset.
- Windows: `%APPDATA%\axion\config.json`.
- macOS: `~/Library/Application Support/axion/config.json`.

Supported environment overrides include `AXION_WEB_HOST`, `AXION_WEB_PORT`, `AXION_MAX_FLOWS`, `AXION_FLOW_TIMEOUT_SECONDS`, and `AXION_AI_ENABLED`. `RUST_LOG` controls logging for the current run. Credentials are never saved in dashboard settings.

## Optional Cloudflare Workers AI

Local analysis works without Cloudflare. To use cloud analysis, set `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` in the process environment or in a local `.env` file (see `.env.example`). The token needs Workers AI permission. Enable AI in settings or set `AXION_AI_ENABLED=true`; the default model is `clef-flash` and can be changed using `AXION_AI_MODEL`. The indicator is offline until a request succeeds. `AXION_AI_MAX_REQUESTS_PER_MINUTE` controls the rate, defaulting to 30.

Only selected suspicious flow metadata is sent to the [Workers AI REST endpoint](https://developers.cloudflare.com/workers-ai/get-started/rest-api/), never raw payloads. By default IP addresses and hostnames are omitted; destination port, aggregates, and visible TLS metadata can still be sensitive. `AXION_AI_SHARE_IDENTITY=true` explicitly includes IP addresses and observed SNI. The bounded queue, request timeouts, and rate spacing keep cloud requests out of the capture loop. Model scores are separate from local heuristic scores and are not measured probabilities of correctness. Keep API credentials out of source control, logs, and shared configuration.

## CI and downloadable builds

On pushes to `main`, pull requests, and manual dispatch, the [Rust CI workflow](https://github.com/braydos-h/Axion/actions/workflows/rust.yml) runs formatting, Clippy, locked Rust tests, the Node.js dashboard contract test, a release build, and an unprivileged demo smoke test that compares all served web assets to the source files. The [Build binaries workflow](https://github.com/braydos-h/Axion/actions/workflows/build.yml) can be run manually; download its `axion-linux-x86_64` or `axion-linux-aarch64` artifact from the completed run. Both native jobs run locked tests and smoke-test the release executable before uploading versioned archives.

A tag such as `v1.0.0` starts the release workflow. It checks that the tag matches the package version, runs CI and both native builds, creates SHA-256 checksums, and creates a draft release. It publishes only after every expected asset has been uploaded and verified. Releases are not created retroactively; a tag must be pushed and the workflow must succeed. GitHub Actions availability and the resulting artifacts can be checked on the repository's Actions and Releases pages.

## Troubleshooting and limitations

- **Capture cannot start:** check interface selection, libpcap/Npcap installation, and capture permissions. Use `axion demo` or `axion replay --file ...` without elevated privileges. Promiscuous mode is not enabled.
- **Dashboard unavailable:** use the exact printed URL; try `--web-port 0` if ports are occupied. Check that another local process is not intercepting the requested address.
- **AI remains offline:** check credentials, token permissions, model availability, and network access. Local detection remains available.
- **Missing TLS details:** ECH, midstream capture, packet loss, fragmentation, unsupported link types, or incomplete handshakes can hide metadata. UDP/QUIC is not decrypted. The reported TLS version is the highest offered ClientHello version, not necessarily the negotiated version.
- **Drop counters:** capture-event drops indicate the flow worker could not keep up; libpcap or kernel drops may not be included. Flow views are bounded and expire after inactivity.
- **Interpretation:** first-observed and reverse directions are not necessarily host ingress and egress. Heuristics can flag ordinary traffic. No validated detection rate is claimed, and a Clef score is not proof of VLESS or REALITY.

For evaluation, use a consented, labelled set of benign and target sessions, split by session and environment. Record ground truth independently, replay captures, and measure precision, recall, and false-positive rate on an untouched test set. PCAPs may contain sensitive content; protect them accordingly.

Axion is licensed under [GPL-3.0-only](LICENSE).
