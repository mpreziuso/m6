# Third-party notices

M6's own code is licensed MIT (see [LICENSE](LICENSE)). This repository also
embeds and adapts code from the **Google Fuchsia** project to provide Linux
binary compatibility (Starnix). Every forked Fuchsia source file here carries a
`Use of this source code is governed by a BSD-style license` header, so the code
is governed by Fuchsia's root `/LICENSE` — the 2-Clause BSD License, reproduced
verbatim in [LICENSE.fuchsia](LICENSE.fuchsia). Per Fuchsia's licensing policy,
BSD-licensed Fuchsia code also carries an additional patent grant
(`/PATENTS`), reproduced verbatim in [PATENTS.fuchsia](PATENTS.fuchsia).

Upstream source: <https://fuchsia.googlesource.com/fuchsia> (Starnix lives under
`//src/starnix`). Per-file `Copyright ... The Fuchsia Authors` headers are
retained in the forked sources.

## Forked from Fuchsia — BSD-2-Clause

These crates contain source ported or forked from Fuchsia, adapted for M6
(`no_std`, ARM64, M6 capabilities). Their `Cargo.toml` declares
`license = "BSD-2-Clause"`.

- `m6-starnix` — the Starnix core (forked `//src/starnix/kernel`)
- `m6-starnix-uapi`, `m6-starnix-types`, `m6-starnix-syscalls`, `m6-starnix-ext`
- `m6-starnix-sync`, `m6-starnix-lifecycle`, `m6-starnix-registers`
- `m6-starnix-range-map`, `m6-starnix-usercopy`, `m6-starnix-memory-pinning`
- `m6-starnix-page-buf`, `m6-starnix-stack`, `m6-starnix-task-command`
- `m6-starnix-atomic-bitflags`, `m6-starnix-expando`, `m6-starnix-split-enum-storage`
- `m6-starnix-elf-parse`, `m6-starnix-line-discipline`, `m6-starnix-mapped-clock`
- `m6-starnix-time-pretty`, `m6-starnix-extended-pstate`
- `m6-starnix-filter-methods-macro`

Vendored Fuchsia-crate shims under `m6-starnix/vendor/` (`fuchsia_async`,
`fuchsia_inspect`, `fuchsia_runtime`, `fuchsia_scheduler`, `fuchsia_trace`,
`process_builder`, `syncio`) are likewise BSD-2-Clause — minimal stand-ins for
the upstream Fuchsia crates of the same name.

## M6-original — MIT

These crates are M6-authored. They mirror a Fuchsia (or `std`) public API so the
forked code compiles unchanged, but contain no copied Fuchsia source; they
inherit the workspace MIT license.

- `m6-zx-shim` — Zircon (`zx::`) API backed by M6 capabilities
- `m6-starnix-std` — a `std`-like surface over `core`/`alloc`
- `m6-starnix-logging`, `m6-starnix-crypt`, `m6-starnix-flyweights` — stubs /
  reimplementations of the Fuchsia crates of the same name
- `m6-fuchsia-rcu`, `m6-fuchsia-rcu-collections`, `m6-starnix-rcu` —
  single-CPU reimplementations of the Fuchsia RCU crates
- `m6-starnix/vendor/fragile` — reimplementation of the third-party `fragile`
  crate (itself Apache-2.0/MIT)
