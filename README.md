# network_mitm

Nintendo Switch Network mitm sysmodule.

network_mitm allows you to:
- Dump traffic from SSL of the running game (NEX,...) in PCAP files.
- Mitm ssl to replace `NintendoClass2CAG3` CA with a user provided one (useful for NPLN traffic capture)

More features might appears depending of the needs.

## Building

Make sure that the submodules are initialized and up to date.

```bash
git submodule update --init --recursive
```

### With Docker

1. Install `Docker` and `docker compose` (or `docker-compose`).

2. Run `docker compose up --build` (or `docker-compose up --build`). It runs `make` in the container.

### Without Docker

1. Install [`devkitPro`](https://devkitpro.org/wiki/Getting_Started) and the following dependencies:
    - `switch-dev`
    - `switch-mbedtls`
    - `libnx` (Currently needs [16.0.0](https://github.com/switchbrew/libnx/pull/603) patches)

2. Run `make` command.

## Licensing

This software is licensed under the terms of the GPLv2.

You can find a copy of the license in the [LICENSE file](LICENSE).
