# network_mitm

Nintendo Switch Network MITM sysmodule.

network_mitm allows you to:
- Disable verification of servers' SSL certificates.
- Dump decrypted traffic from the running game (NEX, NPLN, etc.) in PCAP files.
- Replace Nintendo CAs with a user provided one for more secure SSL proxy MITM.

More features might appear depending on user needs. Please create an issue/PR if you have an idea!

## Configuration
The following configuration should be added to `/atmosphere/config/system_settings.ini`:

```ini
; network_mitm config
[network_mitm]
; Enable SSL: this should be set to 1 for any of the options below to be active.
enable_ssl = u8!0x1
; Disable SSL verification: this should be set to 1 if you wish to disable certificate validity checks.
; Useful for instance for SSL proxy MITMing purposes for programs using nn::ssl BSD-style sockets.
; This does not impact browser traffic, see the next option to help with that.
; Careful: anyone on the network could see your console's full traffic if they can intercept your traffic.
disable_ssl_verification = u8!0x1
; Root CA filename: replaces Nintendo CAs with the specified CA in DER form.
; This should be present in the root of the SD (sd:/rootCA.der for the below example)
; Leave commented to disable.
custom_ca = str!rootCA.der
; Dump decrypted network traffic user-link PCAPs to the SD card.
; Note: this isn't possible currently due to a bug (likely threading-related).
should_dump_ssl_traffic = u8!0x1
; Possible values "ethernet", "ip" or "user"
pcap_link_type = str!user
```

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
