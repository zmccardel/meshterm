# meshterm

An interactive Meshtastic client for the terminal. One C file, no
dependencies beyond libc and POSIX. Compiles with `cc`/`gcc` and runs 
anywhere you have a serial port.

```
$ meshterm -p /dev/cuaU0
-!- connecting to /dev/cuaU0
-!- connected as koi
-!- /help for commands
21:14:02 #LongFast <HILL> anyone up on the ridge?
[#LongFast] on my way
```

It talks to the radio module directly — the StreamAPI framing and the 
protobuf encoding are implemented in the file. There is no protobuf 
library, no curses, no runtime, and nothing to install on the module.

## What it does

- Send and receive messages on any channel, and direct messages to a node
- Create, delete, share and join channels, including `meshtastic.org/e/#`
  share URLs
- Set the node name, LoRa region, WiFi credentials and Bluetooth on/off
- Connect over USB serial or over TCP port 4403 to a WiFi-enabled node
- Reconnect automatically when the node reboots

Enough to take a freshly flashed board from nothing to talking:

```
/region US
/name Ridge Repeater RIDG
```

## Building
**BSD**
```
cc -O2 -o meshterm meshterm.c
```
**Linux**
```
gcc -O2 -o meshterm mestherm.c
```

## Usage

```
meshterm [-p port] [-b baud] [-c rcfile] [-v] [-t|-T] [-x] [-C] [-m message]
```

| flag | meaning |
| --- | --- |
| `-p` | serial device, or `tcp:HOST[:PORT]` (default port 4403) |
| `-b` | serial speed, default 115200 |
| `-c` | settings file, default `~/.meshtermrc` |
| `-v` | verbose: firmware log output and protocol detail |
| `-t` / `-T` | timestamps on / off |
| `-x` | show hex node ids alongside names |
| `-C` | disable colour |
| `-m` | send one message and exit |

Typing a line sends it to the current channel or direct-message target.
Lines starting with `/` are commands; `/help` lists them. Up and down
arrows walk the last 20 entries.

`-m` and piped input make it scriptable:

```
meshterm -p /dev/cuaU0 -m "gate closed at 2100"
echo "/nodes" | meshterm -p /dev/cuaU0
```

Messages go to stdout and status to stderr, so `meshterm -p /dev/cuaU0 >
mesh.log` keeps a clean transcript while you watch progress on the
terminal.

## Serial ports

**FreeBSD / OpenBSD.** Use the callout device, `/dev/cuaU0`, not
`/dev/ttyU0` — the dial-in device blocks waiting for carrier detect. Add
yourself to the `dialer` group and log back in:

```
# pw groupmod dialer -m yourname
```

The USB-to-UART bridge drivers are in the base system. `uslcom(4)` covers
CP210x (Heltec, most ESP32 boards), `uftdi(4)` covers FTDI, `uchcom(4)`
covers CH340, and `umodem(4)` covers boards with native USB.

**Linux.** ESP32 boards with a bridge chip appear as `/dev/ttyUSB0`.
Boards with native USB — nRF52840, RP2040, ESP32-S3 and C3 — appear as
`/dev/ttyACM0`. The `cp210x`, `ftdi_sio`, `ch341` and `cdc_acm` drivers
are all in-tree and load on hotplug. Add yourself to `dialout`:

```
# usermod -aG dialout yourname
```

If nothing appears at all, try a different USB cable. Charge-only cables
have no data lines and are the single most common cause.

## Settings

`/set` adjusts display preferences and `/save` writes them to
`~/.meshtermrc`, one `key value` pair per line:

```
time on
names on
hex off
color on
verbose off
passkey off
mute !1234abcd
```

These are local to meshterm and never sent to the radio. Radio
configuration is separate and lives under the commands listed as *radio
config* in `/help`.

## Notes

A channel share URL contains the encryption key. Anyone who reads it can
join the channel and decrypt its traffic — treat it the way you would
treat the key itself.

`/wifi <ssid> <password>` puts the password in your terminal scrollback,
and in your shell history if you pass it with `-m`.

Enabling WiFi on an ESP32 disables Bluetooth; the two radios cannot run at
once. Config changes that touch the network reboot the node, which drops
the session — meshterm reconnects on its own.

Set the LoRa region before expecting a new board to transmit. Until it is
set the firmware stays silent. Region and modem preset must match on both
ends or the radios cannot hear each other at all.

## Compatibility

Any board running Meshtastic firmware. Developed against 2.6, and written
to tolerate version drift: unknown protobuf fields are preserved on
config writes rather than discarded, and unrecognised enum values are
reported by number instead of being dropped.

The terminal handling is plain VT100 — no 256-colour sequences, no
alternate screen, no cursor addressing beyond erase-line and
cursor-left — so it degrades to clean monochrome on hardware terminals
and serial consoles.

## Licence

Zero-clause BSD. Do whatever you like with it.

Meshtastic® is a registered trademark of Meshtastic LLC. This is an
unofficial third-party client, not affiliated with or endorsed by that
project. No Meshtastic source code is included here; the wire format is
implemented from the published protocol description.
