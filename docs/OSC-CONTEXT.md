---
title: OSC 300819: Hierarchial Context Signalling
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# OSC 300819: Hierarchial Context Signalling

A terminal connects a user with programs. Control of the program side of
terminals is typically passed around to various different components while the
user is active: a shell might pass control to a process it invokes. If that
process is `run0` then primary control is passed to the privileged session of
the target user. If `systemd-nspawn` is invoked to start a container primary
controls is passed to that container, and so on.

A terminal emulator might be interested to know which component is currently is
in primary control of the program side of a terminal. OSC 3000910 is a
mechanism to inform it about such contexts. Each component taking over control
can inform the terminal emulators that a new context begins now, and then use
the terminal or pass control down to further apps, which can introduce
contexts. Each context may carry various discriptive metadata fields.

## Status

This OS is invented by systemd. Currently, no terminal application is known
that consumes these sequences.

## Usecases

Terminal emulators can use hierarchial context information:

1. To introduce markers/bookmarks in the output that the user can jump between.

2. To visually identify output from different contexts. For example the
   background can be tinted in a reddish tone when privileges are acquired, and
   similar.

3. Meta information on specific output can be shown in a tooltip or similar

4. Programs (and all subcontexts) can be killed by right-clicking on the output
   they generate.

5. Failed commands or aborted sessions can be marked requesting use attention.

## Context Types

There are various types of contexts defined by this specification:

1. `boot` → a booted system initiates this context early at boot. (systemd's
   PID 1 generates this on `/dev/console`.)

2. `container` → a container managed initialized an interactive connection to a
   container. (`systemd-nspawn` generates this when interactively invoking a
   container. `machinectl login`, `machinectl shell` do this too.)

3. `vm` → a VMM initialized a terminal connection to VM. (`systemd-vmspawn`
   generates this when interactively invoking a VM, as one example.)

4. `elevate` → when the user interactively acquired higher privileges. (`run0`
   initiates a context of this type whenever the user invokes it to acquire
   root privileges.)

5. `chpriv` → similar, but when the user acquired *different* privileges, not
   necessarily higher ones. (`run0` initiates a context of this type whenever
   the user invokes it to acquire non-root privileges of another user.)

5. `subcontext` → similar, but the source and target privileges where
   identical. (`run0` initiates a context of this type whenever the user
   invokes it to acquire privileges of the user itself.)

6. `remote` → a user invoked a tool such as `ssh` to connect to a remote
   system.

7. `shell` → an interactive terminal shell initiates this context

8. `command` → a shell interactively invokes a new program.

9. `app` → an interactive program may initiate this context.

10. `service` → the service manager invokes an interactive service on the terminal

11. `session` → a login session of the user is initialized.

## Semantics

Contexts in the sense of OSC 300819 are hierarchial, and describe a tree
structure: whenever a new context is opened it becomes the new active context,
and the previously active context becomes its parent (if there is one). Only
one context is currently active, but previously opened contexts remain valid in
the background. Any other data written or read should be considered associated
with the currently active context.

Each context carries an identifier, chosen by the component opening the
context. The identifier can chosen freely, but must not be longer than 64
characters. The characters may be in the 32…126 byte range. Identifiers should universally
unique, for example randomly generated. A freshly generated UUID would work
well for this, but this could also be something like the Linux boot ID combined
with the 64bit inode number of Linux pidfds, or something hashed from it.

Fundamentally, there are two OSC 300819 commands defined:

1. OSC "`300819;S`" (the *start sequence*) → this initiates, updates or indicates a return to a
   context. It carries a context identifier, and typically some metadata. This
   may be send to first initiate a context. If sent again for the a context ID
   that was initiated already this indicates an update of the existing
   context. In this case, any previously set metadata fields for the context
   are flushed out, reset to their defaults, and then reinitialized from the
   newly supplied data. Also, in this case any subcontects of the contexts are
   implicitly terminated.

2. OSC "`300819;X`" (the *end sequence*)→ this terminates a context. It carries a context
   identifier to close, initiated before with OSC `300819;S`. It may also carry
   additional metadata.

## General Syntax

This builds on ECMA-48, and reuse the OSC and ST concepts introduced there.

For sequences following this specification it is recommended to encode OSC as
0x1B 0x5D, and ST as 0x1B 0x5C.

ECMA-48 only allows characters from the range 0x20…0x7e (i.e. 32…126) inside
OSC sequences. Hence, any fields that shall contain characters outside of this
range require escaping. All textual fields must be encoded in UTF-8, which
then must be escaped.

Escaping shall be applied by taking the byte values of the characters to
escape, and formatting them as lower-case hexadecimal prefixed with
`\x`. Example: `Schöpfgefäß` becomes `Sch\xc3\xb6pfgef\xc3\xa4\xc3\x9f`.

The start sequence begins with OSC, followed by the character `S`, followed by
the context ID. This is then followed by any number of metadata fields,
including none. Metadata fields begin with a semicolon (`;`) and end in a
character identifiying the type of field. The sequence ends in ST.

The end sequence begins with OSC, followed by the character `X`, followed by
the context ID, and a series of metadata fields in the the syntax as for the
start sequence.

## Metadata Fields

The following fields are currently defined:

| Suffix | Context Types | Description                                                                                                 |
|--------|---------------|-------------------------------------------------------------------------------------------------------------|
| `u`    | *all*         | UNIX user name the process issuing the sequence runs as                                                     |
| `h`    | *all*         | UNIX host name of the system the process issuing the sequence runs on                                       |
| `m`    | *all*         | The machine ID (i.e. `/etc/machine-id`) of the system the process issuing the sequence runs on              |
| `b`    | *all*         | The boot ID (i.e. `/proc/sys/kernel/random/boot_id`) of the system the process issuing the sequence runs on |
| `p`    | *all*         | The numeric PID of the process issuing the sequence, in decimal notation                                    |
| `P`    | *all*         | The 64bit inode number of the pidfd of the process issuing the sequence, in decimal notation                |
| `c`    | *all*         | The process name (i.e. `/proc/$PID/comm`, `PR_GET_NAME`) of the process issuing the sequence                |
| `v`    | `vm`          | The name of the VM being invoked                                                                            |
| `C`    | `container`   | The name of the container being invoked                                                                     |
| `U`    | `elevate`, `chpriv`, `vm`, `container`, `remote` | Target UNIX user name                                                    |
| `H`    | `remote`      | Target UNIX, DNS host name, or IP address                                                                   |

All fields are optional, including the context type. However, it is generally
recommended to always include the first 7 fields listed above, to make it easy
to pinpoint the origin of a context in a race-free fashion without any
ambiguities.

## Examples

1. A new container `foobar` has been invoked by user `lennart` on host `zeta`:
   `OSC "300819;Sbed86fab93af4328bbed0a1224af6d40;lennartu;zetah;3deb5353d3ba43d08201c136a47ead7bm;d4a3d0fdf2e24fdea6d971ce73f4fbf2b;1062862p;1063162P;foobarc;containert" ST`

2. A context ends: `OSC "300819;Xbed86fab93af4328bbed0a1224af6d40" ST`

## Syntax in ABNF

```abnf
OSC          = %x1B %x5D
ST           = %x1B %x5C

DECIMAL      = "0"-"9"
HEX          = "0"-"9" / "A"-"F" / "a-f"
ID128        = 32*36(HEX / "-")
UINT64       = 1*20DECIMAL
ESCAPED      = "\x" HEX HEX
SAFE         = %x20-3a / %x3c-5b / %x5d-7e / ESCAPED

CTXID        = 1*64SAFE

USER         = 1*255SAFE "u"
HOSTNAME     = 1*255SAFE "h"
MACHINEID    = 1D128 "m"
BOOTID       = ID128 "b"
PID          = UINT64 "p"
PIDFDID      = UINT64 "P"
COMM         = 1*255SAFE "c"

TYPE         = ("service" / "session" / "shell" / "command" / "vm" / "container" / "elevate" / "chpriv"  / "subcontext" / "remote" / "boot" / "app") "t"

SESSIONID    = 1*255SAFE "s"
CWD          = 1*255SAFE "d"
CMDLINE      = *255SAFE "L"
VMNAME       = 1*255SAFE "v"
CONTAINERNAME= 1*255SAFE "C"
TARGETUSER   = 1*255SAFE "U"
TARGETHOST   = 1*255SAFE "H"
APPID        = 1*255SAFE "A"

STARTFIELD   = (USER / HOSTNAME / MACHINEID / BOOTID / PID / PIDFDID / COMM / TYPE / SESSIONID / CWD / CMDLINE / VMNAME / CONTAINERNAME / TARGETUSER / TARGETHOST / APPID)
STARTSEQ     = OSC "300819;" CTXID "S" *(";" STARTFIELD) ST

EXIT         = "success" / "failure" / "crash" / "interrupt"
STATUS       = UINT64
SIGNAL       = "SIGBUS" / "SIGTRAP" / "SIGABRT" / "SIGSEGV" / …

ENDFIELD     = (EXIT / STATUS / SIGNAL)
ENDSEQ       = OSC "300819;" CTXID "X" *(";" ENDFIELD) ST
```

## Known OSC Prefixes

Here's a list of OSC prefixes used by the various sequences currently in public
use in various terminal emulators. It's not going to be complete, but I tried
to do some reasonably thorough research to avoid conflicts with the new OSC
sequence defined above.

| OSC Prefix      | Purpose                                                    |
|----------------:|------------------------------------------------------------|
|     `OSC "0;…"` | Icon name + window title                                   |
|     `OSC "1;…"` | Icon name                                                  |
|     `OSC "2;…"` | Window title                                               |
|     `OSC "3;…"` | X11 property                                               |
|     `OSC "4;…"` | Palette                                                    |
|     `OSC "5;…"` | Special palette                                            |
|     `OSC "6;…"` | Disable special color                                      |
|     `OSC "7;…"` | Report cwd                                                 |
|     `OSC "8;…"` | Hyperlink                                                  |
|     `OSC "9;…"` | Progress bar (conemu) [conflict: also growl notifications] |
|    `OSC "10;…"` | Change colors                                              |
|    `OSC "11;…"` | "                                                          |
|    `OSC "12;…"` | "                                                          |
|    `OSC "13;…"` | "                                                          |
|    `OSC "14;…"` | "                                                          |
|    `OSC "15;…"` | "                                                          |
|    `OSC "16;…"` | "                                                          |
|    `OSC "17;…"` | "                                                          |
|    `OSC "18;…"` | "                                                          |
|    `OSC "19;…"` | "                                                          |
|    `OSC "21;…"` | Query colors (kitty)                                       |
|    `OSC "22;…"` | Cursor shape                                               |
|    `OSC "46;…"` | Log file                                                   |
|    `OSC "50;…"` | Set font                                                   |
|    `OSC "51;…"` | Emacs shell                                                |
|    `OSC "52;…"` | Manipulate selection data (aka clipboard)                  |
|    `OSC "60;…"` | Query allowed                                              |
|    `OSC "61;…"` | Query disallowed                                           |
|    `OSC "99;…"` | Notifications (kitty)                                      |
|   `OSC "104;…"` | Reset color                                                |
|   `OSC "105;…"` | Enable/disable special color                               |
|   `OSC "110;…"` | Reset colors                                               |
|   `OSC "111;…"` | "                                                          |
|   `OSC "112;…"` | "                                                          |
|   `OSC "113;…"` | "                                                          |
|   `OSC "114;…"` | "                                                          |
|   `OSC "115;…"` | "                                                          |
|   `OSC "116;…"` | "                                                          |
|   `OSC "117;…"` | "                                                          |
|   `OSC "118;…"` | "                                                          |
|   `OSC "119;…"` | "                                                          |
|   `OSC "133;…"` | Prompt/command begin/command end (finalterm/iterm2)        |
|   `OSC "440;…"` | Audio (mintty)                                             |
|   `OSC "633;…"` | vscode action (Windows Terminal)                           |
|   `OSC "666;…"` | "termprop" (vte)                                           |
|   `OSC "701;…"` | Locale (mintty)                                            |
|   `OSC "777;…"` | Notification (rxvt)                                        |
|  `OSC "7704;…"` | ANSI colors (mintty)                                       |
|  `OSC "7750;…"` | Emoji style (mintty)                                       |
|  `OSC "7770;…"` | Font size (mintty)                                         |
|  `OSC "7771;…"` | Glyph coverage (mintty)                                    |
|  `OSC "7721:…"` | Copy window title (mintty)                                 |
|  `OSC "7777;…"` | Window size (mintty)                                       |
|  `OSC "9001;…"` | Action (Windows Terminal)                                  |
|  `OSC "1337;…"` | iterm2 multiplex seeuqnece                                 |
|  `OSC "5522;…"` | Clipboard (kitty)                                          |
| `OSC "30001;…"` | Push color onto stack (kitty)                              |
| `OSC "30101;…"` | Pop color from stack (kitty)                               |
| `OSC "77119;…"` | Wide chars (mintty)                                        |
|-----------------|------------------------------------------------------------|
