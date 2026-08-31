Full option reference: `man tape` (or `tape.1` in this repo).

## Description

`tape` requests virtual tape mounts and detaches from IBM Tape Manager for
z/VM, via a CMS Tape Proxy server, on behalf of a Linux guest. It manages
device node ownership so that the requesting user — and only that user — can
access the tape once mounted, and communicates with the proxy over TCP/IP
(optionally TLS) or an AF_IUCV socket.

Beyond mount/detach, `tape` provides convenience commands for Standard Label
tapes: `write`/`read` for moving one labeled file to/from tape, `scan`/`map`
for locating and cataloging files by dataset name, and `verify` for
checksumming what's on tape. These are deliberately basic — enough to make
tape usable as a backup and file-exchange medium from Linux, not a
reimplementation of full mainframe tape-management semantics.

`tape write` and `tape read` fall back to stdin/stdout when `--in`/`--out`
aren't given, so they compose directly with `tar` and similar tools for
whole-filesystem backup and restore.

## Requirements

- A running CMS Tape Proxy server, reachable via TCP/IP or AF_IUCV
- Linux guest under z/VM with the `tape390` channel-attached tape driver
- OpenSSL (`libssl`, `libcrypto`) for TLS transport and sha256 checksums
- `chccwdev` and `vmcp` available on `$PATH`
- `tape` installed setuid root, group `tapes`; only `tapes` group members can mount

## Usage Highlights

**Mount a tape, write a file, detach:**
```sh
tape mount --vol ABC123 --write
tape write --dsn PAYROLL --in payroll.dat
tape detach
```

**Mount a scratch tape and let the system pick a free device:**
```sh
tape mount
```

**Back up a directory tree via `tar`, with a checksum:**
```sh
tar cf - /home | tape write --dsn HOME_BACKUP --extra
```

**Restore everything, or just one file, from a backup:**
```sh
tape scan --dsn HOME_BACKUP
tape read | tar xf - -C /restore

tape scan --dsn HOME_BACKUP
tape read | tar xf - -C /restore home/arty/one.txt
```

**Add another backup after the first, without disturbing it:**
```sh
tar cf - /var | tape write --dsn VAR_BACKUP --append
```

**Verify a backup against the original source data (strongest check):**
```sh
tape scan --dsn HOME_BACKUP
tape verify -C "$(tar cf - /home | sha256sum | cut -d' ' -f1)"
```

**Catalog everything on a tape:**
```sh
tape map
```

**Locate and read the third file sharing a dataset name:**
```sh
tape scan -f PAYROLL -n 3
tape read -o payroll3.dat
```

**Replace a file in place (and everything physically after it):**
```sh
tape scan --dsn PAYROLL --before
tape write --in newpayroll.dat --dsn PAYROLL
```

**Recover after an interrupted mount:**
```sh
tape reset
```

## Building and Installing

```sh
make
sudo make install
```

Requires the `tapes` group to exist beforehand:
```sh
sudo groupadd tapes
sudo usermod -aG tapes <username>
```

See `man tape` for the full command reference, configuration file format
(`tape.conf`), Standard Label handling details, and security notes.

## License

