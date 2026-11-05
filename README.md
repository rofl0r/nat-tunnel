NAT Tunnel
----------

NOTE: The old Python version is final and unmaintained.
Instructions for it are at the end of this file. It is
incompatible with the current C version. Use C only.

If you have access to a server with public IP and unfiltered ports
you can run NAT Tunnel (NT) server on the server, and NT client
on your box behind NAT.
The server requires 2 open ports: one for communication with the
NT client (--admin), the other for regular clients to connect to
(--public: this is the port you want your users to use).

The NT client opens a connection to the server's admin ip/port.
As soon as the server receives a new connection, it signals the
NT client, which then creates a new tunnel connection to the
server, which is then connected to the desired service on the
NT client's side (--local)

The connection between NT Client and NT Server on the admin
interface is protected by a shared secret against unauthorized use.
An adversary who can intercept packets could crack the secret
if it's of insufficient complexity. At least 10 random
characters and numbers are recommended.

Example:
You have a HTTP server listening on your local machine on port 80.
You want to make it available on your cloud server/VPS/etc's public
IP on port 8000.
We use port 7000 on the cloud server for the control channel.

Server:

    ./natsrv --mode server --secret-file secret.txt --server-key server.key --public 0.0.0.0:8000 --admin 0.0.0.0:7000

Client:

    ./natsrv --mode client --secret-file secret.txt --server-pubkey PUBKEY_HEX --local localhost:80 --admin example.com:7000

IPv6 and addresses
-------------------
Both IPv4 and IPv6 work everywhere. Address syntax is host:port.
For IPv6 literals use brackets: [::1]:8080, [2001:db8::1]:7000.
A bare IPv6 address without brackets is rejected, since the
colons make the port ambiguous. For host names IPv4 is
preferred and IPv6 is the fallback; an explicit numeric literal
always wins for its own family. Listen address 0.0.0.0 means
IPv4 all interfaces, :: means IPv6 all interfaces.
On the wire the server reports a peer as ip:port for IPv4 and
[ip]:port for IPv6, and both sides parse both forms.

Keys
----
Generate the server signing key once:

    ./natsrv --genkey server.key

This writes the private key with 0600 permissions and prints
the public key hex. Give that hex string to the client as
--server-pubkey. The server requires --server-key, the client
requires --server-pubkey. Prefer --secret-file PATH over
--secret on shared boxes, since --secret leaks via ps aux.

Build
-----
Build with plain GNU Make (3.82 or newer):

    make

This produces ./natsrv. The Makefile starts with
-include config.mak before the first target, so a local
config.mak can permanently set CFLAGS, CPPDFGS, LDFLAGS,
and friends. The Makefile appends its own defaults with
CFLAGS += -Wall -std=c99. Options on the Make command line
also pass through:

    make CPPFLAGS=-DHAVE_GETRANDOM
    make CFLAGS="-Wall -Wextra -std=c99 -pedantic"
    make USE_SODIUM=1
    make clean

HAVE_GETRANDOM: by default randomness comes from /dev/urandom.
Define HAVE_GETRANDOM to use the getrandom() syscall instead
(Linux 3.17+ / glibc 2.25+). Both paths fail closed.
Linkage is -lpthread by default, plus -lsodium with
USE_SODIUM=1. The code itself is C99 and portable with no
GNU99 extensions. Tabs are used for indentation, following
the microsocks code style.

Tunnel encryption uses XSalsa20. By default it is provided by
the bundled TweetNaCl code (tweetnacl.c, tweetnacl.h). With
USE_SODIUM=1 it links libsodium instead. The sha256 code in
sha256.c is written from scratch; no crypto library is
needed for the default build.

SHA-NI acceleration (optional)
------------------------------
On x86 with Intel SHA extensions, sha256.c uses the SHA-NI
intrinsics automatically when the compiler defines __SHA__
and __SSSE3__. The scalar implementation remains the fallback.
Enable it without -march=native:

    make CPPFLAGS="-msha -msse4.1"

That builds a binary that needs any x86 CPU with SHA-NI and
SSE4.1 support, without other -march=native features. Plain
make without those flags still works everywhere.

Measured on an i7-1160G7, raw SHA256 of 16 KiB blocks:
scalar -O2 is about 257 MB/s, SHA-NI -O2 is about
1574 MB/s (about 6 times faster).

Timeouts and keepalive
----------------------
Tunnel sockets have send and receive timeouts, set with
--timeout SECS (default 1800, 0 disables them). The default is
deliberately conservative: a slow server such as llama.cpp
below 10 tokens per second, or a huge system prompt upload,
can legitimately block for many minutes. Shorter values kill
such tunnels; longer values delay dead socket detection.
Control sockets never get the timeout, so an idle control
connection is not killed.

All sockets use TCP keepalive with probes every 30 seconds
of idle time (5 second interval, 3 probes), so a silently
dead peer is detected in about 45 seconds instead of the
2 hour default. Before a spare socket is paired, both ends
poll it with a zero timeout: a socket that already shows
FIN or RST is dropped and re-armed instead of hanging the
next tunnel. Readable data alone is not treated as death,
since tunnel bytes can legitimately be in flight.

Wire protocol nt02
------------------
Binary length prefixed frames: type byte plus big endian
uint16 payload length plus payload. Types: 1 server hello,
2 client hello, 3 control, 4 tunnel, 5 error, 6 close.
Tunnel data itself is a raw byte stream inside tunnel frames
on the spare channel, encrypted with XSalsa20 when the
request byte is 2 (sk2). Control frames carry CONN peer
addresses and are always encrypted.

Handshake is 2 round trips. Server sends ephemeral X25519
public key, capability byte, 16 byte nonce, and an Ed25519
signature from its long term key. The client verifies against
its pinned server public key, then sends its own ephemeral
key, a request byte (0 adm, 1 skt cleartext tunnel, 2 sk2
encrypted tunnel), and a MAC over the transcript keyed by
the X25519 shared secret plus the shared secret from
--secret or --secret-file. That MAC is client authorization;
the shared secret alone cannot authorize without the
ephemeral private key, and the ephemeral exchange gives
forward secrecy. Stream keys derive from the shared secret
plus transcript hash. CONN peer addresses are always
encrypted on the control channel, even when the server
allows unencrypted tunnel traffic. By default tunnels are
encrypted. The option can improve throughput, or reduce
overhead if the backend is already encrypted, e.g. HTTPS.
It applies only to tunnel traffic; control traffic stays
encrypted.
Capability byte bit 0 mirrors that setting on the wire.

Keys: the server signing key is generated with --genkey
above. Prefer --secret-file PATH over --secret on shared
boxes.

Legacy Python version (final, pre-nt02)
--------------------------------------
The text below is the old Python-only documentation. It does
not describe the nt02 C wire protocol.

Server (IPv4):

    natsrv.py --mode server --secret s3cretP4ss --public 0.0.0.0:8000 --admin 0.0.0.0:7000

Client (IPv4):

    natsrv.py --mode client --secret s3cretP4ss --local localhost:80 --admin example.com:7000

Server (IPv6, note the brackets):

    natsrv.py --mode server --secret s3cretP4ss --public [::]:8000 --admin [::]:7000

Client (IPv6 upstream, IPv4 local):

    natsrv.py --mode client --secret s3cretP4ss --local localhost:80 --admin [2001:db8::1]:7000
