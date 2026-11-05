NAT Tunnel v0.01
----------------
If you have access to a server with public IP and unfiltered ports
you can run NAT Tunnel (NT)  server on the server, and NT client
on your box behind NAT.
the server requires 2 open ports: one for communication with the
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
IP on port 7000.
We use port 8000 on the cloud server for the control channel.

Server (IPv4):

    natsrv.py --mode server --secret s3cretP4ss --public 0.0.0.0:7000 --admin 0.0.0.0:8000

Client (IPv4):

    natsrv.py --mode client --secret s3cretP4ss --local localhost:80 --admin example.com:8000

Server (IPv6, note the brackets):

    natsrv.py --mode server --secret s3cretP4ss --public [::]:7000 --admin [::]:8000

Client (IPv6 upstream, IPv4 local):

    natsrv.py --mode client --secret s3cretP4ss --local localhost:80 --admin [2001:db8::1]:8000
Python version status
-------------------
The Python version (natsrv.py plus rocksock.py) is final and
unmaintained. It is kept for reference only. As of the sk2
XSalsa20 change, Python and C are incompatible on the wire
for encrypted tunnels: C uses XSalsa20 via TweetNaCl or
libsodium, Python still uses SHA256-CTR. Matching pairs are
required. Use the C version for new deployments.

C version
---------
A C99 implementation is included (natsrv.c, sha256.c, sha256.h,
tweetnacl.c, tweetnacl.h, Makefile). Tunnel encryption uses
XSalsa20. By default it is provided by the bundled TweetNaCl
code; with USE_SODIUM=1 it links libsodium instead. The sha256
implementation is written from scratch in sha256.c; no crypto
library is needed for the default build. Note the Python
version is final and incompatible for encrypted tunnels;
see the Python version status section above.

Build it with plain GNU Make (3.82 or newer):

    make

This produces ./natsrv. Run it exactly like the Python program:

    ./natsrv --mode server --secret s3cretP4ss --public 0.0.0.0:7000 --admin 0.0.0.0:8000
    ./natsrv --mode client --secret s3cretP4ss --local localhost:80 --admin example.com:8000

The Makefile starts with -include config.mak before the first
target, so a local config.mak can permanently set CFLAGS,
CPPFLAGS, LDFLAGS, and friends. Note the Makefile appends its
own defaults afterwards with CFLAGS += -Wall -std=c99, so a
plain CFLAGS = assignment in config.mak is kept and the
defaults are appended to it. Options on the Make command line
also pass through, for example:

    make CPPFLAGS=-DHAVE_GETRANDOM
    make CFLAGS="-Wall -Wextra -std=c99 -pedantic"
    make USE_SODIUM=1
    make clean

HAVE_GETRANDOM: by default the C port reads nonce randomness from
/dev/urandom. Define HAVE_GETRANDOM at build time to use the
getrandom() syscall instead (Linux 3.17+ / glibc 2.25+):

    make CPPFLAGS=-DHAVE_GETRANDOM

Both paths fail closed if randomness cannot be obtained; there is
no weaker fallback. Linkage is just -lpthread; the code itself is
C99 and portable with no GNU99 extensions. Tabs are used for
indentation, following the microsocks code style.

Security note: see "Wire protocol and encryption" below.
Tunnel payloads use sk2 encryption by default; control
traffic is authenticated only and stays cleartext.
SHA-NI acceleration (optional)
------------------------------
On x86 with Intel SHA extensions, sha256.c uses the SHA-NI
intrinsics automatically when the compiler defines __SHA__
and __SSSE3__. The scalar implementation remains the fallback.
Enable it without -march=native by adding the two flags that
define the macro and the intrinsics:

    make CPPFLAGS="-msha -msse4.1"

That builds a binary that needs any x86 CPU with SHA-NI and
SSE4.1 support, without other -march=native features. Plain
make without those flags still works everywhere.

Measured on an i7-1160G7, raw SHA256 of 16 KiB blocks:
scalar -O2 is about 257 MB/s, SHA-NI -O2 is about
1574 MB/s (about 6 times faster). For sk2 key stream
generation the gain is smaller because each 32 byte block
pays context setup cost: about 98 MB/s scalar versus
about 223 MB/s with SHA-NI.
Wire protocol nt02
------------------
Binary length prefixed frames: type byte plus big endian
uint16 payload length plus payload. Types: 1 server hello,
2 client hello, 3 control, 4 tunnel, 5 error, 6 close.
Tunnel frames carry up to 16384 bytes. No newline scanning.

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
allows cleartext tunnels. Server policy via --allow-cleartext
(default) or --no-cleartext controls whether skt is accepted.
Capability byte bit 0 mirrors that setting on the wire.

Keys: ./natsrv --genkey --out server.key generates an
Ed25519 keypair, private key file 0600, public key hex
printed for client pinning with --server-pubkey. Server
requires --server-key, client requires --server-pubkey.
Prefer --secret-file PATH over --secret on shared boxes.

Wire protocol and encryption (legacy, pre-nt02)
------------------------------------------------
The shared secret authenticates the admin handshake. It does not
sign or integrity-protect any data. Tunnel payload bytes can be
encrypted with sk2 (below); control traffic never is.

Per admin or tunnel connection the server sends a fresh nonce:
8 random bytes from the OS (os.urandom in Python, /dev/urandom
or getrandom() in C), shown as 16 hex characters plus a newline.
The client replies with hex sha256(cmd + secret + nonce) plus a
newline, where cmd is "adm" for the control socket, "skt" for a
cleartext spare tunnel socket, or "sk2" for an encrypted spare
tunnel socket. The server accepts only if that hash matches;
otherwise it prints "rejected!" and closes the socket. The
nonce is never reused for a different connection, and the
secret itself never goes on the wire.

sk2 encryption (SHA256 counter mode): when a client arms a spare
tunnel socket with sk2, that tunnel's payload bytes in both
directions are XORed with a SHA256 key stream. Per tunnel keys
are sha256("enc-up" + secret + nonce) for client-to-server and
sha256("enc-dn" + secret + nonce) for server-to-client, where
nonce is that tunnel's handshake nonce. Key stream block i is
sha256(key + big-endian counter i). The counter starts at 0 per
tunnel per direction and never repeats inside the tunnel, so
the two directions never share a key stream. Current clients
always use sk2 for spare sockets; servers still accept skt for
old clients, and a sk2 client fails closed against an old
server instead of falling back to cleartext.

Limits: key quality is only as good as the secret. A weak
secret can still be brute forced offline from the handshake
hash, and known plaintext in the tunnel can help confirm a
guess. There is no forward secrecy: if the secret leaks later,
captured tunnels can be decrypted. There is no integrity:
flipping ciphertext bits causes predictable plaintext changes.
Control traffic (adm handshake, CONN: notifications, public
client addresses) is always cleartext. Use a strong secret and,
if you need integrity or forward secrecy, run the tunnel over
TLS or another authenticated encrypted transport.
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


