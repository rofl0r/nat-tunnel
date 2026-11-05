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

C version
---------
A C99 port of natsrv.py is included (natsrv.c, sha256.c, sha256.h,
Makefile). It speaks the same wire protocol and interoperates with
the Python version in both directions. The sha256 implementation
is written from scratch in sha256.c; no crypto library is needed.

Build it with plain GNU Make (3.82 or newer):

    make

This produces ./natsrv. Run it exactly like the Python program:

    ./natsrv --mode server --secret s3cretP4ss --public 0.0.0.0:7000 --admin 0.0.0.0:8000
    ./natsrv --mode client --secret s3cretP4ss --local localhost:80 --admin example.com:8000

Options on the Make command line pass through CPPFLAGS and CFLAGS,
for example:

    make CPPFLAGS=-DHAVE_GETRANDOM
    make CFLAGS="-Wall -Wextra -std=c99 -pedantic"
    make clean

HAVE_GETRANDOM: by default the C port reads nonce randomness from
/dev/urandom. Define HAVE_GETRANDOM at build time to use the
getrandom() syscall instead (Linux 3.17+ / glibc 2.25+):

    make CPPFLAGS=-DHAVE_GETRANDOM

Both paths fail closed if randomness cannot be obtained; there is
no weaker fallback. Linkage is just -lpthread; the code itself is
C99 and portable with no GNU99 extensions. Tabs are used for
indentation, following the microsocks code style.

Security note: see "Wire protocol and encryption" below. The
control handshake is authenticated with the shared secret, but
no traffic is encrypted.

Wire protocol and encryption
----------------------------
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


