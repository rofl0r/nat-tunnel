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


