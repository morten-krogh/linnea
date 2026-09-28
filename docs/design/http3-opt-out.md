# Global HTTP/3 opt-out proposal

The top-level integer `http3` accepts `0` or `1` and defaults to `1`.
`0` prevents every QUIC UDP listener from being created. TCP listeners keep
HTTP/1.1 and their configured HTTP/2 behavior. No origin advertises `Alt-Svc`
for HTTP/3. This is a deployment-wide control; it cannot disable one virtual
host while leaving another on the same UDP listener enabled.
On a hot reload, an older worker generation may continue serving its already
open UDP listener until drain completes. Use a full stop and restart when
HTTP/3 must cease immediately.

This option provides a temporary ingress boundary for deployments that need
method-and-path-specific body limits before Linnea's HTTP/3 request capture
can select them. A route-specific H3 implementation must decode and validate
the request's first HEADERS section, authority, method, and path before granting
large body flow credit or writing a capture file. The existing H3 path selects
the largest cap on same-certificate origins before decoding QPACK and applies
the route's own cap only after capture, so a route-only check is insufficient.

Tests should verify `http3: 0` leaves no UDP listener or `Alt-Svc` on either
HTTP/1.1 or HTTP/2, preserves TCP uploads, and rejects invalid or duplicate
config values. An explicit H3 client must fail to connect while disabled;
stale cached `Alt-Svc` is possible until clients retry TCP.
