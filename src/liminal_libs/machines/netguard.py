"""The plain checks every network step makes (1.93.0; service-containers-networking §8.6): no input or output, no
outside host named. `public_only` (an address public DNS may hold), `overlaps`, `routable_found` (a found segment, or a
prefix you type, that may be routed or named), `listener_refusal` (an address and port no listener of Liminal's takes)
and `wider_than_lan`."""
from __future__ import annotations

import ipaddress

SHARED = ipaddress.ip_network("100.64.0.0/10")  # carriers' NAT, and Tailscale's
DOCUMENTATION = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                          "2001:db8::/32"))
NO_LISTEN_PORTS = (53, 67, 68)  # never bound without your words (N16, N21)
WIDEST = 16  # a found segment wider than a /16 is never routed


def _addr(text):
    return ipaddress.ip_address(str(text).strip().strip("[]"))


def public_only(address) -> str:
    """"" when `address` is one public DNS may hold; else why not, in words. Never Python's is_private alone: shared
    (100.64.0.0/10), loopback, link-local, unique-local, multicast, unspecified and the documentation ranges are refused
    too."""
    try:
        a = _addr(address)
    except ValueError:
        return f"{str(address)[:60]!r} is not an address"
    if a in SHARED:
        return f"{a} is a shared address (100.64.0.0/10: carriers' NAT, Tailscale)"
    if any(a in n for n in DOCUMENTATION if n.version == a.version):
        return f"{a} is a documentation address"
    for word, test in (("loopback", a.is_loopback), ("link-local", a.is_link_local), ("multicast", a.is_multicast),
                       ("unspecified", a.is_unspecified), ("reserved", a.is_reserved), ("private", a.is_private)):
        if test:
            return f"{a} is a {word} address: never in public DNS"
    return ""


def overlaps(prefix, others) -> list[str]:
    """The networks among `others` that `prefix` meets, as written."""
    net = ipaddress.ip_network(str(prefix), strict=False)
    out = []
    for o in others:
        try:
            other = ipaddress.ip_network(str(o), strict=False)
        except ValueError:
            continue
        if other.version == net.version and net.overlaps(other):
            out.append(str(o))
    return out


def routable_found(prefix, avoid=()) -> str:
    """"" when a found segment (or a prefix you type) may be routed or named: private (RFC 1918 or ULA), no wider than
    a /16, not 0.0.0.0/0 or link-local, meeting none of `avoid` (this machine's networks, the pool's halves, other
    segments); else why not."""
    try:
        net = ipaddress.ip_network(str(prefix), strict=False)
    except ValueError:
        return f"{str(prefix)[:60]!r} is not a network"
    if net.prefixlen < WIDEST:
        return f"{net} is wider than a /{WIDEST}"
    if net.is_link_local or net.network_address.is_unspecified:
        return f"{net} is link-local or the whole internet"
    if not net.is_private or (net.version == 4 and net.subnet_of(SHARED)):
        return f"{net} is not a private network"
    met = overlaps(net, avoid)
    if met:
        return f"{net} meets {', '.join(met[:4])}"
    return ""


def listener_refusal(address, port: int, allowed=()) -> str:
    """"" when a listener of Liminal's may take address:port; else why not: never every address, never 53, 67 or 68
    without your words (`allowed`: the (address, port) pairs you allowed in words)."""
    if (str(address), int(port)) in {(str(a), int(p)) for a, p in allowed}:
        return ""
    try:
        a = _addr(address)
    except ValueError:
        return f"{str(address)[:60]!r} is not an address"
    if a.is_unspecified:
        return f"{a}:{port}: a listener of Liminal's is never bound to every address"
    if int(port) in NO_LISTEN_PORTS:
        return f"{a}:{port}: port {port} is never listened on without your words"
    return ""


def wider_than_lan(remote, lan) -> bool:
    """Whether a rule's remote reaches more than your network (`lan`: its prefix)."""
    if str(remote).lower() in ("any", "*", "0.0.0.0/0", "::/0"):
        return True
    try:
        return not ipaddress.ip_network(str(remote), strict=False).subnet_of(ipaddress.ip_network(str(lan), strict=False))
    except (ValueError, TypeError):
        return True
