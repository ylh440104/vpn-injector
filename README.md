# vpn-injector

Android `VpnService` front-end for CVE-2026-98432 research on Linux 4.19.191.

## Why

The `ireq_opt` use-after-free needs a forged TCP segment (arbitrary source
address, source port and ISN) delivered to the target listener. Building such a
segment normally requires `CAP_NET_RAW`, which an unprivileged app does not
have.

`VpnService` sidesteps that: the framework hands the app a tun file descriptor,
and anything written to it is delivered to the kernel as if it had arrived on
that interface. No raw sockets, no capabilities. The kernel then runs its normal
receive path and the listener sees a genuine segment.

## Layout

```
MainActivity   request VPN consent, start/stop the tunnel
InjService     establish tun 10.7.7.1/24, relay framed IPv4 packets into it
```

## Protocol

The app dials a control server outbound (so no inbound NAT hole is needed) and
then:

```
server -> app    4-byte big-endian length, then that many bytes of IPv4 packet
app -> server    single 0x06 byte, one per injected packet
```

The server builds the packets with raw sockets, which is where the forged
source address and sequence numbers come from.

## Build

GitHub Actions, `.github/workflows/build.yml`, debug APK as an artifact.
Nothing is built on-device.

## Caveats

* Establishing a VPN replaces any other active VPN (Clash and friends).
* `addRoute("0.0.0.0", 0)` captures all traffic while the tunnel is up.
* This is research tooling for hardware you own.
