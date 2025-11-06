# XDPBroker
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/alrolo3/xdp-broker)
#
XDPBroker: A High-Performance XDP/eBPF Packet Broker for Flow-Based Distribution of VXLAN-Encapsulated Traffic for Network Analysis

## Project

**XDPBroker** is a packet broker to distribute remotely mirrored traffic to multiple analysis instances. The project currently runs on top of the OVS core, but the goal is to move it to one or more programs that combine a user-space process with one or more eBPF components.

The idea is as follows: mirrored/replicated traffic arrives at the “analysis” server via VXLAN tunnels, where each VNI represents a different “client.” Upon arrival, the broker must determine the VNI, strip the tunnel headers, and send the raw packet to the analysis instance whose name matches the tunnel. For example, if VNI=100, the instance host would be something like `lxc-suricata-100`, and its interface would likely be called `veth100i1`—but could this be discovered from user space? I’m not sure.

There is a possibility that the analysis instance is not located on the same host, meaning the packet’s destination is remote. This option should be supported: the same eBPF program (or another attached at a different point in the packet-processing path) must be able to add new VXLAN headers or modify the existing ones based on a map. This must be simple and lightweight so as not to overload the CPU.

Lastly, if a tunnel carries a very large volume of traffic, it could overwhelm its analysis instance. To address this, the eBPF component responsible for sending traffic to a local instance should be able to run an algorithm **X** that distributes the **flows** (per-flow packet streams) of a VXLAN across **X** instances. The algorithm is yet to be defined, but it should be something like a **5-tuple hash**.


