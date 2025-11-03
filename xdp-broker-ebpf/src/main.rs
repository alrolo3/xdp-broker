//! # About
//! This is an eBPF program written to process packets in the XDP (eXpress Data Path) layer.
//! The program inspects network packet headers and performs match-based decision-making.
//! Specifically, it processes Ethernet, IPv4, TCP, and UDP headers and logs source IP and port
//! information. If the program encounters unsupported protocols or errors, it safely handles them.
//!
//! # Code Overview
//!
//! ## Kernel Attributes
//! - `#![no_std]`: Indicates that the program does not use Rust's standard library as it's intended for
//!   kernel execution.
//! - `#![no_main]`: Prevents the usual Rust entry point (`main`) as the program is not a typical user-space
//!   application.
//!
//! ## Modules Used
//! - `aya_ebpf`: Provides bindings for eBPF program types, helpers, and macros.
//! - `aya_log_ebpf`: Used for kernel-space logging.
//! - `network_types`: Provides definitions for common network packet headers (Ethernet, IP, TCP, UDP).
//! - `core::mem`: Used for memory size calculations.
//!
//! ## Panic Handler
//! - A custom panic handler `panic_handler` is defined for handling panics gracefully. On a panic,
//!   the system enters an infinite loop (`loop {}`).
//!
//! ## Entry Point
//! The `xdp` macro (`#[xdp]`) registers the function `xdp_broker` as the main eBPF entry point for XDP.
//!
//! ## Core Functionality
//!
//! ### `xdp_broker` Function
//! - Signature: `pub fn xdp_broker(ctx: XdpContext) -> u32`
//! - Acts as the main entry point for the XDP program.
//! - Calls `try_xdp_firewall` to analyze the packet.
//! - Returns the appropriate XDP action, such as:
//!   - `XDP_PASS`: Packet is allowed to pass through.
//!   - `XDP_ABORTED`: Packet processing is aborted in case of errors.
//!
//! ### `try_xdp_firewall` Function
//! - Analyzes the packet's headers to log the source IP and port.
//! - Steps:
//!   - Extracts Ethernet header (`EthHdr`) and ensures it's an IPv4 packet.
//!   - Extracts IPv4 header (`Ipv4Hdr`) and retrieves source/destination addresses.
//!   - Based on the transport layer protocol (TCP/UDP), extracts its respective header
//!     (`TcpHdr` or `UdpHdr`) and retrieves the source port.
//!   - Logs source IP address and port information using `aya_log_ebpf::info!`.
//! - Returns:
//!   - `XDP_PASS` if the packet is processed successfully.
//!   - An error (`Err(())`) if packet inspection fails at any step.
//!
//! ### Helper Function: `ptr_at`
//! - Signature: `fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()>`
//! - A utility function for safely accessing specific regions of memory within the packet context.
//! - Parameters:
//!   - `ctx`: The XDP context, which contains packet data.
//!   - `offset`: Position within the packet to read from.
//! - Validates whether the memory access will remain within bounds of the packet buffer.
//! - Returns:
//!   - A raw pointer (`*const T`) to the specified memory location on success.
//!   - An error (`Err(())`) if the memory access would go out of bounds.
//!
//! ### Logging
//! - Logs source IP and source port using `info!` in the format:
//!   - `"SRC IP: {:i}, SRC PORT: {}"`, where `:i` applies formatting to the IP address.
//!
//! # XDP Actions
//! The eBPF program primarily uses the following XDP actions:
//! - `XDP_PASS`: Allows the packet to pass further in the networking stack.
//! - `XDP_ABORTED`: Indicates that processing of the packet was aborted prematurely, usually due to errors.
//!
//! # Error Handling
//! - Memory bounds are checked using `ptr_at` before trying to access headers.
//! - Unsupported protocols are safely ignored by returning an error or `XDP_PASS`.
//! - All errors in `try_xdp_firewall` are caught at `xdp_broker` level and result in `XDP_ABORTED`.
//!
//! # Notes
//! - The program does not handle IPv6 packets or protocols other than TCP/UDP.
//! - The `no_std` environment limits the use of some high-level Rust features.
//! - Testability is limited without access to kernel-level testing frameworks or mocks.
#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
    vxlan::VxlanHdr,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[xdp]
pub fn xdp_broker(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] //
fn pointer_safe_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

/// A simple eBPF-based XDP firewall function to inspect and log IPv4 traffic.
/// This function is intended to be attached to an XDP (eXpress Data Path) hook
/// and can analyze incoming packets at the network interface level.
///
/// # Parameters
/// - `ctx`: An `XdpContext` object which provides the raw packet data and metadata for inspection.
///
/// # Returns
/// - On success, returns `Ok(u32)` which indicates the XDP action to take (e.g., `XDP_PASS` to let the packet continue).
/// - On failure, returns `Err(())` to indicate an error in parsing or packet inspection.
///
/// # Workflow
/// 1. Parse the Ethernet header from the packet. If the pointer is invalid, terminate with an error.
/// 2. Check if the packet is an IPv4 packet by inspecting the EtherType field. If it's not, allow the packet to pass (`XDP_PASS`).
/// 3. Parse the IPv4 header to extract details such as the source address and destination address.
/// 4. Inspect the protocol field in the IPv4 header:
///     - If the protocol is TCP, retrieve the source port from the TCP header.
///     - If the protocol is UDP, retrieve the source port from the UDP header.
///     - For any other protocol, terminate with an error.
/// 5. Log the source IP address and source port for monitoring or debugging purposes.
/// 6. Return `XDP_PASS` to allow the packet to pass further processing.
///
/// # Logging
/// - Logs the source IP address (`SRC IP`) and source port (`SRC PORT`) for every inspected packet.
/// - Use the `info!` macro to produce the logs.
///
/// # Safety
/// - Dereferencing raw pointers is inherently unsafe. The function ensures safety by verifying the validity
///   of pointers using the `pointer_safe_at` function before any dereferencing operation. However, unsafe
///   blocks are used when accessing data directly from parsed headers.
///
/// # Limitations
/// - This implementation only processes IPv4 traffic and ignores IPv6 or other protocols.
/// - Currently, the function allows all packets (`XDP_PASS`) and does not perform any packet dropping or filtering.
/// - Parsing beyond the Ethernet, IPv4, and either TCP/UDP headers is unsupported.
///
/// # Dependencies
/// - `EthHdr`, `Ipv4Hdr`, `TcpHdr`, and `UdpHdr` structs for parsing respective protocol headers.
/// - Helper function `pointer_safe_at` for safely accessing packet data.
/// - `IpProto` and `EtherType` enums for protocol type identification.
/// - `xdp_action` enum for defining possible XDP actions.
///
/// # Example
/// ```no_run
/// use crate::ebpf_program::try_xdp_firewall;
/// use redbpf_probes::xdp::prelude::*;
///
/// fn main() {
///     // Call this function as part of an XDP hook logic.
///     // Provide the `XdpContext` object representing a packet.
///     match try_xdp_firewall(ctx) {
///         Ok(action) => {
///             // Apply the returned XDP action
///         },
///         Err(_) => {
///             // Handle parsing error
///         },
///     }
/// }
/// ```
///
/// # Notes
/// - The function is intended for educational or simple logging purposes, not for use in production filtering scenarios.
/// - Packet processing performance and memory safety must always be considered when working with eBPF programs.
///
/// # See Also
/// - `redbpf_probes::xdp` crate for more tools to generate eBPF XDP programs.
/// - XDP documentation for in-depth details on handling XDP hooks:
/// <https://www.kernel.org/doc/html/latest/networking/xdp.html>
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {

    let eth_header: *const EthHdr = pointer_safe_at::<EthHdr>(&ctx, 0)?;

    match unsafe { (*eth_header).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4_header: *const Ipv4Hdr = pointer_safe_at::<Ipv4Hdr>(&ctx,  EthHdr::LEN)?;

    match unsafe { (*ipv4_header).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let source_addr = u32::from_be_bytes(unsafe { (*ipv4_header).src_addr });
    let destination_addr = u32::from_be_bytes(unsafe { (*ipv4_header).dst_addr });

    let udp_header: *const UdpHdr = pointer_safe_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let source_port = unsafe { (*udp_header).src_port() };
    let destination_port = unsafe { (*udp_header).dst_port() }; // u16 host endian

    if destination_port != 4789 {
        return Ok(xdp_action::XDP_PASS);
    }

    let vxlan_header: *const VxlanHdr =
        pointer_safe_at::<VxlanHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

    let vni = unsafe { (*vxlan_header).vni() };


    //
    info!(&ctx, "SRC IP: {:i}, SRC PORT: {} // DST IP: {:i}, DST PORT: {} // VXLAN VNI: {}",
        source_addr, source_port, destination_addr, destination_port, vni);

    Ok(xdp_action::XDP_PASS)
}