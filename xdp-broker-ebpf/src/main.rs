#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext, EbpfContext};
use aya_log_ebpf::info;

use core::mem;
use aya_ebpf::bindings::xdp_md;
use aya_ebpf::helpers::{bpf_redirect, bpf_redirect_map, bpf_xdp_adjust_head};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{DevMapHash, HashMap};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
    vxlan::VxlanHdr,
};
use xdp_broker_common::Backend;

const IFINDEX_VETH100I1: u32 = 11;      // <- tu veth (dentro del contenedor es eth1)
const VXLAN_PORT: u16 = 4789;           // puerto VXLAN por defecto
const VNI_TARGET: u32 = 1000;           // VNI que queremos desviar
const VXLAN_I_BIT: u8 = 0x08;           // bit "I" de VXLAN (debe estar a 1)

#[map] //
static VNI_BACKENDS: HashMap<u32, Backend> = HashMap::<u32, Backend>::with_max_entries(1024, 0);

#[map]
static REDIRECT_MAP: DevMapHash = DevMapHash::with_max_entries(1024, 0);

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

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let eth_header: *const EthHdr = pointer_safe_at::<EthHdr>(&ctx, 0)?;

    match unsafe { (*eth_header).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4_header: *const Ipv4Hdr = pointer_safe_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;

    match unsafe { (*ipv4_header).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let source_addr = u32::from_be_bytes(unsafe { (*ipv4_header).src_addr });
    let destination_addr = u32::from_be_bytes(unsafe { (*ipv4_header).dst_addr });

    let udp_header: *const UdpHdr = pointer_safe_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let source_port = unsafe { (*udp_header).src_port() };
    let destination_port = unsafe { (*udp_header).dst_port() }; // u16 host endian

    if destination_port != VXLAN_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    let vxlan_header: *const VxlanHdr =
        pointer_safe_at::<VxlanHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

    // Test if the VNI is valid
    let vni = unsafe { (*vxlan_header).vni() };
    if vni == 0 && (unsafe { (*vxlan_header).flags } & VXLAN_I_BIT) == 0 {
        return Ok(xdp_action::XDP_DROP);
    }

    let backend = unsafe { VNI_BACKENDS.get(vni) };

    if !backend.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }
    
    let backend = backend.unwrap();


    let decap_off = (EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + VxlanHdr::LEN) as i32;

    if unsafe { bpf_xdp_adjust_head(ctx.as_ptr() as *mut xdp_md, decap_off) } != 0 {
        return Ok(xdp_action::XDP_ABORTED);
    }

    let _inner_eth: *const EthHdr = pointer_safe_at::<EthHdr>(&ctx, 0)?;

    let _inner_ipv4_header: *const Ipv4Hdr = pointer_safe_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;

    //info!(&ctx, "SRC IP: {:i}, SRC PORT: {} // DST IP: {:i}, DST PORT: {} // VXLAN VNI: {}",
    //    source_addr, source_port, destination_addr, destination_port, vni);

    let _inner_source_addr = u32::from_be_bytes(unsafe { (*_inner_ipv4_header).src_addr });
    let _inner_destination_addr = u32::from_be_bytes(unsafe { (*_inner_ipv4_header).dst_addr });

    //info!(&ctx, "SRC IP: {:i} // DST IP: {:i} // VXLAN VNI: {}",
    //    _inner_source_addr, _inner_destination_addr, vni);

   info!(&ctx, "VNI: {}, Backend_if: {}", vni, backend.if_index);
    //let if_index = unsafe { backend.as_ref() }.if_index();
    //unsafe { bpf_redirect_map(*REDIRECT_MAP, if_index, 0) };
    Ok(REDIRECT_MAP.redirect(backend.if_index, 0).unwrap_or(xdp_action::XDP_PASS))
    //Ok(unsafe { bpf_redirect(backend.if_index, 0) as u32 })
}