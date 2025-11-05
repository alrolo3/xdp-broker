use anyhow::Context as _;
use aya::maps::{DevMapHash, HashMap};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use xdp_broker_common::Backend;
use rtnetlink::{Handle, new_connection};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "vmbr0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-broker"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }


    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("xdp_broker").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    {
        let mut vni_backends: HashMap<_, u32, Backend> = HashMap::try_from(ebpf.map_mut("VNI_BACKENDS").unwrap())?;
        let backend_test: Backend = Backend { if_index: 11, flags: 0 };
        vni_backends.insert(1000, backend_test, 0).expect("TODO: panic message");
    }

    {
        let mut redirect_map: DevMapHash<_> = DevMapHash::try_from(ebpf.map_mut("REDIRECT_MAP").unwrap())?;
        // Donde pone NONE se puede pasar un Option<&ProgramFd> para que se redirija el paquete a otro XDP program
        redirect_map.insert(11, 11, None, 0).expect("TODO: panic message");
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
