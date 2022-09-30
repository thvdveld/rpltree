use clap::Parser;
use colored::Colorize;

use std::{net::Ipv6Addr, str::FromStr};

mod motes;
use motes::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the pcap file.
    #[arg(short, long)]
    file: Option<std::path::PathBuf>,
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    let path = if let Some(ref file) = args.file {
        log::trace!("parsing PCAP file");
        file.to_str().unwrap().to_string()
    } else {
        log::trace!("parsing STDIN");
        "/dev/stdin".to_string()
    };

    let mut builder = rtshark::RTSharkBuilder::builder().input_path(&path);

    if args.file.is_none() {
        builder = builder.live_capture();
    }

    let mut rtshark = match builder.spawn() {
        Err(err) => {
            log::error!("error running tshark: {err}");
            return;
        }
        Ok(rtshark) => rtshark,
    };

    let mut motes = Motes::default();

    log::trace!("Starting parsing...");
    // read packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        log::error!("Error parsing TShark output: {e}");
        None
    }) {
        log::trace!("Reading packet..");
        let src_address = if let Some(ip_layer) = packet.layer_name("ipv6") {
            ip_layer.metadata("ipv6.src").map(|meta| {
                let value = if meta.value().starts_with("::") {
                    format!("fe80{}", meta.value())
                } else {
                    meta.value().to_string().replace("fd00", "fe80")
                };
                Ipv6Addr::from_str(&value).unwrap()
            })
        } else {
            None
        };

        if let Some(addr) = src_address {
            if !motes.contains(addr) {
                log::trace!("Adding new mote with address {addr}");
                println!("{}", "Added new mote".underline());
                let mut mote = Mote::new(addr);
                mote.set_updated();
                motes.add(mote);
                motes.showtree();
            }
        }

        if let Some(layer) = packet.layer_name("icmpv6") {
            if let Some(code) = layer.metadata("icmpv6.code") {
                if code.value() != "2" {
                    continue;
                }
            }

            let src_address = if src_address.is_none() {
                if let Some(meta) = layer.metadata("icmpv6.rpl.opt.target.prefix") {
                    Ipv6Addr::from_str(meta.value()).unwrap().into()
                } else {
                    None
                }
            } else {
                src_address
            };

            if let Some(addr) = src_address {
                if !motes.contains(addr) {
                    motes.add(Mote::new(addr));
                }
            }

            let parent = if let Some(layer) = packet.layer_name("ipv6") {
                layer
                    .metadata("ipv6.dst")
                    .map(|meta| Ipv6Addr::from_str(meta.value()).unwrap())
            } else {
                None
            };

            let parent = if let Some(meta) = layer.metadata("icmpv6.rpl.opt.transit.parent") {
                Ipv6Addr::from_str(meta.value()).unwrap().into()
            } else {
                parent
            };

            let parent = if let Some(parent) = parent {
                if parent.is_multicast() {
                    None
                } else {
                    Some(Ipv6Addr::from_str(&parent.to_string().replace("fd00", "fe80")).unwrap())
                }
            } else {
                parent
            };

            if let (Some(src_address), Some(parent)) = (src_address, parent) {
                let mote = if motes.contains(src_address) {
                    motes.get_mut(src_address)
                } else {
                    unreachable!();
                };

                if mote.set_parent(parent) {
                    if let Some(layer) = packet.layer_name("frame") {
                        println!(
                            "{}",
                            format!(
                                "New tree at {} (+ {})",
                                layer.metadata("frame.time").unwrap().value(),
                                layer.metadata("frame.time_relative").unwrap().value()
                            )
                            .underline()
                        );
                    }

                    motes.showtree();
                }
            }
        }
    }
}
