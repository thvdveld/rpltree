use clap::Parser;
use colored::Colorize;
use pcap::Capture;

use smoltcp::{phy::ChecksumCapabilities, wire::*};

use rpltree::*;

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
        file
    } else {
        log::trace!("parsing from pipe");
        std::path::Path::new("/dev/stdin")
    };

    let mut pcap = Capture::from_file(path).unwrap();

    let mut motes = Motes::default();

    while let Ok(packet) = pcap.next_packet() {
        if let Ok(packet) = Ieee802154Frame::new_checked(packet.data) {
            let repr = Ieee802154Repr::parse(&packet).unwrap();
            let payload = packet.payload().unwrap();
            let iphc_packet = SixlowpanIphcPacket::new_checked(payload).unwrap();
            let repr = SixlowpanIphcRepr::parse(
                &iphc_packet,
                repr.src_addr,
                repr.dst_addr,
                &[SixlowpanAddressContext(&[0xfd, 0x00])],
            )
            .unwrap();
            let src_addr = repr.src_addr;

            if !motes.contains(src_addr.into()) {
                log::trace!("Adding new mote with address {src_addr}");
                println!("{}", "Added new mote".underline());
                let mut mote = Mote::new(src_addr.into());
                mote.set_updated();
                motes.add(mote);
                motes.showtree();
            }

            let parent = repr.dst_addr;

            if let Ok(icmp) = Icmpv6Packet::new_checked(iphc_packet.payload()) {
                if let Ok(Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject {
                    options,
                    ..
                })) = Icmpv6Repr::parse(
                    &repr.src_addr.into(),
                    &repr.dst_addr.into(),
                    &icmp,
                    &ChecksumCapabilities::ignored(),
                ) {
                    //let parent = if !options.is_empty() {
                    //let option = RplOptionPacket::new_unchecked(options);
                    //match RplOptionRepr::parse(&option).unwrap() {
                    //RplOptionRepr::TransitInformation { parent_address, .. } => {
                    //if let Some(new_parent) = parent_address {
                    //new_parent
                    //} else {
                    //parent
                    //}
                    //}
                    //_ => parent,
                    //}
                    //} else {
                    //parent
                    //};
                    if motes.contains(src_addr.into()) {
                        let mote = motes.get_mut(src_addr.into());
                        if mote.set_parent(parent.into()) {
                            println!("{}", "New tree".underline());
                            motes.showtree();
                        }
                    }
                }
            }
        }
    }
}
