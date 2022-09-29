use clap::Parser;

use std::{net::Ipv6Addr, str::FromStr};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the pcap file.
    #[arg(short, long)]
    file: Option<std::path::PathBuf>,
}

const PREFIX: &str = "fd00";

#[derive(Debug, PartialEq, Eq)]
struct Mote {
    id: usize,
    ip: Ipv6Addr,
    parent: Option<Ipv6Addr>,
}

impl Mote {
    pub fn new(address: Ipv6Addr) -> Self {
        Self {
            id: rand::random(),
            ip: address,
            parent: None,
        }
    }

    pub fn set_parent(&mut self, address: Ipv6Addr) -> bool {
        let changed = self.parent != Some(address);
        //if changed {
            //println!("{} -> new parent: {address}", self.ip);
        //}
        self.parent = Some(address);
        changed
    }
}

#[derive(Debug, Default)]
struct Motes {
    motes: Vec<Mote>,
}

impl Motes {
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        self.motes.iter().any(|mote| mote.ip == address)
    }

    pub fn get_mut(&mut self, address: Ipv6Addr) -> &mut Mote {
        self.motes
            .iter_mut()
            .find(|mote| mote.ip == address)
            .unwrap()
    }

    pub fn add(&mut self, mote: Mote) {
        self.motes.push(mote);
    }

    pub fn showtree(&self) {
        if self.motes.is_empty() {
            return;
        }

        let mut trees = vec![];

        let mut roots = vec![];

        for mote in &self.motes {
            if mote.parent.is_none() {
                roots.push(mote);
            }
        }

        for root in &roots {
            let mut tree = termtree::Tree::new(root.ip.to_string());
            self.add_to_tree(&mut tree, Some(root.ip));

            trees.push(tree);
        }

        for tree in &trees {
            println!("{tree}");
        }
    }

    fn add_to_tree(&self, tree: &mut termtree::Tree<String>, parent: Option<Ipv6Addr>) {
        for mote in &self.motes {
            if mote.parent == parent {
                let mut sub = termtree::Tree::new(mote.ip.to_string());
                self.add_to_tree(&mut sub, Some(mote.ip));
                tree.push(sub);
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    let path = if let Some(ref file) = args.file {
        file.to_str().unwrap().to_string()
    } else {
        "/dev/stdin".to_string()
    };

    let mut builder = rtshark::RTSharkBuilder::builder().input_path(&path);

    if args.file.is_none() {
        builder = builder.live_capture();
    }

    let mut rtshark = match builder.spawn() {
        Err(err) => {
            eprintln!("Error running tshark: {err}");
            return;
        }
        Ok(rtshark) => rtshark,
    };

    let mut motes = Motes::default();

    // read packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        eprintln!("Error parsing TShark output: {e}");
        None
    }) {
        //for layer in packet.iter() {
            //println!("Layer: {}", layer.name());
            //for metadata in layer.iter() {
                //println!("\t{}", metadata.name());
            //}
        //}

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
                motes.add(Mote::new(addr));
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
                    //println!("{:#?}", motes.motes);

                    if let Some(layer) = packet.layer_name("frame") {
                        println!(
                            "New tree at {}",
                            layer.metadata("frame.time").unwrap().value()
                        );
                    }

                    motes.showtree();
                }
            }
        }
    }
}
