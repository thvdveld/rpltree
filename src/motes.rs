use std::net::Ipv6Addr;

use colored::Colorize;

#[derive(Debug, PartialEq, Eq)]
pub struct Mote {
    id: usize,
    ip: Ipv6Addr,
    parent: Option<Ipv6Addr>,
    updated: bool,
}

impl Mote {
    pub fn new(address: Ipv6Addr) -> Self {
        Self {
            id: rand::random(),
            ip: address,
            parent: None,
            updated: false,
        }
    }

    pub fn set_parent(&mut self, address: Ipv6Addr) -> bool {
        let changed = self.parent != Some(address);
        self.updated = changed;
        self.parent = Some(address);
        changed
    }

    pub fn set_updated(&mut self) {
        self.updated = true;
    }
}

#[derive(Debug, Default)]
pub struct Motes {
    motes: Vec<Mote>,
}

impl Motes {
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        let mut address = address.octets();
        address[..2].copy_from_slice(&[0u8; 2]);

        self.motes.iter().any(|mote| {
            let mut mote_address = mote.ip.octets();
            mote_address[..2].copy_from_slice(&[0u8; 2]);
            mote_address == address
        })
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

    pub fn showtree(&mut self) {
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
            let mut tree = termtree::Tree::new(if root.updated {
                root.ip.to_string().magenta().italic().bold().to_string()
            } else {
                root.ip.to_string()
            });
            self.add_to_tree(&mut tree, Some(root.ip));

            trees.push(tree);
        }

        for tree in &trees {
            println!("{tree}");
        }

        for mote in &mut self.motes {
            mote.updated = false;
        }
    }

    fn add_to_tree(&self, tree: &mut termtree::Tree<String>, parent: Option<Ipv6Addr>) {
        for mote in &self.motes {
            if mote.parent == parent {
                let mut sub = termtree::Tree::new(if mote.updated {
                    mote.ip
                        .to_string()
                        .magenta()
                        .italic()
                        .underline()
                        .bold()
                        .to_string()
                } else {
                    mote.ip.to_string()
                });
                self.add_to_tree(&mut sub, Some(mote.ip));
                tree.push(sub);
            }
        }
    }
}

