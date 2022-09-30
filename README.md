# RPLTree

RPLTree is PCAP parser that displays RPL trees in the terminal.

## Important

This library uses [`smoltcp`]("https://github.com/smoltcp-rs/smoltcp") for parsing packets. However, the RPL implementation is still a work in progress. Therefore, not all packets are decoded correctly (such as 6LoWPAN extended headers). I use this project to validate the parsing of 6LoWPAN packets, as well as RPL packets.

Version `0.1.0` is able to parse non-storing mode RPL trees. This version does not, because of the extended headers.
