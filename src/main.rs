extern crate pcap;
extern crate pnet_packet;

use pcap::Capture;
use pnet_packet::{ipv4,tcp};

fn main() {
    // XXX: yeah, yeah, yeah, use try!
    let mut cap = Capture::from_raw_fd(0).unwrap();

    while let Ok(packet) = cap.next() {
        // We can skip decoding Ethernet, since the payload of an 802.3
        // layer 2 frame starts at offset 14. (Assuming there's no VLAN
        // tag... TODO: add a check for 802.1Q ethertype values 0x8100,
        // 0x88a8 for single and double-tagged frames respectively.)
        // We also assume IPv4, and damn the consequences!
        let ip4_offset = 14;
        let ip4 = ipv4::Ipv4Packet::new(&packet.data[ip4_offset..]).unwrap();

        // The IPv4 HL field is specified in units of 32-bit words.
        let tcp_offset = ip4_offset + 4 * ip4.get_header_length() as usize;
        let tcp = tcp::TcpPacket::new(&packet.data[tcp_offset..]).unwrap();

        // Ditto for TCP data offset.
        let data_offset = tcp_offset + 4 * tcp.get_data_offset() as usize;
        let data = &packet.data[data_offset..];

        println!("TCP data {:?}:{:?} -> {:?}:{:?}\n{:?}",
                ip4.get_source(), tcp.get_source(),
                ip4.get_destination(), tcp.get_destination(),
                data);
    }
}
