extern crate pcap;
extern crate pnet_packet;

use pcap::Capture;
use pnet_packet::{ipv4,tcp};
use std::mem;

fn tcp_data(data: &[u8]) -> &[u8] {
    // We can skip decoding Ethernet, since the payload of an 802.3
    // layer 2 frame starts at offset 14. (Assuming there's no VLAN
    // tag... TODO: add a check for 802.1Q ethertype values 0x8100,
    // 0x88a8 for single and double-tagged frames respectively.)
    // We also assume IPv4, and damn the consequences!
    let ip4_offset = 14;
    let ip4 = ipv4::Ipv4Packet::new(&data[ip4_offset..]).unwrap();

    // The IPv4 HL field is specified in units of 32-bit words.
    let tcp_offset = ip4_offset + 4 * ip4.get_header_length() as usize;
    let tcp = tcp::TcpPacket::new(&data[tcp_offset..]).unwrap();

    // Ditto for TCP data offset.
    let data_offset = tcp_offset + 4 * tcp.get_data_offset() as usize;
    &data[data_offset..]
}

/// Extract a 32-bit network byte order value as a host order u32.
/// This is the safe version that does all the nice, safe, checked shifting
/// and bitwise masking. It's also stupefyingly slow, relatively speaking.
/// Curse you, Rust, and your insistence that we avoid undefined behavior!
/// NOTE: I've seen rustc compile code like this down to a single bswapl,
/// but it doesn't seem to want to do it here.
#[inline]
#[cfg(feature = "slow")]
fn u32be_to_host(data: &[u8], offset: usize) -> u32 {
    let b0 = ((data[offset + 0] as u32) << 24) as u32;
    let b1 = ((data[offset + 1] as u32) << 16) as u32;
    let b2 = ((data[offset + 2] as u32) << 8) as u32;
    let b3 = ((data[offset + 3] as u32)) as u32;
    b0 | b1 | b2 | b3
}

/// Extract a 32-bit network byte order value as a host order u32.
/// This is the fast version that compiles to a single bswapl instruction.
/// Use this if you are a super cool person who drives fast cars while
/// things explode in your rearview mirror.
#[cfg(not(feature = "slow"))]
#[inline(always)]
fn u32be_to_host(data: &[u8], offset: usize) -> u32 {
    let val: u32 = unsafe {
        let ptr = data[offset..].as_ptr() as *const u32;
        mem::transmute(*ptr)
    };
    u32::from_be(val)
}

/// ONC-RPC message type.
enum OncRpcMessageType {
    Call,
    Reply
}

/// Wraps borrowed packet data with methods *almost* conforming to RFC 5531.
struct OncRpcMessage<'p> {
    data: &'p [u8],
}

impl<'a> OncRpcMessage<'a> {
    /// Construct a new OncRpcMessage from raw data.
    pub fn new<'p>(data: &'p [u8]) -> Option<OncRpcMessage<'p>> {
        if data.len() >= OncRpcMessage::minimum_packet_size() {
            Some(OncRpcMessage{data: data})
        } else {
            None
        }
    }

    /// Return the minimum valid packet size for an ONC-RPC message.
    /// Currently set at the minimum header size of 28 bytes. Technically
    /// this excludes continuations, which might be shorter as they have
    /// no header, but we wouldn't want to interpret those anyway.
    pub fn minimum_packet_size() -> usize { 28 }

    /// Return true iff the raw packet data *looks* like an ONC-RPC message,
    /// where "looks like" involves squinting at the fragment header, XID,
    /// and so on and making some incorrect assumptions.
    pub fn looks_like_it_be_what_it_is(&self) -> bool {
        // Incorrect assumption 1: messages are not fragmented.
        self.is_last_fragment() &&
            // Incorrect assumption 2: XID is always nonzero
            self.xid() > 0 &&
            // OK, I guess fragment length is greater than zero
            self.fragment_length() > 0 &&
            // The message should have a valid type
            self.message_type().is_some() &&
            // We don't support no stinkin' RFC 1050
            self.version().unwrap_or(2) == 2 &&
            // Who the heck would use ONC-RPC for anything but NFS??
            self.program().map_or(true, |p| p == 100003) &&
            // Incorrect assumption 3: nobody uses NFSv4 (or 2...)
            self.program_version().map_or(true, |v| v == 3)
    }

    /// Return true iff this is the last fragment.
    pub fn is_last_fragment(&self) -> bool {
        self.data[0] & 0x80 != 0
    }

    /// Return the fragment length.
    pub fn fragment_length(&self) -> u32 { u32be_to_host(self.data, 4) }

    /// Return the RPC XID.
    pub fn xid(&self) -> u32 { u32be_to_host(self.data, 4) }

    /// Return the type of the message (Call or Reply), or None if the
    /// field contains a value not specified by RFC 5531.
    pub fn message_type(&self) -> Option<OncRpcMessageType> {
        match u32be_to_host(self.data, 8) {
            0 => Some(OncRpcMessageType::Call),
            1 => Some(OncRpcMessageType::Reply),
            _ => None
        }
    }

    /// Return a Call-only field at a given offset, or None if this is a Reply.
    fn call_only_field(&self, offset: usize) -> Option<u32> {
        match self.message_type() {
            Some(OncRpcMessageType::Call)
                => Some(u32be_to_host(self.data, offset)),
            _ => None
        }
    }

    /* These fields are specific to Call messages. */
    pub fn version(&self) -> Option<u32> { self.call_only_field(12) }
    pub fn program(&self) -> Option<u32> { self.call_only_field(16) }
    pub fn program_version(&self) -> Option<u32> { self.call_only_field(20) }
    pub fn procedure(&self) -> Option<u32> { self.call_only_field(24) }
    pub fn auth_size(&self) -> Option<usize> {
        self.call_only_field(32).map(|x| x as usize)
    }

    /// Return the total size of the RPC message header. This is the same
    /// as the offset to the payload, if there is one. Note that we are
    /// assuming the verifier for both calls and replies is AUTH_NONE with
    /// a zero-length body.
    pub fn header_size(&self) -> Option<usize> {
        match self.message_type() {
            Some(OncRpcMessageType::Reply) => Some(28),
            Some(OncRpcMessageType::Call)
                => Some(self.auth_size().unwrap() + 44),
            _ => None
        }
    }

    pub fn payload(&self) -> Option<&[u8]> {
        match self.header_size() {
            Some(header_size) => Some(&self.data[header_size..]),
            _ => None
        }
    }
}

fn main() {
    // XXX: yeah, yeah, yeah, use try!
    let mut cap = Capture::from_raw_fd(0).unwrap();

    while let Ok(packet) = cap.next() {
        // Unpack the delicious, meaty 5-layer burrito of NFS traffic.
        // We have the application layer beef and chicken combo (NFS inside
        // ONC-RPC), transport layer beans (TCP) blended with spicy network
        // layer rice (IPv4), liberally covered in link layer guacamole
        // (Ethernet). In this metaphor, the physical layer tortilla has
        // already been opened for us.
        let data = tcp_data(packet.data);

        // WARNING! We play fast and loose here by attempting to interpret
        // every TCP payload as the beginning of an ONC-RPC message, bailing
        // if it looks like a continuation. This is obviously wrong, but in
        // order to do it correctly, we would need to reconstruct the TCP
        // stream, and frankly, ain't nobody got time for that. (Literally.
        // The slightest delay in pulling data off stdin could cause us to
        // drop packets on capture. This problem can be solved, of course,
        // e.g., by keeping separate buffers for raw packets and TCP data
        // which are maintained by threads running on different CPUs.)
        if let Some(rpc) = OncRpcMessage::new(data) {
            if rpc.looks_like_it_be_what_it_is() {
                println!("{:?}", rpc.xid());
                println!("{:?}", rpc.payload());
            }
        }
    }
}
