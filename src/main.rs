extern crate pcap;
extern crate pnet_packet;

use pcap::Capture;
use pnet_packet::{ipv4,tcp};
use std::collections::HashMap;
use std::mem;

/// Given a u8 slice containing a reassembled Ethernet "packet", return
/// a TcpPacket representing the inner TCP header, and a u8 slice spanning
/// the segment data.
fn tcp_data_from_reassembled_ethernet(data: &[u8])
        -> (tcp::TcpPacket, &[u8]) {
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
    let segment_start = tcp_offset + 4 * tcp.get_data_offset() as usize;

    // Ethernet requires that the payload length be at least 46 bytes
    // (when 802.1Q tag is absent); shorter payloads are zero-padded.
    // Thus, to figure out how long the TCP segment data *really* is,
    // we must look at the IPv4 header.
    let segment_end = ip4_offset + ip4.get_total_length() as usize;

    (tcp, &data[segment_start..segment_end])
}

/// Models one end of an ONC-RPC dialogue. Feed it TCP segments and it
/// will periodically excrete an ONC-RPC message!
struct Conversation {
    /// Whether the conversation has seen at least one valid ONC-RPC message.
    started: bool,

    /// The current highest-observed sequence number in the TCP stream.
    sequence: u32,

    /// The sequence position at which we expect to see the next message.
    next: u32,

    /// 1KiB of buffer ought to be enough for anybody.
    /// XXX: currently unused.
    buffer: [u8;1024],
}

impl Conversation {
    pub fn new(seq: u32) -> Conversation {
        Conversation {
            started: false,
            sequence: seq,
            next: seq,
            buffer: [0;1024],
        }
    }

    /// Advance the state of the conversation by processing a TCP segment
    /// header and data. Return Some(message) if the segment contained a
    /// full ONC-RPC header.
    ///
    /// N.B.: this process depends on being able to "latch on" to a valid
    /// ONC-RPC message at some point in order to transition from "unstarted"
    /// to "started." Currently, this works by assuming that the first
    /// segment that could possibly contain an RPC message has one at offset
    /// zero. In general, it would be necessary to examine every byte of
    /// every segment and apply some heuristic to decide if it looks like
    /// an ONC-RPC header, but we don't do anything fancy yet.
    ///
    /// The current behavior is likely to work as long as the capture
    /// contains the *start* of the RPC traffic.
    ///
    /// TODO: add fancy RPC detection in the unstarted state
    /// TODO: needs to buffer for incomplete RPC headers.
    pub fn update<'a>(&mut self, i: u32, tcp: &tcp::TcpPacket, data: &'a [u8])
            -> Option<OncRpcMessage<'a>>
    {
        self.sequence = tcp.get_sequence();
        if !self.started && data.len() > 20 { // super crappy!
            self.started = true;
            self.next = self.sequence;
        }

        let start = self.sequence;
        let end = start + data.len() as u32;

        // Is the next RPC position inside this segment?
        if self.started && (self.next >= start && self.next < end) {
            let offset = (self.next - start) as usize;
            println!("Frame {} dst={} seq={} size={}",
                    i, tcp.get_destination(), self.sequence, data.len());
            println!("Next={}", self.next);
            println!("Segment contains RPC message at {}", offset);

            let rpc_snippet = &data[
                offset..std::cmp::min(offset+64, data.len())];

            println!("{:16.1x}", HexDump(rpc_snippet));

            // XXX: ASSUMES THE ENTIRE RPC HEADER IS IN THIS SEGMENT!!
            let rpc = OncRpcMessage::new(&data[offset..]).unwrap();

            let cur_size = rpc.fragment_length() + 4;
            println!("Next RPC in {} bytes", cur_size);
            self.next += cur_size;

            Some(rpc)
        } else {
            None
        }
    }
}

/// Extracts ONC-RPC messages from a stream of TCP goop.
struct RpcStream<T: pcap::Activated> {
    /// The packet capture from which to acquire TCP goop.
    capture: pcap::Capture<T>,
    count: u32,

    /// Map of destination port -> (sequence, next_rpc_offset). This should be
    /// a good enough state, assuming the input capture only includes one TCP
    /// conversation, or only conversations between two IP addresses!
    conversations: HashMap<u16, Conversation>,
}

impl<T: pcap::Activated> RpcStream<T> {
    pub fn new(capture: pcap::Capture<T>) -> RpcStream<T> {
        RpcStream {
            capture: capture,
            count: 0,
            conversations: HashMap::new(),
        }
    }

    /// Return the next OncRpcMessage from the capture, blocking as needed
    /// until enough data is observed to identify it.
    ///
    /// XXX: this should probably be a proper iterator.
    pub fn next(&mut self) -> Result<u32, pcap::Error> {

        loop {
            let packet = self.capture.next()?;
            let (tcp, segment) =
                tcp_data_from_reassembled_ethernet(packet.data);

            // Find the conversation record for this end of the stream
            let mut conv = self.conversations
                .entry(tcp.get_destination())
                .or_insert(Conversation::new(tcp.get_sequence()));

            // One more packet on the pile
            self.count += 1;

            // XXX: this should be returning the message itself, not just
            // the frame number; however, we'll need to restructure this a
            // bit to avoid falling into the "can't borrow mutably more than
            // once" trap. (Allowing msg to escape the loop extends the
            // mutable borrow on self.capture. This isn't over-cautious, as
            // msg contains a slice of the data yielded by the previous call
            // to self.capture.next(), which is only valid until the next
            // call! So we need to adopt a structure that allows us to prove
            // to the Rust compiler that the packet data is never still
            // borrowed at the time we call capture.next())
            if let Some(msg) = conv.update(self.count, &tcp, segment) {
                return Ok(self.count)
            }
        }
    }
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
            self.version().map_or(true, |v| v == 2) &&
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
    pub fn fragment_length(&self) -> u32 {
        u32be_to_host(self.data, 0) & 0x7FFFFFFF
    }

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

/// A wrapper for u8 slices that provides an impl for LowerHex/UpperHex.
/// Control of the hex dump output is done by providing formatting flags;
/// "width" and "precision" are overloaded to mean "octets per row," and
/// "octets per group." E.g., the format specifier {:16.1x} would result
/// in output like this:
///
///     00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
///     10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
///
/// And {:8.2x} would produce output like this:
///
///     0001 0203 0405 0607
///     0809 0a0b 0c0d 0e0f
///
/// Zero values (e.g., {:0.0x}) disable rowbreaks and grouping, respectively:
///
///     000102030405060708090a0b0c0d0e0f...
///
struct HexDump<'a>(&'a [u8]);

impl<'a> HexDump<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter, uppercase: bool)
            -> Result<(), std::fmt::Error> {
        let octets_per_row = fmtr.width().unwrap_or(0);
        let octets_per_group = fmtr.precision().unwrap_or(0);
        let mut in_row = 0;
        let mut in_group = 0;
        for (i, octet) in self.0.iter().enumerate() {
            if uppercase {
                try!(fmtr.write_fmt(format_args!("{:02X}", octet)));
            } else {
                try!(fmtr.write_fmt(format_args!("{:02x}", octet)));
            }

            // Don't add trailing space or newline!
            if i+1 == self.0.len() { break; }

            in_row += 1;
            in_group += 1;
            if octets_per_row != 0 && in_row == octets_per_row {
                try!(fmtr.write_str("\n"));
                in_row = 0;
                in_group = 0;
            }
            if octets_per_group != 0 && in_group == octets_per_group {
                try!(fmtr.write_str(" "));
                in_group = 0;
            }
        }
        Ok(())
    }
}

impl<'a> std::fmt::LowerHex for HexDump<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter)
            -> Result<(), std::fmt::Error> {
        self.fmt(fmtr, false)
    }
}

impl<'a> std::fmt::UpperHex for HexDump<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter)
            -> Result<(), std::fmt::Error> {
        self.fmt(fmtr, true)
    }
}

fn main() {
    // XXX: yeah, yeah, yeah, use try!
    let mut cap = Capture::from_raw_fd(0).unwrap();
    let mut stream = RpcStream::new(cap);

    while let Ok(msg) = stream.next() {
        println!("Got RPC message with xid = {}", msg);
    }
}
