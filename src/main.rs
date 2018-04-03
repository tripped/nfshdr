extern crate pcap;
use pcap::Capture;

fn main() {

    // XXX: yeah, yeah, yeah, use try!
    let mut cap = Capture::from_raw_fd(0).unwrap();

    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
    }
}
