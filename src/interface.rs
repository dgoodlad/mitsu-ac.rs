#[macro_use]
use crate::protocol::packets::RawPacket;
use crate::protocol::packets::ChecksummedPacket;
use embedded_hal::serial;
use heapless::Vec;
use heapless::spsc::Queue;
use heapless::consts::*;

/// Used for packet-sized buffers
type MaxPacketSize = U22;

pub struct MitsubishiDevice<S> where S: serial::Read<u8> + serial::Write<u8> {
    serial: S,
    serial_buffer: heapless::spsc::Queue<u8, U32>,
    packet_buffer: Vec<u8, MaxPacketSize>,
}

impl<S> MitsubishiDevice<S> where S: serial::Read<u8> + serial::Write<u8> {
    pub fn new(serial: S) -> Self {
        MitsubishiDevice { serial, serial_buffer: Queue::new(), packet_buffer: Vec::new() }
    }

    pub fn read_single_packet<'a>(&'a self) -> Option<ChecksummedPacket> {
        let buffer = &self.packet_buffer;
        match RawPacket::read(&buffer[0..buffer.len()]) {
            Ok((remaining, packet @ RawPacket::Complete { .. })) => None,
            Ok((remaining, RawPacket::Incomplete { expected_length })) => None,
            Err(e) => None,
        }
    }
}
