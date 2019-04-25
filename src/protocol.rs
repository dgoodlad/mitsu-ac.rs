use nom::*;
use core::ops::Add;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketType {
    Set = 0x41,
    Get = 0x42,
    ConnectAck = 0x7a,
    Unknown = 0xff,
}

impl From<u8> for PacketType {
    fn from(byte: u8) -> Self {
        match byte {
            0x41 => PacketType::Set,
            0x42 => PacketType::Get,
            0x7a => PacketType::ConnectAck,
            _ => PacketType::Unknown,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Power {
    On,
    Off,
}

#[derive(Debug, Eq, PartialEq)]
enum Mode {
    Heat,
    Dry,
    Cool,
    Fan,
    Auto,
}

type Setpoint = u8;

#[derive(Debug, Eq, PartialEq)]
enum Fan {
    Auto,
    Quiet,
    F1,
    F2,
    F3,
    F4,
}

#[derive(Debug, Eq, PartialEq)]
enum Vane {
    Auto,
    V1,
    V2,
    V3,
    V4,
    V5,
    Swing,
}

#[derive(Debug, Eq, PartialEq)]
enum WideVane {
    LL,
    L,
    Center,
    R,
    RR,
    LR,
    Swing,
}

type ISee = bool;

#[derive(Debug, Eq, PartialEq)]
struct SettingsData {
    power: Option<Power>,
    mode: Option<Mode>,
    setpoint: Option<Setpoint>,
    fan: Option<Fan>,
    vane: Option<Vane>,
    widevane: Option<WideVane>,
    isee: Option<ISee>,
}

trait Checksummable {
    fn checksum(&self) -> Checksum;
}

#[derive(Debug, PartialEq, Eq)]
struct PacketHeader {
    packet_type: PacketType,
    length: usize,
}

impl Checksummable for PacketHeader {
    fn checksum(&self) -> Checksum {
        Checksum(0x31 + self.packet_type as u32 + self.length as u32)
    }
}

impl Checksummable for [u8] {
    fn checksum(&self) -> Checksum {
        Checksum(self.iter().fold(0u32, |a,b| a + (*b as u32)))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Packet<'a> {
    ChecksumOk { packet_type: PacketType, data: &'a [u8], checksum: ValidChecksum },
    ChecksumInvalid { packet_type: PacketType, data: &'a [u8], checksum: InvalidChecksum },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Checksum(u32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ValidChecksum(u8);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct InvalidChecksum {
    received: Checksum,
    calculated: Checksum,
}

impl Add for Checksum {
    type Output = Checksum;

    fn add(self, other: Checksum) -> Checksum {
        Checksum(self.0 + other.0)
    }
}

impl From<u8> for Checksum {
    fn from(byte: u8) -> Checksum {
        Checksum(byte as u32)
    }
}

impl Checksum {
    fn verify(self, other: Checksum) -> Result<ValidChecksum, InvalidChecksum> {
        if other == self {
            Ok(ValidChecksum(self.0 as u8))
        } else {
            Err(InvalidChecksum { received: self, calculated: other })
        }
    }
}


named!(length_sum<u32>, do_parse!(
    length: peek!(be_u8) >>
    sum: map!(take!(length + 1), sum_bytes) >>
    (sum)
));

named!(header<PacketHeader>, do_parse!(
    tag!(&[0xfc]) >>
    packet_type: packet_type >>
    tag!(&[0x01, 0x30]) >>
    length: map!(be_u8, |b| b as usize) >>
    (PacketHeader { packet_type, length: length })
));

named!(packet_type<PacketType>, map!(be_u8, PacketType::from));

#[allow(dead_code)]
fn sum_bytes(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |a,b| a + (*b as u32))
}

named!(packet<Packet>, do_parse!(
    header: header >>
    header_sum: expr_opt!(Some(header.checksum())) >>
    data_sum: peek!(map!(take!(header.length), <[u8]>::checksum)) >>
    data: take!(header.length) >>
    checksum: do_parse!(
        received: map!(be_u8, Checksum::from) >>
        (received.verify(header_sum + data_sum))
    ) >>
    (match checksum {
        Ok(valid) => Packet::ChecksumOk {
            packet_type: header.packet_type,
            data: data,
            checksum: valid,
        },
        Err(invalid) => Packet::ChecksumInvalid {
            packet_type: header.packet_type,
            data: data,
            checksum: invalid,
        }
    })
));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_test() {
        assert_eq!(header(&[0xfc, 0x41, 0x01, 0x30, 0x42]),
            Ok((&b""[..], PacketHeader { packet_type: PacketType::Set, length: 0x42 }))
        );
    }

    #[test]
    fn packet_test() {
        assert_eq!(packet(&[0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0xac]),
            Ok((&b""[..], Packet::ChecksumOk {
                packet_type: PacketType::ConnectAck,
                data: &[0x00],
                checksum: ValidChecksum(0xac),
            }))
        );
        assert_eq!(packet(&[0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0x42]),
            Ok((&b""[..], Packet::ChecksumInvalid {
                packet_type: PacketType::ConnectAck,
                data: &[0x00],
                checksum: InvalidChecksum { calculated: Checksum(0xac), received: Checksum(0x42) },
            }))
        );
    }

    #[test]
    fn length_sum_test() {
        assert_eq!(length_sum(&[0x2, 0x20, 0x22]), Ok((&b""[..], 0x44)));
    }
}
