use nom::{be_u8};

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
struct Header {
    packet_type: PacketType,
    length: u8,
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

#[derive(Debug, PartialEq, Eq)]
struct Packet<'a> {
    packet_type: PacketType,
    data: &'a [u8],
    checksum: Checksum,
}

#[derive(Debug, PartialEq, Eq)]
struct Checksum(u8);

impl<'a> From<&Packet<'a>> for Checksum {
    fn from(packet: &Packet) -> Checksum {
        let length = packet.data.len() as u8;
        let sum = packet.data.iter().sum::<u8>();
        Checksum((0x01 + 0x30 + packet.packet_type as u8 + length + sum) & 0xff)
    }
}

impl<'a> Packet<'a> {
    fn valid_checksum(&self) -> bool {
        self.checksum == Checksum::from(self)
    }
}

struct InvalidChecksum {
    received: u8,
    calculated: u8,
}

fn verify_checksum(checksum: u8, packet_type: u8, data_sum: u8) -> Result<u8, InvalidChecksum> {
    let calculated = (packet_type + 0x01 + 0x30 + data_sum) & 0xff;
    if calculated == checksum {
        Ok(checksum)
    } else {
        Err(InvalidChecksum { received: checksum, calculated: calculated })
    }
}

named!(length_sum<u8>, do_parse!(
    length: be_u8 >>
    sum: fold_many_m_n!(length as usize, length as usize, be_u8, 0, |acc, item| acc + item) >>
    (sum)
));

named!(packet<Packet>, do_parse!(
    tag!(&[0xfc]) >>
    packet_type: be_u8 >>
    tag!(&[0x01, 0x30]) >>
    data: length_bytes!(be_u8) >>
    checksum: be_u8 >>
    (Packet {
        packet_type: PacketType::from(packet_type),
        data: data,
        checksum: Checksum(checksum),
    })
));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_test() {
        assert_eq!(packet(&[0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0x54]),
            Ok((&b""[..], Packet {
                packet_type: PacketType::ConnectAck,
                data: &[0x00],
                checksum: Checksum(0x54),
            }))
        )
    }

    #[test]
    fn length_sum_test() {
        assert_eq!(length_sum(&[0x2, 0x20, 0x22]), Ok((&b""[..], 0x42)));
    }
}
