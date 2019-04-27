use nom::*;
use core::ops::Add;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketType {
    Set = 0x41,
    Get = 0x42,
    Response = 0x62,
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
    Unknown,
}

impl From<u8> for Power {
    fn from(byte: u8) -> Self {
        match byte {
            0 => Power::Off,
            1 => Power::On,
            _ => Power::Unknown,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Mode {
    Heat,
    Dry,
    Cool,
    Fan,
    Auto,
    Unknown,
}

impl From<u8> for Mode {
    fn from(byte: u8) -> Self {
        match byte {
            1 => Mode::Heat,
            2 => Mode::Dry,
            3 => Mode::Cool,
            7 => Mode::Fan,
            8 => Mode::Auto,
            _ => Mode::Unknown,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Fan {
    Auto,
    Quiet,
    F1,
    F2,
    F3,
    F4,
    Unknown,
}

impl From<u8> for Fan {
    fn from(byte: u8) -> Self {
        match byte {
            0 => Fan::Auto,
            1 => Fan::Quiet,
            2 => Fan::F1,
            3 => Fan::F2,
            5 => Fan::F3,
            6 => Fan::F4,
            _ => Fan::Unknown,
        }
    }
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
    Unknown,
}

impl From<u8> for Vane {
    fn from(byte: u8) -> Self {
        match byte {
            0 => Vane::Auto,
            1 => Vane::V1,
            2 => Vane::V2,
            3 => Vane::V3,
            4 => Vane::V4,
            5 => Vane::V5,
            7 => Vane::Swing,
            _ => Vane::Unknown,
        }
    }
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
    Unknown,
}

impl From<u8> for WideVane {
    fn from(byte: u8) -> Self {
        match byte {
            0x1 => WideVane::LL,
            0x2 => WideVane::L,
            0x3 => WideVane::Center,
            0x4 => WideVane::R,
            0x5 => WideVane::RR,
            0x8 => WideVane::LR,
            0xc => WideVane::Swing,
            _   => WideVane::Unknown,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ISee {
    On,
    Off,
    Unknown,
}

#[derive(Debug, Eq, PartialEq)]
struct Setpoint(Temperature);

#[derive(Debug, Eq, PartialEq)]
struct SettingsData {
    power: Power,
    mode: Mode,
    setpoint: Setpoint,
    fan: Fan,
    vane: Vane,
    widevane: WideVane,
    isee: ISee,
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

impl Checksummable for &[u8] {
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
    fn verify(self, header: &Checksummable, data: &Checksummable) -> Result<ValidChecksum, InvalidChecksum> {
        let calculated = header.checksum() + data.checksum();
        if calculated == self {
            Ok(ValidChecksum(self.0 as u8))
        } else {
            Err(InvalidChecksum { received: self, calculated })
        }
    }
}

named!(header<PacketHeader>, do_parse!(
    tag!(&[0xfc]) >>
    packet_type: packet_type >>
    tag!(&[0x01, 0x30]) >>
    length: map!(be_u8, |b| b as usize) >>
    (PacketHeader { packet_type, length: length })
));

named!(packet_type<PacketType>, map!(be_u8, PacketType::from));

named!(packet<Packet>, do_parse!(
    header: header >>
    data: take!(header.length) >>
    received_checksum: map!(be_u8, Checksum::from) >>
    (match received_checksum.verify(&header, &data) {
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

#[derive(Debug, PartialEq, Eq)]
enum Temperature {
    HalfDegreesCPlusOffset { value: u8 },
    SetpointMapped { value: u8 },
    RoomTempMapped { value: u8 },
}

#[derive(Debug, PartialEq, Eq)]
struct TenthDegreesC(u8);

impl Temperature {
    fn celsius_tenths(&self) -> TenthDegreesC {
        match self {
            Temperature::HalfDegreesCPlusOffset { value } => TenthDegreesC((value - 128) * 5),
            Temperature::SetpointMapped { value } => TenthDegreesC((0x1f - value) * 10),
            Temperature::RoomTempMapped { value } => TenthDegreesC((value + 10) * 10),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedData {
    Settings {
        power: Power,
        mode: Mode,
        setpoint: Setpoint,
        fan: Fan,
        vane: Vane,
        widevane: WideVane,
        isee: ISee,
    },
    RoomTemperature { temperature: Temperature },
    Status { compressor_frequency: u8, operating: u8 },
    Unknown,
}

named!(settings_data<ParsedData>, do_parse!(
    tag!(&[0x02]) >>
    take!(2) >>
    power: map!(be_u8, Power::from) >>
    // TODO when mode:bit3 is set, isee = true
    mode: map!(be_u8, Mode::from) >>
    setpoint_mapped: map!(be_u8, |b| Temperature::SetpointMapped { value: b })>>
    fan: map!(be_u8, Fan::from) >>
    vane: map!(be_u8, Vane::from) >>
    take!(2) >>
    widevane: map!(be_u8, WideVane::from) >>
    setpoint_half_deg: map!(be_u8, |b| Temperature::HalfDegreesCPlusOffset { value: b }) >>
    setpoint: value!(match (setpoint_mapped, setpoint_half_deg) {
        (s, Temperature::HalfDegreesCPlusOffset { value: 0 }) => Setpoint(s),
        (_, s) => Setpoint(s),
    }) >>
    take!(4) >>
    (ParsedData::Settings {
        power, mode, fan, vane, widevane, setpoint, isee: ISee::Unknown
    })
));

named!(room_temp_data<ParsedData>, do_parse!(
    tag!(&[0x03]) >>
    take!(2) >>
    mapped: map!(be_u8, |b| Temperature::RoomTempMapped { value: b }) >>
    take!(2) >>
    half_deg: map!(be_u8, |b| Temperature::HalfDegreesCPlusOffset { value: b }) >>
    take!(9) >>
    temperature: value!(match (half_deg, mapped) {
        (Temperature::HalfDegreesCPlusOffset { value: 0 }, t) => t,
        (t, _) => t,
    }) >>
    (ParsedData::RoomTemperature { temperature })
));

named!(timer_data<ParsedData>, do_parse!(
    tag!(&[0x05]) >>
    (ParsedData::Unknown)
));

// TODO test the status info packet
named!(status_data<ParsedData>, do_parse!(
    tag!(&[0x06]) >>
    take!(2) >>
    compressor_frequency: be_u8 >>
    operating: be_u8 >>
    (ParsedData::Status { compressor_frequency, operating })
));

named!(unknown_data<ParsedData>, do_parse!((ParsedData::Unknown)));

named!(data<ParsedData>, alt!(
    settings_data |
    room_temp_data |
    timer_data |
    status_data |
    unknown_data
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &[u8] = &[];

    #[test]
    fn header_test() {
        assert_eq!(header(&[0xfc, 0x41, 0x01, 0x30, 0x42]),
            Ok((EMPTY, PacketHeader { packet_type: PacketType::Set, length: 0x42 }))
        );
    }

    #[test]
    fn packet_test() {
        assert_eq!(packet(&[0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0xac]),
            Ok((EMPTY, Packet::ChecksumOk {
                packet_type: PacketType::ConnectAck,
                data: &[0x00],
                checksum: ValidChecksum(0xac),
            }))
        );
        assert_eq!(packet(&[0xfc, 0x41, 0x01, 0x30, 0x010, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0xfa]),
            Ok((EMPTY, Packet::ChecksumOk {
                packet_type: PacketType::Set,
                data: &[0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00],
                checksum: ValidChecksum(0xfa),
            }))
        );
        assert_eq!(packet(&[0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0x42]),
            Ok((EMPTY, Packet::ChecksumInvalid {
                packet_type: PacketType::ConnectAck,
                data: &[0x00],
                checksum: InvalidChecksum { calculated: Checksum(0xac), received: Checksum(0x42) },
            }))
        );
    }

    #[test]
    fn settings_data_test() {
        assert_eq!(data(&[0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07, 0x00, 0x00, 0x03, 0x94, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, ParsedData::Settings {
                power: Power::On,
                mode: Mode::Heat,
                setpoint: Setpoint(Temperature::HalfDegreesCPlusOffset { value: 0x94 }),
                fan: Fan::Auto,
                vane: Vane::Swing,
                widevane: WideVane::Center,
                isee: ISee::Unknown,

            }))
        );
        assert_eq!(data(&[0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07, 0x00, 0x00, 0x03, 0xa0, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, ParsedData::Settings {
                power: Power::On,
                mode: Mode::Heat,
                setpoint: Setpoint(Temperature::HalfDegreesCPlusOffset { value: 0xa0 }),
                fan: Fan::Auto,
                vane: Vane::Swing,
                widevane: WideVane::Center,
                isee: ISee::Unknown,
            }))
        );
    }

    #[test]
    fn temperature_data_test() {
        assert_eq!(data(&[0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, ParsedData::RoomTemperature {
                temperature: Temperature::HalfDegreesCPlusOffset{ value: 0xaa },
            }))
        );

    }
}
