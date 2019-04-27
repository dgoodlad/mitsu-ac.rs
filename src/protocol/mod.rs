use nom::*;
use core::ops::Add;

pub mod packets;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketType {
    SetRequest      = 0x41,
    GetInfoRequest  = 0x42,
    ConnectRequest  = 0x5a,

    SetResponse     = 0x61,
    GetInfoResponse = 0x62,
    ConnectResponse = 0x7a,

    Unknown         = 0xff,
}

impl From<u8> for PacketType {
    fn from(byte: u8) -> Self {
        match byte {
            0x41 => PacketType::SetRequest,
            0x42 => PacketType::GetInfoRequest,
            0x5a => PacketType::ConnectRequest,

            0x61 => PacketType::SetResponse,
            0x62 => PacketType::GetInfoResponse,
            0x7a => PacketType::ConnectResponse,

            _ => PacketType::Unknown,
        }
    }
}

impl PacketType {
    fn encode(&self) -> u8 {
        match self {
            PacketType::SetRequest      => 0x41,
            PacketType::GetInfoRequest  => 0x42,
            PacketType::ConnectRequest  => 0x5a,

            PacketType::SetResponse     => 0x61,
            PacketType::GetInfoResponse => 0x62,
            PacketType::ConnectResponse => 0x7a,

            PacketType::Unknown         => 0xff,
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

impl Power {
    fn encode(&self) -> u8 {
        match self {
            Power::Off => 0x00,
            Power::On => 0x01,
            Power::Unknown => 0x00,
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

impl Mode {
    fn encode(&self) -> u8 {
        match self {
            Mode::Heat    => 0x01,
            Mode::Dry     => 0x02,
            Mode::Cool    => 0x03,
            Mode::Fan     => 0x07,
            Mode::Auto    => 0x08,
            Mode::Unknown => 0x00,
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

impl Fan {
    fn encode(&self) -> u8 {
        match self {
            Fan::Auto    => 0x00,
            Fan::Quiet   => 0x01,
            Fan::F1      => 0x02,
            Fan::F2      => 0x03,
            Fan::F3      => 0x05,
            Fan::F4      => 0x06,
            Fan::Unknown => 0x00,
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

impl Vane {
    fn encode(&self) -> u8 {
        match self {
            Vane::Auto    => 0x00,
            Vane::V1      => 0x01,
            Vane::V2      => 0x02,
            Vane::V3      => 0x03,
            Vane::V4      => 0x04,
            Vane::V5      => 0x05,
            Vane::Swing   => 0x07,
            Vane::Unknown => 0x00,
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

impl WideVane {
    fn encode(&self) -> u8 {
        match self {
            WideVane::LL      => 0x01,
            WideVane::L       => 0x02,
            WideVane::Center  => 0x03,
            WideVane::R       => 0x04,
            WideVane::RR      => 0x05,
            WideVane::LR      => 0x08,
            WideVane::Swing   => 0x0c,
            WideVane::Unknown => 0x00,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ISee {
    On,
    Off,
    Unknown,
}

impl From<u8> for ISee {
    fn from(byte: u8) -> Self {
        match byte {
            0 => ISee::Off,
            1 => ISee::On,
            _ => ISee::Unknown,
        }
    }
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
struct TenthDegreesC(u8);

impl TenthDegreesC {
    fn encode_as_setpoint_mapped(&self) -> u8 { 0x1f - self.0 / 10 }
    fn encode_as_room_temp_mapped(&self) -> u8 { self.0 / 10 - 10 }
    fn encode_as_half_deg_plus_offset(&self) -> u8 { self.0 / 5 + 128 }
}

#[derive(Debug, PartialEq, Eq)]
enum GetInfoResponseData {
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

named!(settings_data<GetInfoResponseData>, do_parse!(
    tag!(&[InfoType::Settings as u8]) >>
    take!(2) >>
    power: map!(be_u8, Power::from) >>
    mode_and_isee: bits!(tuple!(
        take_bits!(u8, 4),
        map!(take_bits!(u8, 1), ISee::from),
        map!(take_bits!(u8, 3), Mode::from))) >>
    isee: value!(mode_and_isee.1) >>
    mode: value!(mode_and_isee.2) >>
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
    (GetInfoResponseData::Settings {
        power, mode, fan, vane, widevane, setpoint, isee
    })
));

named!(room_temp_data<GetInfoResponseData>, do_parse!(
    tag!(&[InfoType::RoomTemp as u8]) >>
    take!(2) >>
    mapped: map!(be_u8, |b| Temperature::RoomTempMapped { value: b }) >>
    take!(2) >>
    half_deg: map!(be_u8, |b| Temperature::HalfDegreesCPlusOffset { value: b }) >>
    take!(9) >>
    temperature: value!(match (half_deg, mapped) {
        (Temperature::HalfDegreesCPlusOffset { value: 0 }, t) => t,
        (t, _) => t,
    }) >>
    (GetInfoResponseData::RoomTemperature { temperature })
));

named!(timer_data<GetInfoResponseData>, do_parse!(
    tag!(&[InfoType::Timers as u8]) >>
    (GetInfoResponseData::Unknown)
));

// TODO test the status info packet
named!(status_data<GetInfoResponseData>, do_parse!(
    tag!(&[InfoType::Status as u8]) >>
    take!(2) >>
    compressor_frequency: be_u8 >>
    operating: be_u8 >>
    (GetInfoResponseData::Status { compressor_frequency, operating })
));

named!(unknown_data<GetInfoResponseData>, do_parse!((GetInfoResponseData::Unknown)));

named!(data<GetInfoResponseData>, alt!(
    settings_data |
    room_temp_data |
    timer_data |
    status_data |
    unknown_data
    )
);

struct ControlPacketData {
    power: Option<Power>,
    mode: Option<Mode>,
    temp: Option<Temperature>,
    fan: Option<Fan>,
    vane: Option<Vane>,
    widevane: Option<WideVane>,
}

// "Control packet" data: sends desired settings to the device
//
// 16-bytes:
//
//  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
// ID  F0  F1  PW  MO  TM  FA  VA  xx  xx  xx  xx  xx  WV  T2  xx
//
// ID: 0x01
// F0: Flag byte 0, set bits indicate presence of power/mode/temp/fan/vane values
// F1: Flag byte 1, set bits indicate presence of widevane value
// PW: Power
// MO: Mode
// TM: Temperature (as 'setpoint mapped' value)
// FA: Fan
// VA: Vane
// WV: Wide Vane
// T2: Temperature (as half-degrees c + offset)
impl<'a> ControlPacketData {
    fn write(&self, data: &'a mut [u8; 16]) -> &'a [u8; 16] {
        data[0] = 0x01; // Unknown constant in the protocol
        self.write_flags(&mut data[1..3]);

        data[3] = match self.power {
            Some(ref power) => power.encode(),
            _ => 0x00,
        };

        data[4] = match self.mode {
            Some(ref mode) => mode.encode(),
            _ => 0x00,
        };

        data[5] = match self.temp {
            Some(ref temp) => temp.celsius_tenths().encode_as_setpoint_mapped(),
            _ => 0x00,
        };

        data[6] = match self.fan {
            Some(ref fan) => fan.encode(),
            _ => 0x00,
        };

        data[7] = match self.vane {
            Some(ref vane) => vane.encode(),
            _ => 0x00,
        };

        data[13] = match self.widevane {
            Some(ref widevane) => widevane.encode(),
            _ => 0x00,
        };

        data[14] = match self.temp {
            Some(ref temp) => temp.celsius_tenths().encode_as_half_deg_plus_offset(),
            _ => 0x00,
        };

        data
    }

    fn write_flags(&self, data: &mut [u8]) {
        data[0] = 0x00u8 |
            (match self.power { Some(Power::Unknown) => 0, Some(_) => 0b00000001, _ => 0 }) |
            (match self.mode  { Some(Mode::Unknown)  => 0, Some(_) => 0b00000010, _ => 0 }) |
            (match self.temp  {                            Some(_) => 0b00000100, _ => 0 }) |
            (match self.fan   { Some(Fan::Unknown)   => 0, Some(_) => 0b00001000, _ => 0 }) |
            (match self.vane  { Some(Vane::Unknown)  => 0, Some(_) => 0b00010000, _ => 0 });
        data[1] = 0x00u8 |
            (match self.widevane { Some(WideVane::Unknown) => 0, Some(_) => 0b00000001, _ => 0 });
    }
}

// TODO use this enum in the parser macros, too
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum InfoType {
    Settings     = 0x02,
    RoomTemp     = 0x03,
    Unknown      = 0x04,
    Timers       = 0x05,
    Status       = 0x06,
    MaybeStandby = 0x09,
}

impl InfoType {
    fn encode(&self) -> u8 {
        self.clone() as u8
    }
}

struct InfoPacketData {
    info_type: InfoType,
}

impl<'a> InfoPacketData {
    fn write(&self, data: &'a mut [u8; 16]) -> &'a [u8; 16] {
        data[0] = self.info_type as u8;
        for i in &mut data[1..16] { *i = 0u8 }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &[u8] = &[];

    #[test]
    fn header_test() {
        assert_eq!(header(&[0xfc, 0x41, 0x01, 0x30, 0x42]),
            Ok((EMPTY, PacketHeader { packet_type: PacketType::SetRequest, length: 0x42 }))
        );
    }

    #[test]
    fn packet_test() {
        assert_eq!(packet(&[0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0xac]),
            Ok((EMPTY, Packet::ChecksumOk {
                packet_type: PacketType::ConnectResponse,
                data: &[0x00],
                checksum: ValidChecksum(0xac),
            }))
        );
        assert_eq!(packet(&[0xfc, 0x41, 0x01, 0x30, 0x010, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0xfa]),
            Ok((EMPTY, Packet::ChecksumOk {
                packet_type: PacketType::SetRequest,
                data: &[0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00],
                checksum: ValidChecksum(0xfa),
            }))
        );
        assert_eq!(packet(&[0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0x42]),
            Ok((EMPTY, Packet::ChecksumInvalid {
                packet_type: PacketType::ConnectResponse,
                data: &[0x00],
                checksum: InvalidChecksum { calculated: Checksum(0xac), received: Checksum(0x42) },
            }))
        );
    }

    #[test]
    fn settings_data_test() {
        assert_eq!(data(&[0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07, 0x00, 0x00, 0x03, 0x94, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponseData::Settings {
                power: Power::On,
                mode: Mode::Heat,
                setpoint: Setpoint(Temperature::HalfDegreesCPlusOffset { value: 0x94 }),
                fan: Fan::Auto,
                vane: Vane::Swing,
                widevane: WideVane::Center,
                isee: ISee::Off,

            }))
        );
        assert_eq!(data(&[0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07, 0x00, 0x00, 0x03, 0xa0, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponseData::Settings {
                power: Power::On,
                mode: Mode::Heat,
                setpoint: Setpoint(Temperature::HalfDegreesCPlusOffset { value: 0xa0 }),
                fan: Fan::Auto,
                vane: Vane::Swing,
                widevane: WideVane::Center,
                isee: ISee::Off,
            }))
        );
    }

    #[test]
    fn temperature_data_test() {
        // When the half-degrees value is present in byte 6, use it
        assert_eq!(data(&[0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponseData::RoomTemperature {
                temperature: Temperature::HalfDegreesCPlusOffset{ value: 0xaa },
            }))
        );
        // When the half-degrees value is missing, test that we fall back to the
        // lower-res "mapped" value from byte 3
        assert_eq!(data(&[0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponseData::RoomTemperature {
                temperature: Temperature::RoomTempMapped{ value: 0x0b },
            }))
        );
    }

    #[test]
    fn control_packet_data_flags_test() {
        let mut slice = [0x00, 0x00];
        let mut packet = ControlPacketData {
            power: Some(Power::On),
            mode: Some(Mode::Auto),
            fan: Some(Fan::Auto),
            vane: Some(Vane::Swing),
            widevane: Some(WideVane::LL),
            temp: Some(Temperature::HalfDegreesCPlusOffset { value: TenthDegreesC(210).encode_as_half_deg_plus_offset() }),
        };
        packet.write_flags(&mut slice);
        assert_eq!(0b00011111, slice[0]);
        assert_eq!(0b00000001, slice[1]);

        packet.widevane = None;
        packet.write_flags(&mut slice);
        assert_eq!(0b00011111, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        packet.power = None;
        packet.write_flags(&mut slice);
        assert_eq!(0b00011110, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        packet.mode = None;
        packet.write_flags(&mut slice);
        assert_eq!(0b00011100, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        packet.fan = None;
        packet.write_flags(&mut slice);
        assert_eq!(0b00010100, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        packet.vane = None;
        packet.write_flags(&mut slice);
        assert_eq!(0b00000100, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        packet.temp = None;
        packet.write_flags(&mut slice);
        assert_eq!(0b00000000, slice[0]);
        assert_eq!(0b00000000, slice[1]);
    }

    #[test]
    fn control_packet_data_write_test() {
        let mut slice = [0x00; 16];
        let packet = ControlPacketData {
            power: Some(Power::On),
            mode: Some(Mode::Auto),
            fan: Some(Fan::Auto),
            vane: Some(Vane::Swing),
            widevane: Some(WideVane::LL),
            temp: Some(Temperature::HalfDegreesCPlusOffset { value: TenthDegreesC(210).encode_as_half_deg_plus_offset() }),
        };

        let result = packet.write(&mut slice);
        assert_eq!(result[0], 0x01, "must start with 0x01");
        assert_eq!(result[1], 0b00011111, "flags.0");
        assert_eq!(result[2], 0b00000001, "flags.1");
        assert_eq!(result[3], 0x01, "power");
        assert_eq!(result[4], 0x08, "mode");
        assert_eq!(result[5], 0x0a, "temp mapped");
        assert_eq!(result[6], 0x00, "fan");
        assert_eq!(result[7], 0x07, "vane");
        assert_eq!(result[8..13], [0x00; 5], "NULL");
        assert_eq!(result[13], 0x01, "widevane");
        assert_eq!(result[14], 0xaa, "temp as half-deg offset");
    }

    #[test]
    fn info_packet_data_write_test() {
        let mut slice = [0x01; 16]; // Make it all 1s to test that the later bytes get zeroed out properly
        let packet = InfoPacketData { info_type: InfoType::Settings };
        let result = packet.write(&mut slice);

        assert_eq!(result[0], 0x02, "info type = settings");
        assert_eq!(result[1..16], [0x00; 15]);
    }
}
