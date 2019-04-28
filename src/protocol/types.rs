use super::encoding::*;

#[derive(Debug, Eq, PartialEq)]
pub enum Power {
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

impl OneByteEncodable for Power {
    fn encoded_as_byte(&self) -> u8 {
        match self {
            Power::Off => 0x00,
            Power::On => 0x01,
            Power::Unknown => 0x00,
        }
    }
}

one_byte_encodable_enum!(Power, Mode, Fan, Vane, WideVane);

#[derive(Debug, Eq, PartialEq)]
pub enum Mode {
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

impl OneByteEncodable for Mode {
    fn encoded_as_byte(&self) -> u8 {
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
pub enum Fan {
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

impl OneByteEncodable for Fan {
    fn encoded_as_byte(&self) -> u8 {
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
pub enum Vane {
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

impl OneByteEncodable for Vane {
    fn encoded_as_byte(&self) -> u8 {
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
pub enum WideVane {
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

impl OneByteEncodable for WideVane {
    fn encoded_as_byte(&self) -> u8 {
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
pub enum ISee {
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

#[derive(Debug, PartialEq, Eq)]
pub enum Temperature {
    HalfDegreesCPlusOffset { value: u8 },
    SetpointMapped { value: u8 },
    RoomTempMapped { value: u8 },
}

impl Temperature {
    pub fn celsius_tenths(&self) -> TenthDegreesC {
        match self {
            Temperature::HalfDegreesCPlusOffset { value } => TenthDegreesC((value - 128) * 5),
            Temperature::SetpointMapped { value } => TenthDegreesC((0x1f - value) * 10),
            Temperature::RoomTempMapped { value } => TenthDegreesC((value + 10) * 10),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TenthDegreesC(pub u8);

impl TenthDegreesC {
    pub fn encode_as_setpoint_mapped(&self) -> u8 { 0x1f - self.0 / 10 }
    pub fn encode_as_room_temp_mapped(&self) -> u8 { self.0 / 10 - 10 }
    pub fn encode_as_half_deg_plus_offset(&self) -> u8 { self.0 / 5 + 128 }
}
