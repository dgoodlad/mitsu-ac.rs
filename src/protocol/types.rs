use super::encoding::*;
use enum_repr::EnumRepr;

#[EnumRepr(type="u8")]
#[derive(Debug, Eq, PartialEq)]
pub enum Power {
    Off = 0,
    On = 1,
}

impl OneByteEncodable for Power {
    fn encoded_as_byte(&self) -> u8 {
        self.repr()
    }
}

one_byte_encodable_enum!(Power, Mode, Fan, Vane, WideVane);

#[EnumRepr(type="u8")]
#[derive(Debug, Eq, PartialEq)]
pub enum Mode {
    Heat = 0x01,
    Dry  = 0x02,
    Cool = 0x03,
    Fan  = 0x07,
    Auto = 0x08,
}

impl OneByteEncodable for Mode {
    fn encoded_as_byte(&self) -> u8 {
        self.repr()
    }
}

#[EnumRepr(type="u8")]
#[derive(Debug, Eq, PartialEq)]
pub enum Fan {
    Auto  = 0x00,
    Quiet = 0x01,
    F1    = 0x02,
    F2    = 0x03,
    F3    = 0x05,
    F4    = 0x06,
}

impl OneByteEncodable for Fan {
    fn encoded_as_byte(&self) -> u8 {
        self.repr()
    }
}

#[EnumRepr(type="u8")]
#[derive(Debug, Eq, PartialEq)]
pub enum Vane {
    Auto  = 0x00,
    V1    = 0x01,
    V2    = 0x02,
    V3    = 0x03,
    V4    = 0x04,
    V5    = 0x05,
    Swing = 0x07,
}

impl OneByteEncodable for Vane {
    fn encoded_as_byte(&self) -> u8 {
        self.repr()
    }
}

#[EnumRepr(type="u8")]
#[derive(Debug, Eq, PartialEq)]
pub enum WideVane {
    LL     = 0x01,
    L      = 0x02,
    Center = 0x03,
    R      = 0x04,
    RR     = 0x05,
    LR     = 0x08,
    Swing  = 0x0c,
}

impl OneByteEncodable for WideVane {
    fn encoded_as_byte(&self) -> u8 {
        self.repr()
    }
}

#[EnumRepr(type="u8")]
#[derive(Debug, Eq, PartialEq)]
pub enum ISee {
    Off = 0x00,
    On  = 0x01,
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
