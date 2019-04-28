use nom::*;
use super::types::{Power, Mode, Temperature, Fan, Vane, WideVane, TenthDegreesC};
use super::encoding::*;
use core::marker::PhantomData;

trait PacketType {
    const ID: u8;
}

trait PacketData<T: PacketType> : Encodable + Sized {
    fn length(&self) -> usize;
    fn decode(from: &[u8]) -> IResult<&[u8], Self>;
}

#[derive(Debug, Eq, PartialEq)]
struct Packet<T: PacketType, D: PacketData<T>> {
    _packet_type: PhantomData<T>,
    data: D,
}

#[derive(Debug, Eq, PartialEq)]
struct DecodingError;

impl<T: PacketType, D: PacketData<T>> Packet<T, D> {
    fn new(data: D) -> Self {
        Packet {
            _packet_type: PhantomData,
            data: data,
        }
    }

    // TODO should we really abstract away from nom here, or just return an IResult?
    fn parse(input: &[u8]) -> Result<Self, DecodingError> {
        match parse_packet_type(input, D::decode) {
            Ok((rest, packet)) => Ok(packet),
            Err(_) => Err(DecodingError),
        }
    }
}

impl<T: PacketType, D: PacketData<T>> Encodable for Packet<T, D> {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        let data_len = self.data.length();
        if into.len() != 5 + data_len + 1 {
            //Ok(into)
            Err(EncodingError)
        } else {
            into[0] = 0xfc;
            into[1] = T::ID;
            into[2] = 0x01;
            into[3] = 0x30;
            into[4] = data_len as u8;
            self.data.encode(&mut into[5..(data_len + 5)])?;
            Ok(into)
        }
    }
}

struct SetRequest;
impl PacketType for SetRequest { const ID: u8 = 0x41; }

struct SetRequestData {
    power: Option<Power>,
    mode: Option<Mode>,
    temp: Option<Temperature>,
    fan: Option<Fan>,
    vane: Option<Vane>,
    widevane: Option<WideVane>,
}

// 16 bytes:
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
impl PacketData<SetRequest> for SetRequestData {
    fn length(&self) -> usize { 0x10 }
    fn decode(from: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(from,
            tag!(&[0x01]) >>
            flags: bits!(do_parse!(
                take_bits!(u8, 3) >>
                vane: take_bits!(u8, 1) >>
                fan: take_bits!(u8, 1) >>
                temp: take_bits!(u8, 1) >>
                mode: take_bits!(u8, 1) >>
                power: take_bits!(u8, 1) >>
                take_bits!(u8, 7) >>
                widevane: take_bits!(u8, 1) >>
                ((power, mode, temp, fan, vane, widevane))
            )) >>
            // TODO parse the actual fields into Options
            (SetRequestData {
                power: None,
                mode: None,
                temp: None,
                fan: None,
                vane: None,
                widevane: None,
            })
        )
    }
}

impl SetRequestData {
    fn encode_flags<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if into.len() != 2 { return Err(EncodingError); }

        into[0] = 0x00u8 |
            (match self.power { Some(Power::Unknown) => 0, Some(_) => 0b00000001, _ => 0 }) |
            (match self.mode  { Some(Mode::Unknown)  => 0, Some(_) => 0b00000010, _ => 0 }) |
            (match self.temp  {                            Some(_) => 0b00000100, _ => 0 }) |
            (match self.fan   { Some(Fan::Unknown)   => 0, Some(_) => 0b00001000, _ => 0 }) |
            (match self.vane  { Some(Vane::Unknown)  => 0, Some(_) => 0b00010000, _ => 0 });
        into[1] = 0x00u8 |
            (match self.widevane { Some(WideVane::Unknown) => 0, Some(_) => 0b00000001, _ => 0 });
        Ok(into)
    }
}

impl Encodable for SetRequestData {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if into.len() != self.length() {
            Err(EncodingError)
        } else {
            into[0] = 0x01;
            self.encode_flags(&mut into[1..3])?;
            self.power.encode(&mut into[3..4])?;
            self.mode.encode(&mut into[4..5])?;
            into[5] = match self.temp { Some(ref temp) => temp.celsius_tenths().encode_as_setpoint_mapped(), None => 0x00 };
            self.fan.encode(&mut into[6..7])?;
            self.vane.encode(&mut into[7..8])?;
            for i in  &mut into[8..13] { *i = 0 }
            self.widevane.encode(&mut into [13..14])?;
            into[14] = match self.temp { Some(ref temp) => temp.celsius_tenths().encode_as_half_deg_plus_offset(), None => 0x00 };
            into[15] = 0;
            Ok(into)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct GetInfoRequest;
impl PacketType for GetInfoRequest { const ID: u8 = 0x42; }

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum InfoType {
    Settings     = 0x02,
    RoomTemp     = 0x03,
    Type4        = 0x04,
    Timers       = 0x05,
    Status       = 0x06,
    MaybeStandby = 0x09,
    Unknown      = 0xff,
}

impl InfoType {
    fn encode(&self) -> u8 {
        self.clone() as u8
    }
}

impl From<u8> for InfoType {
    fn from(byte: u8) -> Self {
        match byte {
            0x02 => InfoType::Settings,
            0x03 => InfoType::RoomTemp,
            0x04 => InfoType::Type4,
            0x05 => InfoType::Timers,
            0x06 => InfoType::Status,
            0x09 => InfoType::MaybeStandby,
            _ => InfoType::Unknown,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct GetInfoRequestData(InfoType);
impl PacketData<GetInfoRequest> for GetInfoRequestData {
    fn length(&self) -> usize { 0x10 }
    fn decode(from: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(from,
            info_type: map!(be_u8, InfoType::from) >>
            (GetInfoRequestData(info_type))
        )
    }
}

impl Encodable for GetInfoRequestData {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if into.len() != self.length() {
            Err(EncodingError)
        } else {
            into[0] = self.0 as u8;
            for i in &mut into[1..16] { *i = 0 }
            Ok(into)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ConnectRequest {}
impl PacketType for ConnectRequest { const ID: u8 = 0x5a; }

#[derive(Debug, Eq, PartialEq)]
enum SetResponse {}
impl PacketType for SetResponse { const ID: u8 = 0x61; }

#[derive(Debug, Eq, PartialEq)]
struct SetResponseData;
impl SetResponseData {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input, take!(16) >> (Self))
    }
}

impl PacketData<SetResponse> for SetResponseData {
    fn length(&self) -> usize { 0x10 }
    fn decode(from: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(from,
            take!(16) >>
            (SetResponseData)
        )
    }
}

impl Encodable for SetResponseData {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        Ok(into)
    }
}

enum GetInfoResponse {}
impl PacketType for GetInfoResponse { const ID: u8 = 0x62; }

enum ConnectResponse {}
impl PacketType for ConnectResponse { const ID: u8 = 0x7a; }

fn parse_packet_type<T, D>(input: &[u8], d: fn(&[u8]) -> IResult<&[u8], D>) -> IResult<&[u8], Packet<T, D>> where T: PacketType, D: PacketData<T> {
    do_parse!(input,
        tag!(&[0xfc,
               T::ID,
               0x01,
               0x30]) >>
        length: be_u8 >>
        data: flat_map!(take!(length), d) >>
        _checksum: be_u8 >>
        (Packet::new(data))
    )
}

mod tests {
    use super::*;

    #[test]
    fn get_info_request_test() {
        let mut buf: [u8; 22] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let packet = Packet::new(GetInfoRequestData(InfoType::Settings));
        assert_eq!(packet.encode(&mut buf),
                   Ok(&[0xfc, 0x42, 0x01, 0x30, 0x10,
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00,
                        ][0..22]))
    }

    #[test]
    fn set_request_test() {
        let mut buf: [u8; 22] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let packet = Packet::new(SetRequestData {
            power: Some(Power::On),
            mode: Some(Mode::Auto),
            fan: Some(Fan::Auto),
            vane: Some(Vane::Swing),
            widevane: Some(WideVane::LL),
            temp: Some(Temperature::HalfDegreesCPlusOffset { value: TenthDegreesC(210).encode_as_half_deg_plus_offset() }),
        });
        let result = packet.encode(&mut buf);
        assert_eq!(result,
                   Ok(&[0xfc, 0x41, 0x01, 0x30, 0x10,
                        0x01, 0x1f, 0x1,
                        0x01, 0x08, 0x0a, 0x00, 0x07,
                        0x00, 0x00, 0x00, 0x00, 0x00,
                        0x01,
                        0xaa,
                        0x00,
                        0x00,
                   ][0..22])
        );
    }

    #[test]
    fn packet_type_parser_test() {
        let buf: &[u8; 22] = &[0xfc, 0x61, 0x01, 0x30, 0x10,
                               0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07,
                               0x00, 0x00, 0x03, 0x94, 0x00, 0x00, 0x00, 0x00,
                               0x00];
        assert_eq!(Packet::parse(buf), Ok(Packet::new(SetResponseData)))
    }
}
