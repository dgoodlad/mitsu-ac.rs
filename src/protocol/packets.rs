use nom::*;
use super::types::{Power, Mode, Temperature, Fan, Vane, WideVane, ISee, TenthDegreesC};
use super::encoding::*;
use core::marker::PhantomData;

trait PacketType {
    const ID: u8;
}

trait PacketData<T: PacketType> : Encodable + Sized {
    const LENGTH: usize = 0x10;
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
        let data_len = D::LENGTH;
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
            // Checksum
            into[(data_len + 5)] = 0xfc - (into[0..(data_len + 5)].iter().fold(0u32, |acc,b| acc + *b as u32) as u8);
            Ok(into)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SetRequest;
impl PacketType for SetRequest { const ID: u8 = 0x41; }

#[derive(Debug, PartialEq, Eq)]
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
            power: cond!(flags.0 == 1, map!(be_u8, Power::from)) >>
            mode: cond!(flags.1 == 1, map!(be_u8, Mode::from)) >>
            _temp_mapped: cond!(flags.2 == 1, map!(be_u8, |b| Temperature::SetpointMapped { value: b }))>>
            fan: cond!(flags.3 == 1, map!(be_u8, Fan::from)) >>
            vane: cond!(flags.4 == 1, map!(be_u8, Vane::from)) >>
            take!(5) >>
            widevane: cond!(flags.5 == 1, map!(be_u8, WideVane::from)) >>
            temp: cond!(flags.2 == 1, map!(be_u8, |b| Temperature::HalfDegreesCPlusOffset { value: b })) >>
            take!(1) >>
            (SetRequestData {
                power,
                mode,
                temp,
                fan,
                vane,
                widevane,
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
        if into.len() != Self::LENGTH {
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
    fn decode(from: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(from,
            info_type: map!(be_u8, InfoType::from) >>
            (GetInfoRequestData(info_type))
        )
    }
}

impl Encodable for GetInfoRequestData {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if into.len() != Self::LENGTH {
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

struct ConnectRequestData;

impl ConnectRequestData {
    // We have no idea what these magic values mean or if we can use anything
    // else, but they seem to do the trick...
    const BYTE1: u8 = 0xca;
    const BYTE2: u8 = 0x01;
}

impl PacketData<ConnectRequest> for ConnectRequestData {
    const LENGTH: usize = 0x02;

    fn decode(from: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(from,
            tag!(&[Self::BYTE1, Self::BYTE2]) >>
            (ConnectRequestData)
        )
    }
}

impl Encodable for ConnectRequestData {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if into.len() != Self::LENGTH {
            Err(EncodingError)
        } else {
            into[0] = Self::BYTE1;
            into[1] = Self::BYTE2;
            Ok(into)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum SetResponse {}
impl PacketType for SetResponse { const ID: u8 = 0x61; }

#[derive(Debug, Eq, PartialEq)]
struct SetResponseData;

impl PacketData<SetResponse> for SetResponseData {
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

#[derive(Debug, PartialEq, Eq)]
enum GetInfoResponse {}
impl PacketType for GetInfoResponse { const ID: u8 = 0x62; }

#[derive(Debug, PartialEq, Eq)]
enum GetInfoResponseData {
    Settings {
        power: Power,
        mode: Mode,
        setpoint: Temperature,
        fan: Fan,
        vane: Vane,
        widevane: WideVane,
        isee: ISee,
    },
    RoomTemperature { temperature: Temperature },
    Status { compressor_frequency: u8, operating: u8 },
    Unknown,
}

impl GetInfoResponseData {
    fn decode_settings(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
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
                (s, Temperature::HalfDegreesCPlusOffset { value: 0 }) => s,
                (_, s) => s,
            }) >>
            take!(4) >>
            (GetInfoResponseData::Settings {
                power, mode, fan, vane, widevane, setpoint, isee
            })
        )
    }

    fn decode_room_temp(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
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
        )
    }

    fn decode_timer(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            tag!(&[InfoType::Timers as u8]) >>
            (GetInfoResponseData::Unknown)
        )
    }

    fn decode_status(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            tag!(&[InfoType::Status as u8]) >>
            take!(2) >>
            compressor_frequency: be_u8 >>
            operating: be_u8 >>
            (GetInfoResponseData::Status { compressor_frequency, operating })
        )
    }

    fn decode_unknown(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input, (GetInfoResponseData::Unknown))
    }
}

impl PacketData<GetInfoResponse> for GetInfoResponseData {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        alt!(input,
             Self::decode_settings |
             Self::decode_room_temp |
             Self::decode_timer |
             Self::decode_status |
             Self::decode_unknown
        )
    }
}

impl Encodable for GetInfoResponseData {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        // TODO
        Ok(into)
    }
}

enum ConnectResponse {}
impl PacketType for ConnectResponse { const ID: u8 = 0x7a; }

named!(checksum<u8>, do_parse!(
    length: peek!(do_parse!(tag!(&[0xfc]) >> take!(1) >> tag!(&[0x01, 0x30]) >> len: map!(be_u8, |b| b + 5) >> (len as usize))) >>
    calculated: map!(fold_many_m_n!(length, length, be_u8, 0u32, |acc, b| acc + b as u32), |i| 0xfc - (i as u8)) >>
    received: verify!(be_u8, |b| b == calculated) >>
    (received)
));

fn parse_packet_type<T, D>(input: &[u8], d: fn(&[u8]) -> IResult<&[u8], D>) -> IResult<&[u8], Packet<T, D>> where T: PacketType, D: PacketData<T> {
    do_parse!(input,
        peek!(checksum) >>
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

    const EMPTY: &[u8] = &[];

    #[test]
    fn connect_request_test() {
        let mut buf: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let packet = Packet::new(ConnectRequestData);
        assert_eq!(packet.encode(&mut buf),
                   Ok(&[0xfc, 0x5a, 0x01, 0x30, 0x02,
                        0xca, 0x01,
                        0xa8,
                   ][0..8])
        )
    }

    #[test]
    fn get_info_request_test() {
        let mut buf: [u8; 22] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let packet = Packet::new(GetInfoRequestData(InfoType::Settings));
        assert_eq!(packet.encode(&mut buf),
                   Ok(&[0xfc, 0x42, 0x01, 0x30, 0x10,
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x7b,
                        ][0..22]));
        assert_eq!(Ok(packet), Packet::parse(&buf))
    }

    #[test]
    fn set_request_flags_test() {
        let mut slice = [0x00, 0x00];
        let mut data = SetRequestData {
            power: Some(Power::On),
            mode: Some(Mode::Auto),
            fan: Some(Fan::Auto),
            vane: Some(Vane::Swing),
            widevane: Some(WideVane::LL),
            temp: Some(Temperature::HalfDegreesCPlusOffset { value: TenthDegreesC(210).encode_as_half_deg_plus_offset() }),
        };

        data.encode_flags(&mut slice).unwrap();
        assert_eq!(0b00011111, slice[0]);
        assert_eq!(0b00000001, slice[1]);

        data.widevane = None;
        data.encode_flags(&mut slice).unwrap();
        assert_eq!(0b00011111, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        data.power = None;
        data.encode_flags(&mut slice).unwrap();
        assert_eq!(0b00011110, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        data.mode = None;
        data.encode_flags(&mut slice).unwrap();
        assert_eq!(0b00011100, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        data.fan = None;
        data.encode_flags(&mut slice).unwrap();
        assert_eq!(0b00010100, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        data.vane = None;
        data.encode_flags(&mut slice).unwrap();
        assert_eq!(0b00000100, slice[0]);
        assert_eq!(0b00000000, slice[1]);

        data.temp = None;
        data.encode_flags(&mut slice).unwrap();
        assert_eq!(0b00000000, slice[0]);
        assert_eq!(0b00000000, slice[1]);
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
                        0x98,
                   ][0..22])
        );
        assert_eq!(Ok(packet), Packet::parse(&buf))
    }

    #[test]
    fn packet_type_parser_test() {
        let buf: &[u8; 22] = &[0xfc, 0x61, 0x01, 0x30, 0x10,
                               0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07,
                               0x00, 0x00, 0x03, 0x94, 0x00, 0x00, 0x00, 0x00,
                               0xad];
        assert_eq!(Packet::parse(buf), Ok(Packet::new(SetResponseData)))
    }

    #[test]
    fn decode_info_settings_test() {
        assert_eq!(GetInfoResponseData::decode_settings(&[0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07, 0x00, 0x00, 0x03, 0x94, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponseData::Settings {
                power: Power::On,
                mode: Mode::Heat,
                setpoint: Temperature::HalfDegreesCPlusOffset { value: 0x94 },
                fan: Fan::Auto,
                vane: Vane::Swing,
                widevane: WideVane::Center,
                isee: ISee::Off,

            }))
        );

        assert_eq!(GetInfoResponseData::decode_settings(&[0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07, 0x00, 0x00, 0x03, 0xa0, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponseData::Settings {
                power: Power::On,
                mode: Mode::Heat,
                setpoint: Temperature::HalfDegreesCPlusOffset { value: 0xa0 },
                fan: Fan::Auto,
                vane: Vane::Swing,
                widevane: WideVane::Center,
                isee: ISee::Off,
            }))
        );
    }

    #[test]
    fn decode_info_temperature_test() {
        // When the half-degrees value is present in byte 6, use it
        assert_eq!(GetInfoResponseData::decode_room_temp(&[0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponseData::RoomTemperature {
                temperature: Temperature::HalfDegreesCPlusOffset{ value: 0xaa },
            }))
        );
        // When the half-degrees value is missing, test that we fall back to the
        // lower-res "mapped" value from byte 3
        assert_eq!(GetInfoResponseData::decode_room_temp(&[0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponseData::RoomTemperature {
                temperature: Temperature::RoomTempMapped{ value: 0x0b },
            }))
        );
    }
}
