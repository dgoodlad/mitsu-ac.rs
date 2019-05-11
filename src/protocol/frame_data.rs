use nom::number::streaming::be_u8;
use nom::{do_parse, IResult};

use super::frame::{DataType, Frame};
use super::types::{Power, Mode, Temperature, Fan, Vane, WideVane, ISee};

use super::encoding::*;

/// Decoded `Frame` data. Each variant contains a concrete type useful for
/// representing the `Frame`'s `data_type`.
#[derive(Debug, Eq, PartialEq)]
pub enum FrameData {
    SetRequest(SetRequest),
    GetInfoRequest(GetInfoRequest),
    ConnectRequest(ConnectRequest),

    SetResponse(SetResponse),
    GetInfoResponse(GetInfoResponse),
    ConnectResponse(ConnectResponse),

    Unknown,
}

impl FrameData {
    /// Parses out the data from a given `Frame`
    ///
    /// ```
    /// use mitsu_ac::protocol::{Frame, DataType, FrameData, ConnectResponse};
    ///
    /// let (_, frame) = Frame::parse(&[0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0x54]).unwrap();
    /// let (_, data) = FrameData::parse(frame).unwrap();
    ///
    /// assert_eq!(data, FrameData::ConnectResponse(ConnectResponse::new(0)));
    ///
    /// match data {
    ///     FrameData::ConnectResponse(r) => println!("Received a connect response: {:?}", r),
    ///     _ => panic!("Unexpected frame"),
    /// }
    /// ```
    pub fn parse(frame: Frame<&[u8]>) -> IResult<&[u8], Self> {
        match frame.data_type {
            DataType::SetRequest => Self::parse_data_type(FrameData::SetRequest, frame.data),
            DataType::GetInfoRequest => Self::parse_data_type(FrameData::GetInfoRequest, frame.data),
            DataType::ConnectRequest => Self::parse_data_type(FrameData::ConnectRequest, frame.data),

            DataType::SetResponse => Self::parse_data_type(FrameData::SetResponse, frame.data),
            DataType::GetInfoResponse => Self::parse_data_type(FrameData::GetInfoResponse, frame.data),
            DataType::ConnectResponse => Self::parse_data_type(FrameData::ConnectResponse, frame.data),

            DataType::Unknown => Ok((&[], FrameData::Unknown)),
        }
    }

    fn parse_data_type<T: Parseable>(variant: fn (T) -> Self, data: &[u8]) -> IResult<&[u8], Self> {
        let result: IResult<&[u8], T> = T::parse(data);

        match result {
            Ok((remaining_bytes, t)) => Ok((remaining_bytes, variant(t))),
            Err(e) => Err(e),
        }
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodingError> {
        match self {
            FrameData::SetRequest(data) => data.encode(buffer),
            FrameData::GetInfoRequest(data) => data.encode(buffer),
            FrameData::ConnectRequest(data) => data.encode(buffer),

            FrameData::SetResponse(_)
            | FrameData::GetInfoResponse(_)
            | FrameData::ConnectResponse(_) =>
                Err(EncodingError::NotImplemented),

            FrameData::Unknown => Err(EncodingError::UnknownDataType),
        }
    }
}

trait Parseable : Sized {
    fn parse(data: &[u8]) -> IResult<&[u8], Self>;
}

/// Sets one or more of the device's settings:
///
/// * `power`
/// * `mode`
/// * `setpoint`
/// * `fan`
/// * `vane`
/// * `widevane`
///
/// Each field is an `Option`; if set to `None`, the device's current setting
/// will be left unchanged.
///
/// # Packet structure
///
/// | Byte | Description |
/// |------|---|
/// |    0 | `0x01` - an unknown constant |
/// |    1 | Flag byte 0, set bits indicate presence of power/mode/temp/fan/vane values |
/// |    2 | Flag byte 1, set bits indicate presence of widevane value |
/// |    3 | Power |
/// |    4 | Mode |
/// |    5 | Temperature (as 'setpoint mapped' value) |
/// |    6 | Fan |
/// |    7 | Vane |
/// |    8 | Unused |
/// |    9 | Unused |
/// |   10 | Unused |
/// |   11 | Unused |
/// |   12 | Unused |
/// |   13 | Wide Vane |
/// |   14 | Temperature (as half-degrees c + offset) |
/// |   15 | Unused |
#[derive(Debug, PartialEq, Eq)]
pub struct SetRequest {
    pub power: Option<Power>,
    pub mode: Option<Mode>,
    pub temp: Option<Temperature>,
    pub fan: Option<Fan>,
    pub vane: Option<Vane>,
    pub widevane: Option<WideVane>,
}

impl Parseable for SetRequest {
    fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(data,
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
            power: cond!(flags.0 == 1, map_opt!(be_u8, Power::from_repr)) >>
            mode: cond!(flags.1 == 1, map_opt!(be_u8, Mode::from_repr)) >>
            _temp_mapped: cond!(flags.2 == 1, map!(be_u8, |b| Temperature::SetpointMapped { value: b }))>>
            fan: cond!(flags.3 == 1, map_opt!(be_u8, Fan::from_repr)) >>
            vane: cond!(flags.4 == 1, map_opt!(be_u8, Vane::from_repr)) >>
            take!(5) >>
            widevane: cond!(flags.5 == 1, map_opt!(be_u8, WideVane::from_repr)) >>
            temp: cond!(flags.2 == 1, map!(be_u8, |b| Temperature::HalfDegreesCPlusOffset { value: b })) >>
            take!(1) >>
            (SetRequest {
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

impl FixedSizeEncoding for SetRequest {
    const LENGTH: usize = 0x10;
}

impl Encodable for SetRequest {
    fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<usize, EncodingError> {
        if buf.len() != Self::LENGTH {
            Err(EncodingError::BufferTooSmall)
        } else {
            buf[0] = 0x01;
            self.encode_flags(&mut buf[1..3])?;
            self.power.encode(&mut buf[3..4])?;
            self.mode.encode(&mut buf[4..5])?;
            buf[5] = match self.temp { Some(ref temp) => temp.celsius_tenths().encode_as_setpoint_mapped(), None => 0x00 };
            self.fan.encode(&mut buf[6..7])?;
            self.vane.encode(&mut buf[7..8])?;
            for i in  &mut buf[8..13] { *i = 0 }
            self.widevane.encode(&mut buf [13..14])?;
            buf[14] = match self.temp { Some(ref temp) => temp.celsius_tenths().encode_as_half_deg_plus_offset(), None => 0x00 };
            buf[15] = 0;
            Ok(Self::LENGTH)
        }
    }
}

impl SetRequest {
    fn encode_flags<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if into.len() != 2 { return Err(EncodingError::BufferTooSmall); }

        into[0] = 0x00u8 |
            (match self.power { Some(_) => 0b00000001, _ => 0 }) |
            (match self.mode  { Some(_) => 0b00000010, _ => 0 }) |
            (match self.temp  { Some(_) => 0b00000100, _ => 0 }) |
            (match self.fan   { Some(_) => 0b00001000, _ => 0 }) |
            (match self.vane  { Some(_) => 0b00010000, _ => 0 });
        into[1] = 0x00u8 |
            (match self.widevane { Some(_) => 0b00000001, _ => 0 });
        Ok(into)
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InfoType {
    Settings     = 0x02,
    RoomTemp     = 0x03,
    Type4        = 0x04,
    Timers       = 0x05,
    Status       = 0x06,
    MaybeStandby = 0x09,
    Unknown      = 0xff,
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

/// Requests the given InfoType data from the device
#[derive(Debug, Eq, PartialEq)]
pub struct GetInfoRequest(InfoType);

impl Parseable for GetInfoRequest {
    fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(data,
            info_type: map!(be_u8, InfoType::from) >>
            take!(15) >>
            (GetInfoRequest(info_type))
        )
    }
}

impl Encodable for GetInfoRequest {
    fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodingError> {
        if buf.len() != Self::LENGTH {
            Err(EncodingError::BufferTooSmall)
        } else {
            buf[0] = self.0 as u8;
            for i in &mut buf[1..16] { *i = 0 }
            Ok(Self::LENGTH)
        }
    }
}

impl FixedSizeEncoding for GetInfoRequest {
    const LENGTH: usize = 0x10;
}

/// The preamble that tells the device we're connected and want to talk
#[derive(Debug, Eq, PartialEq)]
pub struct ConnectRequest;

impl ConnectRequest {
    // We have no idea what these magic values mean or if we can use anything
    // else, but they seem to do the trick...
    const BYTE1: u8 = 0xca;
    const BYTE2: u8 = 0x01;
}

impl Parseable for ConnectRequest {
    fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(data,
            tag!(&[Self::BYTE1, Self::BYTE2]) >>
            (ConnectRequest)
        )
    }
}

impl Encodable for ConnectRequest {
    fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodingError> {
        if buf.len() != Self::LENGTH {
            Err(EncodingError::BufferTooSmall)
        } else {
            buf[0] = Self::BYTE1;
            buf[1] = Self::BYTE2;
            Ok(Self::LENGTH)
        }
    }
}

impl FixedSizeEncoding for ConnectRequest {
    const LENGTH: usize = 2;
}

/// Response to the SetRequest
///
/// The data is opaque, and not yet understood.
#[derive(Debug, Eq, PartialEq)]
pub struct SetResponse;

impl Parseable for SetResponse {
    fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(data,
            take!(16) >>
            (SetResponse)
        )
    }
}

/// Response to a GetInfoRequest
///
/// Includes the information requested in the original request. We don't
/// currently parse all of the known `InfoType` responses, and there are also
/// unknown `InfoType`s. For those, we return a `GetInfoResponse::Unknown`.
#[derive(Debug, PartialEq, Eq)]
pub enum GetInfoResponse {
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


impl GetInfoResponse {
    fn decode_settings(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            tag!(&[InfoType::Settings as u8]) >>
            take!(2) >>
            power: map_opt!(be_u8, Power::from_repr) >>
            mode_and_isee: bits!(tuple!(
                take_bits!(u8, 4),
                map_opt!(take_bits!(u8, 1), ISee::from_repr),
                map_opt!(take_bits!(u8, 3), Mode::from_repr))) >>
            isee: value!(mode_and_isee.1) >>
            mode: value!(mode_and_isee.2) >>
            setpoint_mapped: map!(be_u8, |b| Temperature::SetpointMapped { value: b })>>
            fan: map_opt!(be_u8, Fan::from_repr) >>
            vane: map_opt!(be_u8, Vane::from_repr) >>
            take!(2) >>
            widevane: map_opt!(be_u8, WideVane::from_repr) >>
            setpoint_half_deg: map!(be_u8, |b| Temperature::HalfDegreesCPlusOffset { value: b }) >>
            setpoint: value!(match (setpoint_mapped, setpoint_half_deg) {
                (s, Temperature::HalfDegreesCPlusOffset { value: 0 }) => s,
                (_, s) => s,
            }) >>
            take!(4) >>
            (GetInfoResponse::Settings {
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
            (GetInfoResponse::RoomTemperature { temperature })
        )
    }

    fn decode_timer(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            tag!(&[InfoType::Timers as u8]) >>
            (GetInfoResponse::Unknown)
        )
    }

    fn decode_status(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            tag!(&[InfoType::Status as u8]) >>
            take!(2) >>
            compressor_frequency: be_u8 >>
            operating: be_u8 >>
            (GetInfoResponse::Status { compressor_frequency, operating })
        )
    }

    fn decode_unknown(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input, (GetInfoResponse::Unknown))
    }
}

impl Parseable for GetInfoResponse {
    fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        alt!(data,
             Self::decode_settings |
             Self::decode_room_temp |
             Self::decode_timer |
             Self::decode_status |
             Self::decode_unknown
        )
    }
}

/// Response to our `ConnectRequest`
///
/// Once we see this response, we know the device is ready to talk.
#[derive(Debug, Eq, PartialEq)]
pub struct ConnectResponse(u8);

impl ConnectResponse {
    pub fn new(b: u8) -> Self { ConnectResponse(b) }
}

impl Parseable for ConnectResponse {
    fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(data,
            b: be_u8 >>
            (Self(b))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::TenthDegreesC;

    const EMPTY: &[u8] = &[];

    #[test]
    fn parse_get_info_request_test() {
        let data: &[u8] = &[
            0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let result = FrameData::parse_data_type(FrameData::GetInfoRequest, data);
        assert_eq!(Ok((EMPTY, FrameData::GetInfoRequest(GetInfoRequest(InfoType::Settings)))), result);
    }

    #[test]
    fn encode_get_info_request_test() {
        let mut buf: [u8; 16] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let expected: [u8; 16] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = FrameData::GetInfoRequest(GetInfoRequest(InfoType::Settings)).encode(&mut buf);
        assert_eq!(Ok(16), result);
        assert_eq!(expected, buf);
    }

    #[test]
    fn parse_set_request_test() {
        let data: &[u8] = &[
            0x01, 0x1f, 0x1,
            0x01, 0x08, 0x0a, 0x00, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x01,
            0xaa,
            0x00,
        ];
        let result = FrameData::parse_data_type(FrameData::SetRequest, data);
        assert_eq!(Ok((EMPTY, FrameData::SetRequest(SetRequest {
            power: Some(Power::On),
            mode: Some(Mode::Auto),
            fan: Some(Fan::Auto),
            vane: Some(Vane::Swing),
            widevane: Some(WideVane::LL),
            temp: Some(Temperature::HalfDegreesCPlusOffset { value: TenthDegreesC(210).encode_as_half_deg_plus_offset() }),
        }))), result);
    }

    #[test]
    fn encode_set_request_flags_test() {
        let mut buf: [u8; 2] = [0x00, 0x00];
        let mut data = SetRequest {
            power: Some(Power::On),
            mode: Some(Mode::Auto),
            fan: Some(Fan::Auto),
            vane: Some(Vane::Swing),
            widevane: Some(WideVane::LL),
            temp: Some(Temperature::HalfDegreesCPlusOffset { value: TenthDegreesC(210).encode_as_half_deg_plus_offset() }),
        };

        data.encode_flags(&mut buf).unwrap();
        assert_eq!(0b00011111, buf[0]);
        assert_eq!(0b00000001, buf[1]);

        data.widevane = None;
        data.encode_flags(&mut buf).unwrap();
        assert_eq!(0b00011111, buf[0]);
        assert_eq!(0b00000000, buf[1]);

        data.power = None;
        data.encode_flags(&mut buf).unwrap();
        assert_eq!(0b00011110, buf[0]);
        assert_eq!(0b00000000, buf[1]);

        data.mode = None;
        data.encode_flags(&mut buf).unwrap();
        assert_eq!(0b00011100, buf[0]);
        assert_eq!(0b00000000, buf[1]);

        data.fan = None;
        data.encode_flags(&mut buf).unwrap();
        assert_eq!(0b00010100, buf[0]);
        assert_eq!(0b00000000, buf[1]);

        data.vane = None;
        data.encode_flags(&mut buf).unwrap();
        assert_eq!(0b00000100, buf[0]);
        assert_eq!(0b00000000, buf[1]);

        data.temp = None;
        data.encode_flags(&mut buf).unwrap();
        assert_eq!(0b00000000, buf[0]);
        assert_eq!(0b00000000, buf[1]);
    }

    #[test]
    fn encode_set_request_test() {
        let mut buf: [u8; 16] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let expected: [u8; 16] = [
            0x01, 0x1f, 0x01,
            0x01, 0x08, 0x0a, 0x00, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x01,
            0xaa,
            0x00
        ];
        let result = SetRequest {
            power: Some(Power::On),
            mode: Some(Mode::Auto),
            fan: Some(Fan::Auto),
            vane: Some(Vane::Swing),
            widevane: Some(WideVane::LL),
            temp: Some(Temperature::HalfDegreesCPlusOffset { value: TenthDegreesC(210).encode_as_half_deg_plus_offset() }),
        }.encode(&mut buf);
        assert_eq!(Ok(16), result);
        assert_eq!(expected, buf);
    }

    #[test]
    fn parse_connect_request_test() {
        let data: &[u8] = &[0xca, 0x01];
        let result = FrameData::parse_data_type(FrameData::ConnectRequest, data);
        assert_eq!(Ok((EMPTY, FrameData::ConnectRequest(ConnectRequest))), result);
    }

    #[test]
    fn encode_connect_request_test() {
        let mut buf: [u8; 2] = [0x00, 0x00];
        let expected: [u8; 2] = [0xca, 0x01];
        let result = ConnectRequest.encode(&mut buf);
        assert_eq!(Ok(2), result);
        assert_eq!(expected, buf);
    }

    #[test]
    fn parse_get_info_response_settings_test() {
        let data: &[u8] = &[
            0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07,
            0x00, 0x00, 0x03, 0x94, 0x00, 0x00, 0x00, 0x00  ,
        ];

        let result = GetInfoResponse::decode_settings(data);

        assert_eq!(Ok((EMPTY, GetInfoResponse::Settings {
            power: Power::On,
            mode: Mode::Heat,
            setpoint: Temperature::HalfDegreesCPlusOffset { value: 0x94 },
            fan: Fan::Auto,
            vane: Vane::Swing,
            widevane: WideVane::Center,
            isee: ISee::Off,
        })), result);
    }

    #[test]
    fn parse_get_info_response_room_temp_test() {
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0xaa, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = GetInfoResponse::decode_room_temp(data);

        assert_eq!(Ok((EMPTY, GetInfoResponse::RoomTemperature {
            temperature: Temperature::HalfDegreesCPlusOffset{ value: 0xaa  },
        })), result);

        let data2: &[u8] = &[
            0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let result2 = GetInfoResponse::decode_room_temp(data2);

        assert_eq!(Ok((EMPTY, GetInfoResponse::RoomTemperature {
            temperature: Temperature::RoomTempMapped{ value: 0x0b },
        })), result2);
    }
}
