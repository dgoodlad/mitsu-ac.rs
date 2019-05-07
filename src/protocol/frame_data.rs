use nom::number::streaming::be_u8;
use nom::{do_parse, IResult};

use super::frame::{DataType, Frame};
use super::types::{Power, Mode, Temperature, Fan, Vane, WideVane, ISee};

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
    pub fn parse(frame: Frame) -> IResult<&[u8], Self> {
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
            power: cond!(flags.0 == 1, map!(be_u8, Power::from)) >>
            mode: cond!(flags.1 == 1, map!(be_u8, Mode::from)) >>
            _temp_mapped: cond!(flags.2 == 1, map!(be_u8, |b| Temperature::SetpointMapped { value: b }))>>
            fan: cond!(flags.3 == 1, map!(be_u8, Fan::from)) >>
            vane: cond!(flags.4 == 1, map!(be_u8, Vane::from)) >>
            take!(5) >>
            widevane: cond!(flags.5 == 1, map!(be_u8, WideVane::from)) >>
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
            (GetInfoRequest(info_type))
        )
    }
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
pub struct ConnectResponse;

impl Parseable for ConnectResponse {
    fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        Ok((data, Self))
    }
}

mod tests {
    use super::*;
    use super::super::types::TenthDegreesC;

    const EMPTY: &[u8] = &[];

    #[test]
    fn parse_connect_request_test() {
        let data: &[u8] = &[0xca, 0x01];
        let result = FrameData::parse_data_type(FrameData::ConnectRequest, data);
        assert_eq!(Ok((EMPTY, FrameData::ConnectRequest(ConnectRequest))), result);
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
