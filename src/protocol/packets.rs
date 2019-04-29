use nom::*;
use super::types::{Power, Mode, Temperature, Fan, Vane, WideVane, ISee};
use super::encoding::*;

#[derive(Debug, Eq, PartialEq)]
struct DecodingError;

#[repr(u8)]
#[derive(Debug, Eq, PartialEq)]
enum PacketTypeId {
    SetRequest      = 0x41,
    GetInfoRequest  = 0x42,
    ConnectRequest  = 0x5a,

    SetResponse     = 0x61,
    GetInfoResponse = 0x62,
    ConnectResponse = 0x7a,

    Unknown         = 0xff,
}

impl From<u8> for PacketTypeId {
    fn from(byte: u8) -> Self {
        match byte {
            0x41 => PacketTypeId::SetRequest,
            0x42 => PacketTypeId::GetInfoRequest,
            0x5a => PacketTypeId::ConnectRequest,

            0x61 => PacketTypeId::SetResponse,
            0x62 => PacketTypeId::GetInfoResponse,
            0x7a => PacketTypeId::ConnectResponse,

            _ => PacketTypeId::Unknown,
        }
    }
}

named!(checksum<u8>, do_parse!(
    length: peek!(do_parse!(tag!(&[0xfc]) >> take!(1) >> tag!(&[0x01, 0x30]) >> len: map!(be_u8, |b| b + 5) >> (len as usize))) >>
    calculated: map!(fold_many_m_n!(length, length, be_u8, 0u32, |acc, b| acc + b as u32), |i| 0xfc - (i as u8)) >>
    received: verify!(be_u8, |b| b == calculated) >>
    (received)
));

enum ChecksummedPacket<'a> {
    Matched {
        checksum: u8,
        packet_type_id: PacketTypeId,
        raw_bytes: &'a [u8],
    },
    Invalid {
        calculated_checksum: u8,
        received_checksum: u8,
        packet_type_id: PacketTypeId,
        raw_bytes: &'a [u8],
    },
}

impl<'a> ChecksummedPacket<'a> {
    pub fn checksum(raw_bytes: &'a [u8]) -> Result<Self, DecodingError> {
        let result = do_parse!(raw_bytes,
            type_id_and_length: peek!(do_parse!(
                tag!(&[0xfc]) >>
                type_id: be_u8 >>
                tag!(&[0x01, 0x30]) >>
                len: map!(be_u8, |b| b + 5) >>
                ((type_id, len as usize))
            )) >>
            packet_type_id: value!(PacketTypeId::from(type_id_and_length.0)) >>
            length: value!(type_id_and_length.1) >>
            calculated_checksum: map!(fold_many_m_n!(length, length, be_u8, 0u32, |acc, b| acc + b as u32), |i| 0xfc - (i as u8)) >>
            received_checksum: be_u8 >>
            (Self::new(calculated_checksum, received_checksum, packet_type_id, raw_bytes))
        );

        match result {
            // TODO don't discard the remaining bytes
            Ok((_remaining_bytes, packet)) => Ok(packet),
            Err(_e) => Err(DecodingError),
        }
    }

    fn new(calculated_checksum: u8, received_checksum: u8, packet_type_id: PacketTypeId, raw_bytes: &'a [u8]) -> Self {
        if calculated_checksum == received_checksum {
            ChecksummedPacket::Matched { checksum: received_checksum, packet_type_id, raw_bytes }
        } else {
            ChecksummedPacket::Invalid { received_checksum, calculated_checksum, packet_type_id, raw_bytes }
        }
    }

    fn decode<T>(self) -> Result<T, DecodingError> where T: Packet {
        match self {
            ChecksummedPacket::Matched { checksum, packet_type_id, raw_bytes } => {
                // TODO define an error type to handle this "mismatched types" case
                // We're checking to make sure that the caller is trying to
                // parse this packet into the right kind of packet based on the type id
                if packet_type_id != T::TYPE { return Err(DecodingError) }

                let result = do_parse!(raw_bytes,
                    tag!(&[0xfc]) >>
                    tag!(&[T::TYPE as u8]) >>
                    tag!(&[0x01, 0x30]) >>
                    tag!(&[T::DATALEN as u8]) >>
                    packet: flat_map!(take!(T::DATALEN), T::decode_data) >>
                    tag!(&[checksum]) >>
                    (packet)
                );
                match result {
                    Ok((_, packet)) => Ok(packet),
                    Err(_e) => Err(DecodingError),
                }
            },

            ChecksummedPacket::Invalid {received_checksum: _, calculated_checksum: _, packet_type_id: _, raw_bytes: _} => Err(DecodingError),
        }
    }

    fn encode<T>(packet: &T, buf: &'a mut [u8]) -> Result<&'a [u8], EncodingError> where T: Packet {
        buf[0] = 0xfc;
        buf[1] = T::TYPE as u8;
        buf[2] = 0x01;
        buf[3] = 0x30;
        buf[4] = T::DATALEN as u8;
        packet.encode_into(&mut buf[5..(T::DATALEN + 5)])?;
        buf[T::DATALEN + 5] = 0xfc - (buf[0..(T::DATALEN + 5)].iter().fold(0u32, |acc,b| acc + *b as u32) as u8);

        Ok(buf)
    }
}

trait Packet: Sized {
    const TYPE: PacketTypeId;

    /// Length in bytes of the data associated with this type of packet
    ///
    /// *Note*: defaulted to 16 bytes but certain types may override it.
    const DATALEN: usize = 0x10;

    /// Decodes raw bytes
    fn decode_data(input: &[u8]) -> IResult<&[u8], Self>;

    /// Encodes the entire packet into a given buffer of raw bytes
    fn encode_into<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], EncodingError>;
}

#[derive(Debug, PartialEq, Eq)]
struct SetRequest {
    power: Option<Power>,
    mode: Option<Mode>,
    temp: Option<Temperature>,
    fan: Option<Fan>,
    vane: Option<Vane>,
    widevane: Option<WideVane>,
}

impl Packet for SetRequest {
    const TYPE: PacketTypeId = PacketTypeId::SetRequest;

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
    fn decode_data(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
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

    fn encode_into<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if buf.len() != Self::DATALEN {
            Err(EncodingError)
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
            Ok(buf)
        }
    }
}

impl SetRequest {
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

#[derive(Debug, Eq, PartialEq)]
struct GetInfoRequest(InfoType);

impl Packet for GetInfoRequest {
    const TYPE: PacketTypeId = PacketTypeId::GetInfoRequest;

    /// Decodes raw bytes
    fn decode_data(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            info_type: map!(be_u8, InfoType::from) >>
            (GetInfoRequest(info_type))
        )
    }

    /// Encodes the entire packet into a given buffer of raw bytes
    fn encode_into<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if buf.len() != Self::DATALEN {
            Err(EncodingError)
        } else {
            buf[0] = self.0 as u8;
            for i in &mut buf[1..16] { *i = 0 }
            Ok(buf)
        }
    }
}

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
struct ConnectRequest;

impl Packet for ConnectRequest {
    const TYPE: PacketTypeId = PacketTypeId::ConnectRequest;

    const DATALEN: usize = 0x02;

    /// Decodes raw bytes
    fn decode_data(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            tag!(&[Self::BYTE1, Self::BYTE2]) >>
            (ConnectRequest)
        )
    }

    /// Encodes the entire packet into a given buffer of raw bytes
    fn encode_into<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if buf.len() != Self::DATALEN {
            Err(EncodingError)
        } else {
            buf[0] = Self::BYTE1;
            buf[1] = Self::BYTE2;
            Ok(buf)
        }
    }
}

impl ConnectRequest {
    // We have no idea what these magic values mean or if we can use anything
    // else, but they seem to do the trick...
    const BYTE1: u8 = 0xca;
    const BYTE2: u8 = 0x01;
}

#[derive(Debug, Eq, PartialEq)]
struct SetResponse;
impl Packet for SetResponse {
    const TYPE: PacketTypeId = PacketTypeId::SetResponse;

    /// Decodes raw bytes
    fn decode_data(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            take!(16) >>
            (SetResponse)
        )
    }

    /// Encodes the entire packet into a given buffer of raw bytes
    fn encode_into<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        Ok(buf)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GetInfoResponse {
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

impl Packet for GetInfoResponse {
    const TYPE: PacketTypeId = PacketTypeId::GetInfoResponse;

    /// Decodes raw bytes
    fn decode_data(input: &[u8]) -> IResult<&[u8], Self> {
        alt!(input,
             Self::decode_settings |
             Self::decode_room_temp |
             Self::decode_timer |
             Self::decode_status |
             Self::decode_unknown
        )
    }

    /// Encodes the entire packet into a given buffer of raw bytes
    fn encode_into<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        Ok(buf) // TODO
    }
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

#[derive(Debug, Eq, PartialEq)]
struct ConnectResponse;

impl Packet for ConnectResponse {
    const TYPE: PacketTypeId = PacketTypeId::ConnectResponse;

    /// Decodes raw bytes
    fn decode_data(input: &[u8]) -> IResult<&[u8], Self> {
        do_parse!(input,
            (Self)
        )
    }

    /// Encodes the entire packet into a given buffer of raw bytes
    fn encode_into<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        Ok(buf) // TODO
    }

}

mod tests {
    use super::*;
    use super::super::types::TenthDegreesC;

    const EMPTY: &[u8] = &[];

    #[test]
    fn connect_request_test() {
        let mut buf: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let packet = ConnectRequest;
        assert_eq!(ChecksummedPacket::encode(&packet, &mut buf),
                   Ok(&[0xfc, 0x5a, 0x01, 0x30, 0x02,
                        0xca, 0x01,
                        0xa8,
                   ][0..8])
        )
    }

    #[test]
    fn get_info_request_test() {
        let mut buf: [u8; 22] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let packet = GetInfoRequest(InfoType::Settings);
        assert_eq!(ChecksummedPacket::encode(&packet, &mut buf),
                   Ok(&[0xfc, 0x42, 0x01, 0x30, 0x10,
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x7b,
                        ][0..22]));
        assert_eq!(Ok(packet), ChecksummedPacket::checksum(&buf).unwrap().decode())
    }

    #[test]
    fn set_request_flags_test() {
        let mut slice = [0x00, 0x00];
        let mut data = SetRequest {
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
        let packet = SetRequest {
            power: Some(Power::On),
            mode: Some(Mode::Auto),
            fan: Some(Fan::Auto),
            vane: Some(Vane::Swing),
            widevane: Some(WideVane::LL),
            temp: Some(Temperature::HalfDegreesCPlusOffset { value: TenthDegreesC(210).encode_as_half_deg_plus_offset() }),
        };
        let result = ChecksummedPacket::encode(&packet, &mut buf);
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
        assert_eq!(Ok(packet), ChecksummedPacket::checksum(&buf).unwrap().decode())
    }

    #[test]
    fn packet_type_parser_test() {
        let buf: &[u8; 22] = &[0xfc, 0x61, 0x01, 0x30, 0x10,
                               0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07,
                               0x00, 0x00, 0x03, 0x94, 0x00, 0x00, 0x00, 0x00,
                               0xad];
        assert_eq!(ChecksummedPacket::checksum(buf).unwrap().decode(), Ok(SetResponse))
    }

    #[test]
    fn decode_info_settings_test() {
        assert_eq!(GetInfoResponse::decode_settings(&[0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07, 0x00, 0x00, 0x03, 0x94, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponse::Settings {
                power: Power::On,
                mode: Mode::Heat,
                setpoint: Temperature::HalfDegreesCPlusOffset { value: 0x94 },
                fan: Fan::Auto,
                vane: Vane::Swing,
                widevane: WideVane::Center,
                isee: ISee::Off,

            }))
        );

        assert_eq!(GetInfoResponse::decode_settings(&[0x02, 0x00, 0x00, 0x01, 0x01, 0x0f, 0x00, 0x07, 0x00, 0x00, 0x03, 0xa0, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponse::Settings {
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
        assert_eq!(GetInfoResponse::decode_room_temp(&[0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponse::RoomTemperature {
                temperature: Temperature::HalfDegreesCPlusOffset{ value: 0xaa },
            }))
        );
        // When the half-degrees value is missing, test that we fall back to the
        // lower-res "mapped" value from byte 3
        assert_eq!(GetInfoResponse::decode_room_temp(&[0x03, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Ok((EMPTY, GetInfoResponse::RoomTemperature {
                temperature: Temperature::RoomTempMapped{ value: 0x0b },
            }))
        );
    }
}
