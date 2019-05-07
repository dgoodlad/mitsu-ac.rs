use nom::number::streaming::be_u8;
use nom::do_parse;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataType {
    SetRequest = 0x41,
    GetInfoRequest = 0x42,
    ConnectRequest = 0x5a,

    SetResponse = 0x61,
    GetInfoResponse = 0x62,
    ConnectResponse = 0x7a,

    Unknown = 0xff,
}

impl From<u8> for DataType {
    fn from(byte: u8) -> Self {
        match byte {
            0x41 => DataType::SetRequest,
            0x42 => DataType::GetInfoRequest,
            0x5a => DataType::ConnectRequest,

            0x61 => DataType::SetResponse,
            0x62 => DataType::GetInfoResponse,
            0x7a => DataType::ConnectResponse,

            _ => DataType::Unknown,
        }
    }
}

const FRAME_START: u8 = 0xfc;
const FRAME_B3: u8 = 0x01;
const FRAME_B4: u8 = 0x30;

#[derive(Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    pub data_type: DataType,
    pub data_len: usize,
    pub data: &'a [u8],
    checksum: u8,
}

#[derive(Debug, Eq, PartialEq)]
pub enum FrameParsingError<'a> {
    InvalidChecksum,
    IncompleteData(Option<usize>),
    UnknownError(&'a [u8]),
}

impl<'a> Frame<'a> {
    fn checksum(data_type: DataType, data_len: usize, data: &[u8]) -> u8 {
        let header_sum = FRAME_START as u32
            + data_type as u32
            + FRAME_B3 as u32
            + FRAME_B4 as u32
            + data_len as u32;
        let sum = data.iter().fold(header_sum, |acc, b| acc + *b as u32);
        0xfc - (sum as u8)
    }

    fn validate_checksum(&self) -> bool {
        let calculated = Self::checksum(self.data_type, self.data_len, self.data);
        calculated == self.checksum
    }

    fn new(data_type: DataType, data_len: usize, data: &'a [u8]) -> Self {
        Self {
            data_type,
            data_len,
            data,
            checksum: Self::checksum(data_type, data_len, data),
        }
    }

    fn parse(data: &'a [u8]) -> Result<(Self, &'a [u8]), FrameParsingError> {
        if data.len() < 6 { return Err(FrameParsingError::IncompleteData(None)) }

        let result = do_parse!(data,
            tag!(&[FRAME_START]) >>
            data_type: map!(be_u8, DataType::from) >>
            tag!(&[FRAME_B3, FRAME_B4]) >>
            data_len: map!(be_u8, |b| b as usize) >>
            data: take!(data_len) >>
            checksum: be_u8 >>
            (Self { data_type, data_len, data, checksum })
        );

        match result {
            Ok((remaining_data, frame)) => {
                if frame.validate_checksum() {
                    Ok((frame, remaining_data))
                } else {
                    Err(FrameParsingError::InvalidChecksum)
                }
            },

            Err(nom::Err::Incomplete(needed)) => match needed {
                nom::Needed::Size(size) => Err(FrameParsingError::IncompleteData(Some(size))),
                nom::Needed::Unknown => Err(FrameParsingError::IncompleteData(None)),
            },

            Err(nom::Err::Failure((remaining_data, err))) => Err(FrameParsingError::UnknownError(remaining_data)),
            Err(nom::Err::Error((remaining_data, err))) => Err(FrameParsingError::UnknownError(remaining_data)),
        }
    }
}

mod tests {
    use super::*;

    const EMPTY: &[u8] = &[];

    #[test]
    fn checksum_test() {
        assert_eq!(
            0xa8,
            Frame::checksum(DataType::ConnectRequest, 0x02, &[0xca, 0x01])
        );
    }

    #[test]
    fn parse_test() {
        assert_eq!(
            Ok((Frame { data_type: DataType::GetInfoRequest,
                        data_len: 0x10,
                        data: &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                        checksum: 0x7b,
            }, EMPTY)),
            Frame::parse(&[
                0xfc, 0x42, 0x01, 0x30, 0x10,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x7b,
            ])
        );
    }
}
