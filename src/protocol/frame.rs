use nom::number::streaming::be_u8;
use nom::do_parse;

use super::encoding::{Encodable, EncodingError};

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

    fn parse(data: &'a [u8]) -> nom::IResult<&[u8], Self> {
        do_parse!(data,
            tag!(&[FRAME_START]) >>
            data_type: map!(be_u8, DataType::from) >>
            tag!(&[FRAME_B3, FRAME_B4]) >>
            data_len: map!(be_u8, |b| b as usize) >>
            data: take!(data_len) >>
            checksum: value!(Self::checksum(data_type, data_len, data)) >>
            verify!(be_u8, |b| b == checksum) >>
            (Self { data_type, data_len, data, checksum })
        )
    }
}

// TODO this interface is a bit silly, as it requires encoding FrameData into a
// &[u8], using that to construct a Frame, then copying all that data again.
// I might need to split the implementation a bit, perhaps make a new thing that
// stores FrameData instead of &[u8].
impl<'a> Encodable for Frame<'a> {
    fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodingError> {
        if buf.len() < 5 + self.data_len + 1 {
            return Err(EncodingError::BufferTooSmall);
        }

        buf[0] = FRAME_START;
        buf[1] = self.data_type as u8;
        buf[2] = FRAME_B3;
        buf[3] = FRAME_B4;
        buf[4] = self.data.len() as u8;
        buf[5..(5 + self.data_len)].copy_from_slice(self.data);
        buf[5 + self.data_len] = self.checksum;

        Ok(5 + self.data_len + 1)
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
            Ok((EMPTY, (Frame { data_type: DataType::GetInfoRequest,
                        data_len: 0x10,
                        data: &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                        checksum: 0x7b,
            }))),
            Frame::parse(&[
                0xfc, 0x42, 0x01, 0x30, 0x10,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x7b,
            ])
        );
    }

    #[test]
    fn encode_test() {
        let mut buf: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let frame = Frame::new(DataType::ConnectRequest, 2, &[0xca, 0x01]);
        let result = frame.encode(&mut buf);
        assert_eq!(Ok(8), result);
        assert_eq!([0xfc, 0x5a, 0x01, 0x30, 0x02, 0xca, 0x01, 0xa8], buf);
    }
}
