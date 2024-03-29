use nom::number::streaming::be_u8;
use nom::do_parse;

use super::encoding::{Encodable, EncodingError, SizedEncoding};

/// The type of data contained in a frame. We don't know all of the possible
/// types, just a few that have been reverse-engineered.
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

/// A single protocol frame, mainly here to identify and wrap some data.
/// Generally used as either `Frame<&[u8]>` in the case of a frame that's just
/// been parsed from a byte slice, or as `Frame<FrameData>` for a frame that
/// is being built up to be encoded into a byte slice.
#[derive(Debug, Eq, PartialEq)]
pub struct Frame<T: Encodable> {
    pub data_type: DataType,
    pub data_len: usize,
    pub data: T,
}

#[derive(Debug, Eq, PartialEq)]
pub enum FrameParsingError<'a> {
    InvalidChecksum,
    IncompleteData(Option<usize>),
    UnknownError(&'a [u8]),
}

impl<T> Frame<T> where T: Encodable {
    pub fn new(data_type: DataType, data_len: usize, data: T) -> Self {
        Self {
            data_type,
            data_len,
            data,
        }
    }
}

/// A frame parsed from a byte slice
///
/// ```
/// use mitsu_ac::protocol::{Frame, DataType};
///
/// let buf: &[u8] = &[0xfc, 0x5a, 0x01, 0x30, 0x02, 0xca, 0x01, 0xa8];
///
/// if let Ok((_, frame)) = Frame::parse(&buf) {
///     assert_eq!(frame.data_type, DataType::ConnectRequest);
///     assert_eq!(frame.data_len, 0x02);
///     assert_eq!(frame.data, &[0xca, 0x01][0..2]);
/// }
/// ```
impl Frame<&[u8]> {
    pub fn parse_until<'a>(data: &'a [u8]) -> nom::IResult<&'a [u8], &'a [u8]> {
        take_till!(data, |b| b == FRAME_START)
    }

    pub fn parse<'a>(data: &'a [u8]) -> nom::IResult<&'a [u8], Frame<&'a [u8]>> {
        do_parse!(data,
            tag!(&[FRAME_START]) >>
            data_type: map!(be_u8, DataType::from) >>
            tag!(&[FRAME_B3, FRAME_B4]) >>
            data_len: map!(be_u8, |b| b as usize) >>
            data: take!(data_len) >>
            frame: value!(Frame::new(data_type, data_len, data)) >>
            verify!(be_u8, |b| *b == checksum(data_type, data_len, data)) >>
            (frame)
        )
    }
}

fn checksum(data_type: DataType, data_len: usize, data: &[u8]) -> u8 {
    let header_sum = FRAME_START as u32
        + data_type as u32
        + FRAME_B3 as u32
        + FRAME_B4 as u32
        + data_len as u32;
    let sum = data.iter().fold(header_sum, |acc, b| acc + *b as u32);
    0xfc - (sum as u8)
}

impl<T> SizedEncoding for Frame<T> where T: Encodable {
    fn length(&self) -> usize {
        5 + self.data.length() + 1
    }
}

impl<T> Encodable for Frame<T> where T: Encodable {
    fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodingError> {
        if buf.len() < 5 + self.data_len + 1 {
            return Err(EncodingError::BufferTooSmall);
        }

        let (header, rest): (&mut [u8], &mut [u8]) = buf.split_at_mut(5);
        let (data, rest): (&mut [u8], &mut [u8]) = rest.split_at_mut(self.data.length());

        header[0] = FRAME_START;
        header[1] = self.data_type as u8;
        header[2] = FRAME_B3;
        header[3] = FRAME_B4;
        header[4] = self.data.length() as u8;

        self.data.encode(data)?;

        if let Some(last) = rest.first_mut() {
            *last = checksum(self.data_type, self.data_len, data);
            Ok(5 + self.data_len + 1)
        } else {
            Err(EncodingError::BufferTooSmall)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &[u8] = &[];

    #[test]
    fn checksum_test() {
        assert_eq!(
            0xa8,
            checksum(DataType::ConnectRequest, 0x02, &[0xca, 0x01][0..2])
        );
    }

    #[test]
    fn parse_test() {
        let expected = Frame::new(
            DataType::GetInfoRequest,
            0x10,
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][0..16],
        );

        assert_eq!(
            Ok((EMPTY, expected)),
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
        let frame = Frame::new(DataType::ConnectRequest, 2, &[0xca, 0x01][0..2]);
        let result = frame.encode(&mut buf);
        assert_eq!(Ok(8), result);
        assert_eq!([0xfc, 0x5a, 0x01, 0x30, 0x02, 0xca, 0x01, 0xa8], buf);
    }
}
