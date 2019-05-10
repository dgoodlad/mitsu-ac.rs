#[derive(Debug, PartialEq, Eq)]
pub enum EncodingError {
    BufferTooSmall,
    UnknownDataType,
    NotImplemented,
}

pub trait FixedSizeEncoding {
    const LENGTH: usize;
}

pub trait SizedEncoding {
    fn length(&self) -> usize;
}

pub trait Encodable : SizedEncoding {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<usize, EncodingError>;
}

impl<T> SizedEncoding for T where T: FixedSizeEncoding {
    fn length(&self) -> usize { T::LENGTH }
}

#[macro_export]
macro_rules! one_byte_encodable_enum {
    ( $( $enum:ty ),* ) => {
        $(
            impl Encodable for $enum where $enum: OneByteEncodable {
                fn encode<'a>(&self, into: &'a mut [u8]) -> Result<usize, EncodingError> {
                    if into.len() != 1 { return Err(EncodingError::BufferTooSmall); }
                    into[0] = self.encoded_as_byte();
                    Ok(1)
                }
            }
        )*
    }
}

pub trait OneByteEncodable : FixedSizeEncoding {
    fn encoded_as_byte(&self) -> u8;
}

impl<T: OneByteEncodable> FixedSizeEncoding for T {
    const LENGTH: usize = 1;
}

impl<T> FixedSizeEncoding for Option<T> where T: FixedSizeEncoding {
    const LENGTH: usize = T::LENGTH;
}

impl<T> Encodable for Option<T> where T: Encodable + FixedSizeEncoding {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<usize, EncodingError> {
        match self {
            Some(encodable) => encodable.encode(into),
            None => Ok(0)
        }
    }
}

impl SizedEncoding for &[u8] {
    fn length(&self) -> usize { self.len() }
}

impl Encodable for &[u8] {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<usize, EncodingError> {
        if into.len() != self.len() { return Err(EncodingError::BufferTooSmall); }
        into.copy_from_slice(self);
        Ok(self.len())
    }
}
