#[derive(Debug, PartialEq, Eq)]
pub enum EncodingError {
    BufferTooSmall,
    UnknownDataType,
    NotImplemented,
}

pub trait Encodable {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<usize, EncodingError>;
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

pub trait OneByteEncodable {
    fn encoded_as_byte(&self) -> u8;
}

impl<T> Encodable for Option<T> where T: Encodable {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<usize, EncodingError> {
        match self {
            Some(encodable) => encodable.encode(into),
            None => Ok(0)
        }
    }
}
