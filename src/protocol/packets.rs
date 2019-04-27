use nom::*;

struct EncodingError;

trait Encodable {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError>;
}

trait PacketType { fn id() -> u8; }

impl<T> Encodable for T where T: PacketType {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        if into.len() != 1 {
            Err(EncodingError)
        } else {
            into[0] = T::id();
            Ok(into)
        }
    }
}

trait PacketData<T: PacketType> : Encodable {
    fn length(&self) -> usize;
}

struct Packet<T: PacketType, D: PacketData<T>> {
    packet_type: T,
    data: D,
}

impl<T: PacketType, D: PacketData<T>> Encodable for Packet<T, D> {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        let data_len = self.data.length();
        if into.len() != 5 + data_len + 1 {
            Err(EncodingError)
        } else {
            into[0] = 0xfc;
            self.packet_type.encode(&mut into[1..2])?;
            into[2] = 0x01;
            into[3] = 0x30;
            into[4] = data_len as u8;
            self.data.encode(&mut into[5..(data_len + 5)])?;
            Ok(into)
        }
    }
}

enum SetRequest {}
impl PacketType for SetRequest { fn id() -> u8 { 0x42 } }

struct SetRequestData;
impl PacketData<SetRequest> for SetRequestData {
    fn length(&self) -> usize { 0x10 }
}

impl Encodable for SetRequestData {
    fn encode<'a>(&self, into: &'a mut [u8]) -> Result<&'a [u8], EncodingError> {
        // TODO once rust has const generics this check can go away in favor of
        // a type bound
        if into.len() != self.length() {
            Err(EncodingError)
        } else {
            Ok(into)
        }
    }
}
