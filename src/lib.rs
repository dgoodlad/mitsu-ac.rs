#![no_std]

//! mitsu_ac
//!
//! Reverse-engineered protocol implementation for some Mitsubishi heat pumps
//! (aka air conditioners) with CN105 connectors. Based heavily on the work in
//! [SwiCago/HeatPump](https://github.com/SwiCago/HeatPump).
//!
//! This library is in its very early stages, and is quite untested.
//!
//! It is intended for use on embedded hardware, and as such is `no_std`.
//!
//! There is no code to actually interface with a serial device here. The CN105
//! serial connection operates at 2400 baud, 8 bits per byte, even parity with 1
//! stop bit (2400 8E1). You should configure your serial peripheral as such,
//! and use this library to parse/encode data on that line.
//!
//! ## General Usage
//!
//! Read from the serial line:
//!
//! ```
//! use mitsu_ac::protocol::{Frame, FrameData};
//!
//! let mut buf: &[u8] = &[0x42, 0x00, 0xfc, 0x7a, 0x01, 0x30, 0x01, 0x00, 0x54];
//!
//! // Read from the buffer until we find the start of a frame, and discard the junk.
//! let (buf, _) = Frame::parse_until(buf).unwrap();
//!
//! // Read a frame
//! let (buf, frame) = Frame::parse(buf).unwrap();
//!
//! // Parse the frame's contents
//! let (_, data) = FrameData::parse(frame).unwrap();
//!
//! // Do different things depending what we received
//! match data {
//!     FrameData::SetResponse(r) => println!("Acknowledged a SetRequest"),
//!     FrameData::ConnectResponse(_) => println!("Connected!"),
//!     // ...
//!     _ => {},
//! }
//!
//! ```
//!
//! Encode a packet for writing to the serial line:
//!
//! ```
//! use mitsu_ac::protocol::{Frame, DataType, FrameData, GetInfoRequest, InfoType, Encodable};
//!
//! let mut buf: [u8; 22] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//!
//! // Build a `FrameData` containing a `GetInfoRequest`. Other data types might
//! // have more/no properties.
//! let data = FrameData::GetInfoRequest(
//!     GetInfoRequest::new(InfoType::Settings)
//! );
//!
//! // Build a `Frame`
//! let frame: Frame<FrameData> = data.into();
//!
//! match frame.encode(&mut buf[0..22]) {
//!     Ok(len) => {
//!         let encoded: &[u8] = &buf[0..len];
//!         println!("Transmittable encoded slice: {:?}", encoded);
//!
//!         assert_eq!(
//!             // Frame Header
//!             //
//!             //       ---- DataType::GetInfoRequest = 0x42
//!             //       ||||              ---- datalen = 0x10
//!             //       ||||              ||||
//!             &[ 0xfc, 0x42, 0x01, 0x30, 0x10,
//!
//!             // Frame Data (0x10 bytes  ^^^^)
//!             //
//!             // ---- InfoType::Settings = 0x02
//!             // ||||
//!                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!
//!             // Frame Footer (Checksum byte)
//!             //
//!             // ---- Checksum = 0xfc - SUM(frame_bytes) & 0xff
//!             // ||||
//!                0x7b ],
//!             encoded);
//!     },
//!     Err(e) => println!("Error encoding frame: {:?}", e),
//! }
//! ```

#[macro_use]
extern crate nom;

pub mod protocol;

#[doc(inline)]
pub use protocol::*;
