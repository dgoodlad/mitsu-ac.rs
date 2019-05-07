use nom::number::streaming::be_u8;
use nom::do_parse;

use super::frame::{DataType, Frame};

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
    pub fn parse(frame: Frame) -> Result<Self> {
        match frame.data_type {
            DataType::SetRequest => FrameData::SetRequest(SetRequest::parse(frame.data)),
            DataType::GetInfoRequest => FrameData::GetInfoRequest(GetInfoRequest::parse(frame.data)),
            DataType::ConnectRequest => FrameData::ConnectRequest(ConnectRequest::parse(frame.data)),

            DataType::SetResponse => FrameData::SetResponse(SetResponse::parse(frame.data)),
            DataType::GetInfoResponse => FrameData::GetInfoResponse(GetInfoResponse::parse(frame.data)),
            DataType::ConnectResponse => FrameData::ConnectResponse(ConnectResponse::parse(frame.data)),

            DataType::Unknown => FrameData::Unknown,
        }
    }
}

pub struct SetRequest;

impl SetRequest {
    fn parse(data: &[u8]) -> Self {
        Self
    }
}

pub struct GetInfoRequest;

impl GetInfoRequest {
    fn parse(data: &[u8]) -> Self {
        Self
    }
}

pub struct ConnectRequest;

impl ConnectRequest {
    fn parse(data: &[u8]) -> Self {
        Self
    }
}

pub struct SetResponse;

impl SetResponse {
    fn parse(data: &[u8]) -> Self {
        Self
    }
}

pub struct GetInfoResponse;

impl GetInfoResponse {
    fn parse(data: &[u8]) -> Self {
        Self
    }
}

pub struct ConnectResponse;

impl ConnectResponse {
    fn parse(data: &[u8]) -> Self {
        Self
    }
}
