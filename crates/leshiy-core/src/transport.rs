//! Frame transport traits — the channel abstraction the mux runs over.
//! Implemented by the Noise session halves (v0) and the REALITY TLS transport (M1.3c).
use crate::Result;
use crate::frame::Frame;
use core::future::Future;

pub trait FrameRead {
    fn read_frame(&mut self) -> impl Future<Output = Result<Frame>> + Send;
}

pub trait FrameWrite {
    fn write_frame(&mut self, frame: &Frame) -> impl Future<Output = Result<()>> + Send;
}
