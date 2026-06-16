//! Carry leshiy frame/mux over the REALITY TLS 1.3 application-data records.
use crate::error::{RealityError, Result as RealityResult};
use crate::handshake::{
    ClientHandshakeOut, ServerCert, TlsSession, client_handshake, server_handshake,
};
use leshiy_core::frame::Frame;
use leshiy_core::transport::{FrameRead, FrameWrite};
use leshiy_core::{Error, Result};
use leshiy_tls::record::{MAX_RECORD_PAYLOAD, read_record};
use leshiy_tls::tls13::mlkem::MlKemDecapKey;
use leshiy_tls::tls13::record::{open_record_parts, seal_record};
use leshiy_tls::tls13::suite::CipherSuite;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

const APPLICATION_DATA: u8 = 0x17;
/// Max `frame.encode()` that seals into one RFC 8446-compliant TLS record: the
/// TLSInnerPlaintext (frame bytes + 1-byte inner content-type) must not exceed 2^14.
/// The mux already chunks to [`leshiy_core::frame::MAX_FRAME_PAYLOAD`] so this never
/// trips in practice; it's a defense-in-depth guard that turns an oversized frame into
/// a clean error rather than an unreadable (record-cap-rejected) record on the wire.
const MAX_TLS_FRAME_ENCODE: usize = MAX_RECORD_PAYLOAD - 1;

pub struct TlsFrameReader<R> {
    pub(crate) inner: R,
    pub(crate) suite: CipherSuite,
    pub(crate) key: Zeroizing<Vec<u8>>,
    pub(crate) iv: [u8; 12],
    pub(crate) seq: u64,
}
pub struct TlsFrameWriter<W> {
    pub(crate) inner: W,
    pub(crate) suite: CipherSuite,
    pub(crate) key: Zeroizing<Vec<u8>>,
    pub(crate) iv: [u8; 12],
    pub(crate) seq: u64,
}

impl<R: AsyncRead + Unpin + Send> TlsFrameReader<R> {
    async fn recv(&mut self) -> Result<Frame> {
        // read one TLS record (outer header + ciphertext) off the wire
        let rec = read_record(&mut self.inner)
            .await
            .map_err(|_| Error::Closed)?;
        // Reconstruct the 5-byte header (AAD) from the parsed parts and decrypt the
        // body in place — avoids re-encoding the whole record just to open it.
        let len = rec.payload.len() as u16;
        let header = [rec.content_type, 0x03, 0x03, (len >> 8) as u8, len as u8];
        let (inner_type, pt) = open_record_parts(
            self.suite,
            &self.key,
            &self.iv,
            self.seq,
            &header,
            &rec.payload,
        )
        .map_err(|_| Error::Protocol("tls record open".into()))?;
        // Never let the record sequence wrap: a reused (key, nonce) pair would
        // catastrophically break AEAD. Close the connection at exhaustion. (L2)
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("tls record sequence exhausted".into()))?;
        if inner_type != APPLICATION_DATA {
            return Err(Error::Protocol("unexpected inner content type".into()));
        }
        // Zero-copy: the decrypted plaintext Vec becomes Bytes and the frame payload
        // is a refcounted slice of it (no extra copy of the payload).
        Frame::decode_from_bytes(bytes::Bytes::from(pt))
    }
}

impl<R: AsyncRead + Unpin + Send> FrameRead for TlsFrameReader<R> {
    fn read_frame(&mut self) -> impl core::future::Future<Output = Result<Frame>> + Send {
        self.recv()
    }
}

impl<W: AsyncWrite + Unpin + Send> TlsFrameWriter<W> {
    async fn send(&mut self, frame: &Frame) -> Result<()> {
        let bytes = frame.encode();
        if bytes.len() > MAX_TLS_FRAME_ENCODE {
            return Err(Error::FrameTooLarge(bytes.len()));
        }
        let rec = seal_record(
            self.suite,
            &self.key,
            &self.iv,
            self.seq,
            APPLICATION_DATA,
            &bytes,
        )
        .map_err(|_| Error::Protocol("tls record seal".into()))?;
        // See the reader: never let the sequence wrap (nonce reuse). (L2)
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("tls record sequence exhausted".into()))?;
        self.inner.write_all(&rec).await.map_err(Error::Io)?;
        self.inner.flush().await.map_err(Error::Io)?;
        Ok(())
    }
}

impl<W: AsyncWrite + Unpin + Send> FrameWrite for TlsFrameWriter<W> {
    fn write_frame(
        &mut self,
        frame: &Frame,
    ) -> impl core::future::Future<Output = Result<()>> + Send {
        self.send(frame)
    }
}

/// Split a session's app keys into role-correct (reader, writer) over the given halves.
/// server: send=server_key, recv=client_key.  client: send=client_key, recv=server_key.
pub fn into_transport<R, W>(
    session: &TlsSession,
    role: leshiy_core::mux::Role,
    reader_half: R,
    writer_half: W,
) -> (TlsFrameReader<R>, TlsFrameWriter<W>) {
    let (send_key, send_iv, recv_key, recv_iv) = match role {
        leshiy_core::mux::Role::Server => (
            session.server_key.clone(),
            session.server_iv,
            session.client_key.clone(),
            session.client_iv,
        ),
        leshiy_core::mux::Role::Client => (
            session.client_key.clone(),
            session.client_iv,
            session.server_key.clone(),
            session.server_iv,
        ),
    };
    (
        TlsFrameReader {
            inner: reader_half,
            suite: session.suite,
            key: recv_key,
            iv: recv_iv,
            seq: 0,
        },
        TlsFrameWriter {
            inner: writer_half,
            suite: session.suite,
            key: send_key,
            iv: send_iv,
            seq: 0,
        },
    )
}

/// Drive the server handshake: send the flight, read the client Finished record,
/// return the session + the split halves ready for the app-data tunnel.
///
/// The caller has already read the ClientHello off the wire (to identify the connection)
/// and passes the split halves + the raw ClientHello bytes.
pub async fn establish_server<R, W>(
    mut reader: R,
    mut writer: W,
    client_hello: &[u8],
    dest_server_hello: &[u8],
    auth_key: &[u8; 32],
    cert: &ServerCert,
) -> RealityResult<(TlsSession, R, W)>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let (sh_state, flight) = server_handshake(client_hello, dest_server_hello, auth_key, cert)?;
    writer.write_all(&flight).await.map_err(RealityError::Io)?;
    writer.flush().await.map_err(RealityError::Io)?;
    // read one record = the client's (encrypted) Finished
    let fin = read_record(&mut reader)
        .await
        .map_err(|_| RealityError::Malformed("reading client Finished".into()))?;
    let session = sh_state.finish(&fin.encode())?;
    Ok((session, reader, writer))
}

/// Drive the client handshake over split halves. The caller has ALREADY sent the
/// ClientHello on `writer`. Reads the server flight, runs client_handshake, sends the
/// client Finished, returns session+halves.
///
/// `mlkem_dk` is the ML-KEM-768 decapsulation key generated alongside the ClientHello;
/// it is used when the server selects group 0x11ec (X25519MLKEM768).
pub async fn establish_client<R, W>(
    mut reader: R,
    mut writer: W,
    client_hello: &[u8],
    ephemeral_priv: &[u8; 32],
    auth_key: &[u8; 32],
    mlkem_dk: &MlKemDecapKey,
) -> RealityResult<(TlsSession, R, W)>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    // read the server flight: plaintext SH record + one encrypted record. Read two records
    // and concatenate their raw bytes (client_handshake parses SH then the encrypted record).
    let sh_rec = read_record(&mut reader)
        .await
        .map_err(|_| RealityError::Malformed("reading SH record".into()))?;
    let enc_rec = read_record(&mut reader)
        .await
        .map_err(|_| RealityError::Malformed("reading encrypted flight record".into()))?;
    let mut flight = sh_rec.encode();
    flight.extend_from_slice(&enc_rec.encode());
    let out: ClientHandshakeOut =
        client_handshake(client_hello, &flight, ephemeral_priv, auth_key, mlkem_dk)?;
    writer
        .write_all(&out.client_finished_record)
        .await
        .map_err(RealityError::Io)?;
    writer.flush().await.map_err(RealityError::Io)?;
    Ok((out.session, reader, writer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use leshiy_core::frame::{Frame, FrameType};
    use leshiy_core::transport::{FrameRead, FrameWrite};
    use leshiy_tls::tls13::suite::CipherSuite;

    #[tokio::test]
    async fn tls_transport_frame_roundtrip() {
        // shared app keys (as if from a TlsSession); writer=server side, reader=client side
        let suite = CipherSuite::Aes128GcmSha256;
        let s_key = vec![1u8; 16];
        let s_iv = [2u8; 12];
        let (a, b) = tokio::io::duplex(8192);
        let (ar, aw) = tokio::io::split(a);
        let (br, _bw) = tokio::io::split(b);
        // server writes with server key/seq; client reads with server key/seq
        let mut writer = TlsFrameWriter {
            inner: aw,
            suite,
            key: Zeroizing::new(s_key.clone()),
            iv: s_iv,
            seq: 0,
        };
        let mut reader = TlsFrameReader {
            inner: br,
            suite,
            key: Zeroizing::new(s_key.clone()),
            iv: s_iv,
            seq: 0,
        };
        let _ = (ar,); // silence unused

        for i in 0..3u8 {
            writer
                .write_frame(&Frame {
                    stream_id: 1,
                    ftype: FrameType::Data as u8,
                    payload: bytes::Bytes::from(vec![i; 10]),
                })
                .await
                .unwrap();
        }
        for i in 0..3u8 {
            let f = reader.read_frame().await.unwrap();
            assert_eq!(f.payload, vec![i; 10]); // seq advances correctly across frames
        }
    }

    #[tokio::test]
    async fn writer_errors_on_sequence_exhaustion() {
        // At seq == u64::MAX the next increment would wrap to 0 and reuse a
        // nonce. The writer must error instead of wrapping. (L2)
        let suite = CipherSuite::Aes128GcmSha256;
        let (a, _b) = tokio::io::duplex(8192);
        let (_ar, aw) = tokio::io::split(a);
        let mut writer = TlsFrameWriter {
            inner: aw,
            suite,
            key: Zeroizing::new(vec![1u8; 16]),
            iv: [2u8; 12],
            seq: u64::MAX,
        };
        let res = writer
            .write_frame(&Frame {
                stream_id: 1,
                ftype: FrameType::Data as u8,
                payload: bytes::Bytes::from(vec![0u8; 4]),
            })
            .await;
        assert!(res.is_err(), "sequence exhaustion must error, not wrap");
    }

    #[tokio::test]
    async fn wrong_key_fails_to_read() {
        let suite = CipherSuite::Aes128GcmSha256;
        let (a, b) = tokio::io::duplex(8192);
        let (_ar, aw) = tokio::io::split(a);
        let (br, _bw) = tokio::io::split(b);
        let mut writer = TlsFrameWriter {
            inner: aw,
            suite,
            key: Zeroizing::new(vec![1u8; 16]),
            iv: [2u8; 12],
            seq: 0,
        };
        let mut reader = TlsFrameReader {
            inner: br,
            suite,
            key: Zeroizing::new(vec![9u8; 16]),
            iv: [2u8; 12],
            seq: 0,
        };
        writer
            .write_frame(&Frame {
                stream_id: 1,
                ftype: FrameType::Data as u8,
                payload: bytes::Bytes::from(vec![5u8; 4]),
            })
            .await
            .unwrap();
        assert!(reader.read_frame().await.is_err());
    }
}
