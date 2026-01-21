use alloc::vec::Vec;

use crate::crypto::cipher::{EncodedMessage, MessageError, Payload};
use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::error::{AlertDescription, InvalidMessage};
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertLevel, KeyUpdateRequest};
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};

#[non_exhaustive]
#[derive(Debug)]
pub enum MessagePayload<'a> {
    Alert(AlertMessagePayload),
    // one handshake message, parsed
    Handshake {
        parsed: HandshakeMessagePayload<'a>,
        encoded: Payload<'a>,
    },
    // (potentially) multiple handshake messages, unparsed
    HandshakeFlight(Payload<'a>),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend(encoded.bytes()),
            Self::HandshakeFlight(x) => bytes.extend(x.bytes()),
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    pub(crate) fn handshake(parsed: HandshakeMessagePayload<'a>) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()),
            parsed,
        }
    }

    pub(crate) fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: &'a [u8],
    ) -> Result<Self, InvalidMessage> {
        let mut r = Reader::init(payload);
        match typ {
            ContentType::ApplicationData => Ok(Self::ApplicationData(Payload::Borrowed(payload))),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers).map(|parsed| Self::Handshake {
                    parsed,
                    encoded: Payload::Borrowed(payload),
                })
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            _ => Err(InvalidMessage::InvalidContentType),
        }
    }

    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake { .. } | Self::HandshakeFlight(_) => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn into_owned(self) -> MessagePayload<'static> {
        use MessagePayload::*;
        match self {
            Alert(x) => Alert(x),
            Handshake { parsed, encoded } => Handshake {
                parsed: parsed.into_owned(),
                encoded: encoded.into_owned(),
            },
            HandshakeFlight(x) => HandshakeFlight(x.into_owned()),
            ChangeCipherSpec(x) => ChangeCipherSpec(x),
            ApplicationData(x) => ApplicationData(x.into_owned()),
        }
    }
}

impl From<Message<'_>> for EncodedMessage<Payload<'_>> {
    fn from(msg: Message<'_>) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload.into_owned(),
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload::Owned(buf)
            }
        };

        Self {
            typ,
            version: msg.version,
            payload,
        }
    }
}

/// A message with decoded payload
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct Message<'a> {
    pub version: ProtocolVersion,
    pub payload: MessagePayload<'a>,
}

impl Message<'_> {
    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
            )),
        }
    }

    pub fn build_key_update_request() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateRequested),
            )),
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn into_owned(self) -> Message<'static> {
        let Self { version, payload } = self;
        Message {
            version,
            payload: payload.into_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_wire_bytes(self) -> Vec<u8> {
        EncodedMessage::<Payload<'_>>::from(self)
            .into_unencrypted_opaque()
            .encode()
    }

    pub(crate) fn handshake_type(&self) -> Option<HandshakeType> {
        match &self.payload {
            MessagePayload::Handshake { parsed, .. } => Some(parsed.0.handshake_type()),
            _ => None,
        }
    }
}

impl<'a> TryFrom<&'a EncodedMessage<&'a [u8]>> for Message<'a> {
    type Error = InvalidMessage;

    fn try_from(plain: &'a EncodedMessage<&'a [u8]>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

impl<'a> TryFrom<&'a EncodedMessage<Payload<'a>>> for Message<'a> {
    type Error = InvalidMessage;

    fn try_from(plain: &'a EncodedMessage<Payload<'a>>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload.bytes())?,
        })
    }
}

pub(crate) fn read_opaque_message_header(
    r: &mut Reader<'_>,
) -> Result<(ContentType, ProtocolVersion, u16), MessageError> {
    let typ = ContentType::read(r).map_err(|_| MessageError::TooShortForHeader)?;
    // Don't accept any new content-types.
    if let ContentType::Unknown(_) = typ {
        return Err(MessageError::InvalidContentType);
    }

    let version = ProtocolVersion::read(r).map_err(|_| MessageError::TooShortForHeader)?;
    // Accept only versions 0x03XX for any XX.
    match &version {
        ProtocolVersion::Unknown(v) if (v & 0xff00) != 0x0300 => {
            return Err(MessageError::UnknownProtocolVersion);
        }
        _ => {}
    };

    let len = u16::read(r).map_err(|_| MessageError::TooShortForHeader)?;

    // Reject undersize messages
    //  implemented per section 5.1 of RFC8446 (TLSv1.3)
    //              per section 6.2.1 of RFC5246 (TLSv1.2)
    if typ != ContentType::ApplicationData && len == 0 {
        return Err(MessageError::InvalidEmptyPayload);
    }

    // Reject oversize messages
    if len >= MAX_PAYLOAD {
        return Err(MessageError::MessageTooLarge);
    }

    Ok((typ, version, len))
}

/// Content type, version and size.
pub(crate) const HEADER_SIZE: usize = 1 + 2 + 2;

/// Maximum message payload size.
/// That's 2^14 payload bytes and a 2KB allowance for ciphertext overheads.
pub(crate) const MAX_PAYLOAD: u16 = 16_384 + 2048;

/// Maximum on-the-wire message size.
#[cfg(feature = "std")]
pub(crate) const MAX_WIRE_SIZE: usize = MAX_PAYLOAD as usize + HEADER_SIZE;

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::{format, fs, println, vec};

    use super::*;
    use crate::msgs::base::{MaybeEmpty, NonEmpty, SizedPayload};
    use crate::msgs::codec::U24;

    #[test]
    fn test_read_fuzz_corpus() {
        fn corpus_dir() -> PathBuf {
            let from_subcrate = Path::new("../fuzz/corpus/message");
            let from_root = Path::new("fuzz/corpus/message");

            if from_root.is_dir() {
                from_root.to_path_buf()
            } else {
                from_subcrate.to_path_buf()
            }
        }

        for file in fs::read_dir(corpus_dir()).unwrap() {
            let mut f = fs::File::open(file.unwrap().path()).unwrap();
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).unwrap();

            let mut rd = Reader::init(&bytes);
            let msg = EncodedMessage::<Payload<'_>>::read(&mut rd).unwrap();
            println!("{msg:?}");

            let Ok(msg) = Message::try_from(&msg) else {
                continue;
            };

            let enc = EncodedMessage::<Payload<'_>>::from(msg)
                .into_unencrypted_opaque()
                .encode();
            assert_eq!(bytes.to_vec(), enc);
            assert_eq!(bytes[..rd.used()].to_vec(), enc);
        }
    }

    #[test]
    fn can_read_safari_client_hello_with_ip_address_in_sni_extension() {
        let _ = env_logger::Builder::new()
            .filter(None, log::LevelFilter::Trace)
            .try_init();

        let bytes = b"\
        \x16\x03\x01\x00\xeb\x01\x00\x00\xe7\x03\x03\xb6\x1f\xe4\x3a\x55\
        \x90\x3e\xc0\x28\x9c\x12\xe0\x5c\x84\xea\x90\x1b\xfb\x11\xfc\xbd\
        \x25\x55\xda\x9f\x51\x93\x1b\x8d\x92\x66\xfd\x00\x00\x2e\xc0\x2c\
        \xc0\x2b\xc0\x24\xc0\x23\xc0\x0a\xc0\x09\xcc\xa9\xc0\x30\xc0\x2f\
        \xc0\x28\xc0\x27\xc0\x14\xc0\x13\xcc\xa8\x00\x9d\x00\x9c\x00\x3d\
        \x00\x3c\x00\x35\x00\x2f\xc0\x08\xc0\x12\x00\x0a\x01\x00\x00\x90\
        \xff\x01\x00\x01\x00\x00\x00\x00\x0e\x00\x0c\x00\x00\x09\x31\x32\
        \x37\x2e\x30\x2e\x30\x2e\x31\x00\x17\x00\x00\x00\x0d\x00\x18\x00\
        \x16\x04\x03\x08\x04\x04\x01\x05\x03\x02\x03\x08\x05\x08\x05\x05\
        \x01\x08\x06\x06\x01\x02\x01\x00\x05\x00\x05\x01\x00\x00\x00\x00\
        \x33\x74\x00\x00\x00\x12\x00\x00\x00\x10\x00\x30\x00\x2e\x02\x68\
        \x32\x05\x68\x32\x2d\x31\x36\x05\x68\x32\x2d\x31\x35\x05\x68\x32\
        \x2d\x31\x34\x08\x73\x70\x64\x79\x2f\x33\x2e\x31\x06\x73\x70\x64\
        \x79\x2f\x33\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x0b\x00\x02\
        \x01\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19";
        let mut rd = Reader::init(bytes);
        let m = EncodedMessage::<Payload<'_>>::read(&mut rd).unwrap();
        println!("m = {m:?}");
        Message::try_from(&m).unwrap();
    }

    #[test]
    fn alert_is_not_handshake() {
        let m = Message::build_alert(AlertLevel::Fatal, AlertDescription::DecodeError);
        assert_ne!(m.handshake_type(), Some(HandshakeType::ClientHello));
    }

    #[test]
    fn construct_all_types() {
        let samples = [
            &b"\x14\x03\x04\x00\x01\x01"[..],
            &b"\x15\x03\x04\x00\x02\x01\x16"[..],
            &b"\x16\x03\x04\x00\x05\x18\x00\x00\x01\x00"[..],
            &b"\x17\x03\x04\x00\x04\x11\x22\x33\x44"[..],
            &b"\x18\x03\x04\x00\x04\x11\x22\x33\x44"[..],
        ];
        for &bytes in samples.iter() {
            let m = EncodedMessage::<Payload<'_>>::read(&mut Reader::init(bytes)).unwrap();
            println!("m = {m:?}");
            let m = Message::try_from(&m);
            println!("m' = {m:?}");
        }
    }

    #[test]
    fn debug_payload() {
        assert_eq!("01020304", format!("{:?}", Payload::new(vec![1, 2, 3, 4])));
        assert_eq!(
            "01020304",
            format!("{:?}", SizedPayload::<u8, NonEmpty>::from(vec![1, 2, 3, 4]))
        );
        assert_eq!(
            "01020304",
            format!(
                "{:?}",
                SizedPayload::<u16, MaybeEmpty>::from(vec![1, 2, 3, 4])
            )
        );
        assert_eq!(
            "01020304",
            format!(
                "{:?}",
                SizedPayload::<'static, U24, NonEmpty>::from(Payload::new(vec![1, 2, 3, 4]))
            )
        );
    }

    #[test]
    fn into_wire_format() {
        // Message::into_wire_bytes() include both message-level and handshake-level headers
        assert_eq!(
            Message::build_key_update_request().into_wire_bytes(),
            &[0x16, 0x3, 0x4, 0x0, 0x5, 0x18, 0x0, 0x0, 0x1, 0x1]
        );
    }
}
