//! Strict canonical protobuf only for the new Compose service, never legacy RPCs.
use prost::{bytes::Buf, Message};
use std::marker::PhantomData;
use tonic::{
    codec::{Codec, DecodeBuf, Decoder},
    Status,
};
#[derive(Default)]
pub struct StrictCodec<T, U>(PhantomData<(T, U)>);
pub struct StrictDecoder<U>(PhantomData<U>);
impl<T: Message + Send + 'static, U: Message + Default + Send + 'static> Codec
    for StrictCodec<T, U>
{
    type Encode = T;
    type Decode = U;
    type Encoder = <tonic_prost::ProstCodec<T, U> as Codec>::Encoder;
    type Decoder = StrictDecoder<U>;
    fn encoder(&mut self) -> Self::Encoder {
        tonic_prost::ProstCodec::<T, U>::default().encoder()
    }
    fn decoder(&mut self) -> Self::Decoder {
        StrictDecoder(PhantomData)
    }
}
fn decode<U: Message + Default>(raw: &[u8]) -> Result<U, Status> {
    if raw.len() > 70 * 1024 {
        return Err(Status::resource_exhausted("Compose message limit"));
    }
    let value = U::decode(raw).map_err(|_| Status::invalid_argument("Invalid Compose message"))?;
    if value.encode_to_vec() != raw {
        return Err(Status::invalid_argument("Noncanonical Compose message"));
    }
    Ok(value)
}
impl<U: Message + Default> Decoder for StrictDecoder<U> {
    type Item = U;
    type Error = Status;
    fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<U>, Status> {
        let raw = buf.copy_to_bytes(buf.remaining());
        decode(&raw).map(Some)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::agent::compose::v1::ObserveRegisteredApplicationRequest as Request;
    #[test]
    fn rejects_unknown_and_duplicate_fields() {
        let r = Request {
            schema_version: 1,
            application_id: "colrow".into(),
        };
        let raw = r.encode_to_vec();
        assert!(decode::<Request>(&raw).is_ok());
        for suffix in [&[0x18, 1][..], &[0x08, 1][..]] {
            let mut mutated = raw.clone();
            mutated.extend(suffix);
            assert!(decode::<Request>(&mutated).is_err())
        }
    }
}
