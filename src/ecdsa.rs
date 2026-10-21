//! Shape check of an `ECDSA-Sig-Value` (RFC 3279 section 2.2.3).

use der::Decode;
use der::Sequence;
use der::asn1::UintRef;

use crate::Error;

#[derive(Sequence)]
struct EcdsaSigValue<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// Rejects a value that is not a DER `ECDSA-Sig-Value` with `r` and `s` in `1..2^(8 * order_len)`.
pub(crate) fn check(value: &[u8], order_len: usize) -> Result<(), Error> {
    let malformed = |reason: String| Error::InvalidEcdsaSignature(reason);
    let signature = EcdsaSigValue::from_der(value)
        .map_err(|e| malformed(format!("not a der sequence of two integers: {e}")))?;
    for integer in [signature.r, signature.s] {
        let bytes = integer.as_bytes();
        if bytes.iter().all(|b| *b == 0) {
            return Err(malformed("integer is zero".to_owned()));
        }
        if bytes.len() > order_len {
            return Err(malformed(format!(
                "integer longer than the {order_len} byte curve order"
            )));
        }
    }
    Ok(())
}
