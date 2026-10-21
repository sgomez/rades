# rades

AdES signatures built from the ETSI standards, with the signing key held by the caller.

## Signing

**Data to sign**:
The bytes a signature value covers (EN 319 102-1's DTBS), together with the signature algorithm that will cover them.
_Avoid_: pre, presignature, hash to sign

**Pending signature**:
A signature between its two phases: its data to sign is out, its signature values are not yet in.
_Avoid_: session, triphase

**Signature value**:
What the caller's key produces over the data to sign.
_Avoid_: PKCS#1, pk1

**Augmentation**:
Raising a finished signature to a higher level (B-T, B-LT, B-LTA) by adding material to it, never by re-signing.
_Avoid_: upgrade, extension, postsign

**Co-signature**:
A second, independent signature over the same content, parallel to the existing ones.
_Avoid_: multi-signature

**Countersignature**:
A signature over an existing signature value, not over the content.
_Avoid_: counter-sign
