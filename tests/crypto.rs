use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use whn_core::crypto::{verify_b64, Identity};
use whn_core::error::WhnError;

#[test]
fn malformed_keys_and_signatures_are_rejected() {
    let identity = Identity::from_secret_bytes(&[7; 32]);
    let signature = identity.sign(b"message");
    assert!(matches!(
        verify_b64("!", b"message", &signature),
        Err(WhnError::InvalidEncoding)
    ));
    for length in [0, 31, 33] {
        assert!(matches!(
            verify_b64(
                &URL_SAFE_NO_PAD.encode(vec![0; length]),
                b"message",
                &signature
            ),
            Err(WhnError::InvalidPublicKey)
        ));
    }
    for signature in [
        "!".into(),
        URL_SAFE_NO_PAD.encode([0; 63]),
        URL_SAFE_NO_PAD.encode([0; 65]),
    ] {
        assert!(matches!(
            verify_b64(&identity.public_key_b64(), b"message", &signature),
            Err(WhnError::InvalidEncoding)
        ));
    }
    assert!(matches!(
        verify_b64(&identity.public_key_b64(), b"changed", &signature),
        Err(WhnError::InvalidSignature)
    ));
}

#[test]
fn small_order_public_key_cannot_forge_signatures() {
    // Compressed identity point as both public key A and R, with scalar S = 0.
    // The non-strict verification equation accepts this for arbitrary messages.
    let mut key = [0; 32];
    key[0] = 1;
    let mut signature = [0; 64];
    signature[0] = 1;
    assert!(matches!(
        verify_b64(
            &URL_SAFE_NO_PAD.encode(key),
            b"any card",
            &URL_SAFE_NO_PAD.encode(signature)
        ),
        Err(WhnError::InvalidSignature)
    ));
}
