use otp::{Algorithm, Secret, Totp};

#[test]
fn test_generate_and_verify() {
    let issuer = String::from("example");
    let label = String::from("alice@example.com");
    let digits = 6;
    let period = 30;
    let secret = Secret::from_bytes(b"The quick brown fox jumps over the lazy dog");

    let totp = Totp::new(Algorithm::default(), issuer, label, digits, period, secret);

    let timestamp_secs = 30;
    let otp = totp.generate_at(timestamp_secs);

    assert!(
        totp.verify(otp, timestamp_secs - 29, 1),
        "should be valid within acceptable window"
    );
    assert!(
        totp.verify(otp, timestamp_secs, 1),
        "should be valid with at same timestamp"
    );
    assert!(
        totp.verify(otp, timestamp_secs + 29, 1),
        "should be valid within window"
    );
    assert!(
        totp.verify(otp, timestamp_secs + 59, 1),
        "should be valid within window"
    );
    assert!(
        !totp.verify(otp, timestamp_secs + 60, 1),
        "should not be valid"
    );
}

#[test]
fn test_from_and_to_uri() {
    let alg = Algorithm::SHA512;
    let issuer = String::from("example");
    let label = String::from("alice@example.com");
    let digits = 6;
    let period = 30;
    let secret = Secret::from_bytes(b"The quick brown fox jumps over the lazy dog");

    let totp = Totp::new(
        alg,
        issuer.clone(),
        label.clone(),
        digits,
        period,
        secret.clone(),
    );
    let totp_uri = totp.to_uri();

    let totp_from_uri = Totp::from_uri(&totp_uri).expect("parse error");

    assert_eq!(totp_uri, totp_from_uri.to_uri(), "should have same uri");
}
