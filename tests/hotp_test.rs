use otp::{Algorithm, Hotp, Secret};

#[test]
fn test_generate_and_verify() {
    let issuer = String::from("example");
    let label = String::from("alice@example.com");
    let digits = 6;
    let counter = 5;
    let secret = Secret::from_bytes(b"The quick brown fox jumps over the lazy dog");

    let mut hotp = Hotp::new(Algorithm::SHA1, issuer, label, digits, counter, secret);

    let otp = hotp.generate();

    assert_eq!(
        hotp.counter(),
        counter + 1,
        "counter should increment after generate"
    );

    assert!(
        hotp.verify(otp, counter, 0),
        "OTP should be valid at the original counter"
    );

    assert!(
        hotp.verify(otp, counter - 1, 1),
        "OTP should be valid within backward window"
    );

    assert!(
        !hotp.verify(otp, counter - 2, 1),
        "OTP should not be valid outside window"
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

    let hotp = Hotp::new(
        alg,
        issuer.clone(),
        label.clone(),
        digits,
        period,
        secret.clone(),
    );
    let hotp_uri = hotp.to_uri();

    let hotp_from_uri = Hotp::from_uri(&hotp_uri).expect("parse error");

    assert_eq!(hotp_uri, hotp_from_uri.to_uri(), "should have same uri");
}
