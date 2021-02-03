use biscuit::jwa::{
    ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm, SignatureAlgorithm,
};
use biscuit::jwe;
use biscuit::jwk::JWK;
use biscuit::jws::{self, Secret};
use biscuit::{ClaimsSet, Empty, RegisteredClaims, SingleOrMultiple, JWE, JWT};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// Define our own private claims
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct PrivateClaims {
    company: String,
    department: String,
}

fn main() {
    #[allow(unused_assignments)]
    // Craft our JWS
    let expected_claims = ClaimsSet::<PrivateClaims> {
        registered: RegisteredClaims {
            issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
            subject: Some(FromStr::from_str("John Doe").unwrap()),
            audience: Some(SingleOrMultiple::Single(
                FromStr::from_str("htts://acme-customer.com").unwrap(),
            )),
            not_before: Some(1234.into()),
            ..Default::default()
        },
        private: PrivateClaims {
            department: "Toilet Cleaning".to_string(),
            company: "ACME".to_string(),
        },
    };

    let expected_jwt = JWT::new_decoded(
        From::from(jws::RegisteredHeader {
            algorithm: SignatureAlgorithm::HS256,
            ..Default::default()
        }),
        expected_claims.clone(),
    );

    let signing_secret = Secret::Bytes("secret".to_string().into_bytes());

    let jws = expected_jwt.into_encoded(&signing_secret).unwrap();

    // Encrypt the token

    // You would usually have your own AES key for this, but we will use a zeroed key as an example
    let key: JWK<Empty> = JWK::new_octet_key(&vec![0; 256 / 8], Default::default());

    // We need to create an `EncryptionOptions` with a nonce for AES GCM encryption.
    // You must take care NOT to reuse the nonce. You can simply treat the nonce as a 96 bit
    // counter that is incremented after every use
    let mut nonce_counter = num::BigUint::from_bytes_le(&vec![0; 96 / 8]);
    // Make sure it's no more than 96 bits!
    assert!(nonce_counter.bits() <= 96);
    let mut nonce_bytes = nonce_counter.to_bytes_le();
    // We need to ensure it is exactly 96 bits
    nonce_bytes.resize(96 / 8, 0);
    let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };

    // Construct the JWE
    let jwe = JWE::new_decrypted(
        From::from(jwe::RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            media_type: Some("JOSE".to_string()),
            content_type: Some("JOSE".to_string()),
            ..Default::default()
        }),
        jws.clone(),
    );

    // Encrypt
    let encrypted_jwe = jwe.encrypt(&key, &options).unwrap();

    let token = encrypted_jwe.unwrap_encrypted().to_string();

    // Now, send `token` to your clients
    println!("Token: {}", token);

    // ... some time later, we get token back!
    let token: JWE<PrivateClaims, Empty, Empty> = JWE::new_encrypted(&token);

    // Decrypt
    let decrypted_jwe = token
        .into_decrypted(
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();

    let decrypted_jws = decrypted_jwe.payload().unwrap();
    assert_eq!(jws, *decrypted_jws);
    println!("Decrypted JWS: {:?}", decrypted_jws);

    let jws = decrypted_jws
        .decode(&signing_secret, SignatureAlgorithm::HS256)
        .unwrap();
    assert_eq!(*jws.payload().unwrap(), expected_claims);
    println!("Claims: {:?}", *jws.payload().unwrap());

    // Don't forget to increment the nonce!
    nonce_counter = nonce_counter + 1u8;
}
