use actix_web::HttpRequest;

use super::{error, info, HttpResponse};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

// verification function
pub async fn verify_sig(request: &HttpRequest) -> bool {
    let hm_key: &str;
    let hm_sign: &str;

    // Getting the public from headers
    if let Some(hmkey) = request.headers().get("HM-KEY") {
        hm_key = hmkey.to_str().unwrap();
    } else {
        panic!("Public key not found");
    }

    // Taking the signature from headers
    if let Some(hmsign) = request.headers().get("HM-KEY") {
        hm_sign = hmsign.to_str().unwrap();
    } else {
        panic!("Signature key not found");
    }

    // Decoding the timestamp from headers.
    let ts = match request.headers().get("HM-TS") {
        Some(timestamp) => timestamp
            .to_str()
            .unwrap()
            .parse::<u64>()
            .expect("Malformed timestamp"),
        None => {
            panic!("Missing timestamp in Headers");
        }
    };

    // Extracting the public
    let public_key = PublicKey::from_slice(&hex::decode(hm_key).unwrap()).unwrap();
    info!("Public key  found {}", public_key);
    // Extract signature from string
    let signature = Signature::from_compact(&base64::decode(hm_sign).unwrap());
    let sign: Signature;
    match signature {
        Ok(s) => sign = s,
        Err(e) => {
            panic!("{}", e)
        }
    }

    let message = Message::from_slice(
        &Sha256::digest(
            format!("{}{}{}", ts, request.method().as_str(), request.path(),).as_bytes(),
        )[..],
    )
    .unwrap();

    // Condition one time should be 5 second old
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if (current_time - ts) > 20 {
        return false;
    }

    // Verify the signature.
    let verify = Secp256k1::verification_only();
    match verify.verify_ecdsa(&message, &sign, &public_key) {
        Ok(()) => {
            info!("Success");
            true
        }
        Err(_) => {
            error!("Error in verification");
            false
        }
    }
}

pub async fn verify(req: HttpRequest) -> HttpResponse {
    let verify = verify_sig(&req).await;
    HttpResponse::Ok().body(verify.to_string())
}

// Testing the verify function.
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use secp256k1::SecretKey;
    #[rustfmt::skip]
    static  SECKEY:[u8;32] = [
        59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
        102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
    ];
    static PUBKEY: [u8; 33] = [
        2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91, 141,
        134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
    ];
    #[test]
    async fn test_verify_sig() {
        let pubkey = PublicKey::from_slice(&PUBKEY).unwrap();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let msg = format!("{}{}{}", ts, "GET", "/");
        let msg = Sha256::digest(&msg.as_bytes());
        let msg = Message::from_slice(&msg).unwrap();

        let seckey = SecretKey::from_slice(&SECKEY).unwrap();
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(&msg, &seckey);
        let s = signature.serialize_compact();
        let sign = base64::encode(s);

        let req = test::TestRequest::default()
            .insert_header(("HM-KEY", pubkey.to_string()))
            .insert_header(("HM-SIGN", sign.to_string()))
            .insert_header(("HM-TS", ts))
            .to_http_request();
        let result = verify_sig(&req).await;
        assert_eq!(result, true)
    }

    #[test]
    async fn create_header() {
        let pubkey = PublicKey::from_slice(&PUBKEY).unwrap();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let msg = format!("{}{}{}", ts, "GET", "/verify");
        let msg = Sha256::digest(&msg.as_bytes());
        let msg = Message::from_slice(&msg).unwrap();

        let seckey = SecretKey::from_slice(&SECKEY).unwrap();
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(&msg, &seckey).serialize_compact();
        let sign = base64::encode(signature);

        println!("{}", pubkey);
        println!("{}", sign);
        println!("{}", ts);
    }
}
