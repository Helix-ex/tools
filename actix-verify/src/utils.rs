use actix_web::HttpRequest;

use super::*;

// verification function
pub async fn verify_sig(request: &HttpRequest) -> bool {
    // Getting the public from headers
    let hm_key = match request.headers().get("HM-KEY") {
        Some(pk) => {
            info!("{:?}", pk);
            pk.to_str().unwrap()
        }
        None => {
            error!("Public Key not Found");
            return false;
        }
    };

    // Taking the signature from headers
    let hm_sign = match request.headers().get("HM-SIGN") {
        Some(sign) => sign.to_str().unwrap(),
        None => {
            error!("Missing Signature");
            return false;
        }
    };

    // Decoding the timestamp from headers.
    let ts = match request.headers().get("HM-TS") {
        Some(timestamp) => timestamp.to_str().unwrap().parse::<u128>().unwrap(),
        None => {
            error!("Missing timestamp in Headers");
            return false;
        }
    };

    // Extracting the public
    let public_key = PublicKey::from_slice(&hex::decode(hm_key).unwrap()).unwrap();
    info!("Public key  found {}", public_key);
    // Extract signature from string
    let signature = Signature::from_compact(&base64::decode(hm_sign).unwrap());

    let message = Message::from_slice(
        &Sha256::digest(
            format!(
                "{}{}{}",
                ts,
                request.method().as_str(),
                request.path(),
                // request.query_string()
            )
            .as_bytes(),
        )[..],
    )
    .unwrap();

    // Condition one time should be 5 second old
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    if (current_time - ts) > 5000 {
        return false;
    }

    // Verify the signature.
    let verify = Secp256k1::verification_only();
    match verify.verify_ecdsa(&message, &signature.unwrap(), &public_key) {
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
        let msg = format!("{}{}{}", ts, "GET", "127.0.0.1");
        let msg = Sha256::digest(&msg.as_bytes());
        let msg = Message::from_slice(&msg).unwrap();
        let seckey = SecretKey::from_slice(&SECKEY).unwrap();
        let secp = Secp256k1::new();
        let signature =secp.sign_ecdsa(&msg, &seckey);
        let sign = base64::encode(signature.to_string());

        let req = test::TestRequest::default()
            .insert_header(("HM-KEY", pubkey.to_string()))
            .insert_header(("HM-SIGN", sign))
            .insert_header(("HM-TS", ts))
            .to_http_request();
        let result = verify_sig(&req).await;
        assert_eq!(result, false);
    }
}
