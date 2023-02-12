use actix_web::middleware::Logger;
use actix_web::{web, Error, HttpResponse};
use actix_web::{App, HttpServer};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
mod utils;
use utils::*;
use log::{error, info};

#[actix_web::main]
async fn main() -> Result<(), Error> {
    std::env::set_var("RUST_LOG", "info,warn,error");
    env_logger::init();

    println!("Server running on 127.0.0.1:8080");
    HttpServer::new(move || App::new()
        .wrap(Logger::default())
        .route("/", web::get().to(index))
        .route("/verify", web::get().to(verify))
        )
        .bind("0.0.0.0:8080")?
        .run()
        .await?;

    Ok(())
}

pub async fn index() -> HttpResponse {
    info!("Index Called");
    HttpResponse::Ok().body("Hello, world!")
}

