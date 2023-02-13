use actix_web::middleware::Logger;
use actix_web::{web, Error, HttpResponse};
use actix_web::{App, HttpServer};

mod utils;
use dotenv::dotenv;
use log::{error, info};
use utils::*;

#[actix_web::main]
async fn main() -> Result<(), Error> {
    dotenv().ok();
    std::env::set_var("RUST_LOG", "info,warn,error");
    env_logger::init();
    let host = std::env::var("HOST").unwrap();
    let port = std::env::var("PORT").unwrap();

    println!("Server running on {}:{}", host, port);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .route("/", web::get().to(index))
            .route("/verify", web::get().to(verify))
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await?;

    Ok(())
}

pub async fn index() -> HttpResponse {
    HttpResponse::Ok().body("Hello, world!")
}
