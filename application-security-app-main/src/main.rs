use axum::{
    extract::Form,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post, Router},
};
use askama::Template;
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::io;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{BufReader};
use tower::{service_fn, ServiceExt}; // Use service_fn from tower

fn hash_with_salt(s: &str) -> String {
    let salt_path = "./src/salt.txt";
    let salt = fs::read_to_string(salt_path).expect("Should be able to read salt file");
    assert_eq!(
        sha256::digest(&salt),
        "f83c8dbbf9f0d2ecb84fdaf3c9a6e80948fc576a44a7c61c116f7231c1e606cd"
    );
    let password_and_salt = s.to_string() + &salt;
    sha256::digest(password_and_salt.to_string())
}

#[derive(Debug, Clone)]
pub struct PasswordError;

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Password too weak.")
    }
}

pub struct Password {
    hash: String,
}

impl Password {
    pub fn set(password: &str) -> Result<Self, PasswordError> {
        if password.len() > 8
            && password.chars().any(|c| c.is_uppercase())
            && password.chars().any(|c| c.is_lowercase())
            && password.chars().any(|c| c.is_digit(10))
            && !password.chars().all(char::is_alphanumeric)
        {
            Ok(Password {
                hash: hash_with_salt(password),
            })
        } else {
            Err(PasswordError)
        }
    }

    pub fn get_hash(self) -> String {
        self.hash
    }
}

#[derive(Template, Default)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    username: &'a str,
    password: &'a str,
    error_message: &'a str,
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    username: &'a str,
}

fn render_template(template: impl Template) -> Response {
    match template.render() {
        Ok(rendered) => Html(rendered).into_response(),
        Err(e) => {
            eprintln!("Failed to render template: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn welcome() -> Response {
    let template = LoginTemplate::default();
    render_template(template)
}

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

async fn login(fields: Form<User>) -> Response {
    let password_checked = Password::set(&fields.password);
    if !fields.username.is_empty() && password_checked.is_ok() {
        println!(
            "Log in success! \nUser:{}\nPassword:{}",
            &fields.username,
            &fields.password
        );
        let template: HomeTemplate<'_> = HomeTemplate {
            username: &fields.username,
        };
        return render_template(template);
    } else {
        println!(
            "Log in failed! \nUser:{}\nPassword:{}",
            &fields.username,
            &fields.password
        );
        let template = LoginTemplate {
            username: &fields.username,
            password: "",
            error_message: "Invalid credentials!",
        };
        return render_template(template);
    }
}

async fn run_tls_server() -> io::Result<()> {
    // Load the certificate
    let certs = {
        let cert_file = &mut BufReader::new(File::open("localhost.crt").expect("Could not open cert file"));
        certs(cert_file).expect("Could not load certs")
    };

    // Load the RSA private key
    let key = {
        let key_file = &mut BufReader::new(File::open("localhost.key").expect("Could not open key file"));
        let keys = pkcs8_private_keys(key_file).expect("Could not load private keys");

        if keys.is_empty() {
            panic!("No private keys found in the key file.");
        }

        keys[0].clone() // Get the first private key
    };

    // Create TLS config with the loaded cert and key
    let mut config = ServerConfig::new(rustls::NoClientAuth::new());
    config
        .set_single_cert(certs, key)
        .expect("Invalid key or certificate");

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let router = Router::new()
        .route("/", get(welcome))
        .route("/", post(login));

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Listening on https://{}", listener.local_addr()?);

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone(); // clone the router for each connection

        tokio::spawn(async move {
            // Accept the incoming stream as a TLS connection
            let stream = acceptor.accept(stream).await.expect("TLS error");

            // Use the router to handle requests
            let service = service_fn(move |conn| {
                let router = router.clone();
                async move { router.clone().oneshot(conn).await }
            });

            // Serve the incoming request
            if let Err(e) = hyper::server::conn::Http::new().serve_connection(stream, service).await {
                eprintln!("Error serving connection: {:?}", e);
            }
        });
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    run_tls_server().await
}