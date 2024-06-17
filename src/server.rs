//! Default Compute template program.

use std::cell::OnceCell;

use fastly::{
    http::{header, Method, StatusCode},
    secret_store::OpenError,
    Request, Response, SecretStore,
};
use rand::thread_rng;
use typenum::marker_traits::Unsigned;
use voprf::{BlindedElement, BlindedElementLen, ProofLen, VoprfServer, VoprfServerEvaluateResult};

type CipherSuite = voprf::Ristretto255;
type Server = voprf::VoprfServer<CipherSuite>;

const SECRET_STORE: &str = "voprf-secrets";
const SECRET_NAME: &str = "seed";
const SERVER_INFO: &[u8] = b"voprf-server";

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("missing secret ({SECRET_NAME}) from store")]
    Secret,
    #[error("secret store could not be opened: {0}")]
    SecretStore(#[from] OpenError),
    #[error("VOPRF error: {0}")]
    Voprf(#[from] voprf::Error),
}

impl From<Error> for Response {
    fn from(value: Error) -> Self {
        // The only errors that arise are from bad requests.
        Response::from_status(StatusCode::BAD_REQUEST).with_body_text_plain(&format!("{value}"))
    }
}

fn init_server() -> Result<Server, Error> {
    let store = SecretStore::open(SECRET_STORE)?;
    let secret = store.get(SECRET_NAME).ok_or(Error::Secret)?;
    let server = VoprfServer::new_from_seed(&secret.plaintext(), SERVER_INFO)?;
    println!("Server created");
    Ok(server)
}

fn with_server<F, T>(f: F) -> T
where
    F: FnOnce(&Server) -> T,
{
    thread_local! { static SERVER: OnceCell<Server> = const { OnceCell::new() } };

    SERVER.with(|server| {
        f(server.get_or_init(|| {
            init_server().unwrap_or_else(|e| {
                panic!("Unable to initialize VOPRF server: {e}");
            })
        }))
    })
}

fn evaluate(input: &BlindedElement<CipherSuite>) -> VoprfServerEvaluateResult<CipherSuite> {
    with_server(|server| server.blind_evaluate(&mut thread_rng(), input))
}

fn pubkey() -> Vec<u8> {
    let pk = with_server(voprf::VoprfServer::get_public_key);
    <<CipherSuite as voprf::CipherSuite>::Group as voprf::Group>::serialize_elem(pk).to_vec()
}

fn voprf(input: &[u8]) -> Result<Vec<u8>, Error> {
    const RESPONSE_LEN: usize =
        BlindedElementLen::<CipherSuite>::USIZE + ProofLen::<CipherSuite>::USIZE;

    let element = BlindedElement::<CipherSuite>::deserialize(input)?;
    let result = evaluate(&element);

    let mut response = Vec::with_capacity(RESPONSE_LEN);
    response.extend(result.message.serialize());
    response.extend(result.proof.serialize());

    Ok(response)
}

fn check_method(request: &Request, m: &Method) -> Option<Response> {
    (request.get_method() != m).then(|| {
        Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(header::ALLOW, m.as_str())
            .with_body_text_plain("Invalid method for resource\n")
    })
}

fn main() {
    let mut request = fastly::Request::from_client();
    let response = if request.get_path() == "/voprf" {
        check_method(&request, &Method::POST).unwrap_or_else(|| {
            match voprf(&request.take_body().into_bytes()) {
                Ok(r) => Response::from_status(StatusCode::OK).with_body_octet_stream(&r),
                Err(e) => Response::from(e),
            }
        })
    } else if request.get_path() == "/pubkey" {
        check_method(&request, &Method::GET).unwrap_or_else(|| {
            Response::from_status(StatusCode::OK).with_body_octet_stream(&pubkey())
        })
    } else {
        Response::from_status(StatusCode::NOT_FOUND)
            .with_body_text_plain(r#"This service only operates at "/voprf" and "/pubkey"\n"#)
    };
    response.send_to_client();
}
