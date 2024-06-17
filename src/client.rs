use std::io::{self, Read, Write};

use rand::thread_rng;
use reqwest::blocking::Client;
use typenum::marker_traits::Unsigned;
use voprf::{
    EvaluationElement, EvaluationElementLen, Proof, ProofLen, VoprfClient, VoprfClientBlindResult,
};

type CipherSuite = voprf::Ristretto255;
type Group = <CipherSuite as voprf::CipherSuite>::Group;
type PublicKey = <Group as voprf::Group>::Elem;

fn main() {
    const CUTPOINT: usize = EvaluationElementLen::<CipherSuite>::USIZE;
    const RESPONSE_LEN: usize = CUTPOINT + ProofLen::<CipherSuite>::USIZE;

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let url = args.first().expect("need a base URL for the server");
    let client = Client::new();

    let public_key = get_pubkey(&client, url);

    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .expect("read input from stdin");

    let VoprfClientBlindResult { state, message } =
        VoprfClient::<CipherSuite>::blind(&input, &mut thread_rng())
            .expect("client blinding error");

    let response = client
        .post(format!("{url}voprf"))
        .body(message.serialize().as_slice().to_vec())
        .send()
        .expect("voprf error")
        .bytes()
        .expect("error gathering voprf bytes");
    assert_eq!(response.len(), RESPONSE_LEN, "invalid response length");

    let element = EvaluationElement::<CipherSuite>::deserialize(&response[..CUTPOINT])
        .expect("failed to deserialize evaluated element");
    let proof = Proof::<CipherSuite>::deserialize(&response[CUTPOINT..])
        .expect("failed to deserialize proof");

    let output = state
        .finalize(&input, &element, &proof, public_key)
        .expect("finalize failed")
        .to_vec();

    io::stdout().write_all(&output).expect("write error");
}

fn get_pubkey(client: &Client, url: &str) -> PublicKey {
    let bytes = client
        .get(format!("{url}pubkey"))
        .send()
        .expect("public key error")
        .bytes()
        .expect("error gathering public key");
    <Group as voprf::Group>::deserialize_elem(&bytes).expect("invalid public key")
}
