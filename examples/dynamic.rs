
use bytelang::{common::fn_sig, *};
use hex_literal::hex;

fn main() {

    let calldata_loader = OpChunk::calldataloader();

    let s: Selector<1> = Selector{};
    let selector = s.selector();

    let funcs = vec!["arb_uni_sushi", "arb_sushi_uni"];
    let lookup_table = s.lookup_table(funcs);

    let arb_uni_sushi = OpChunk::new("arb_uni_sushi")
        .push1(0x01)
        .stop()
        .finish();

    let arb_sushi_uni = OpChunk::new("arb_sushi_uni")
        .push1(0x02)
        .stop()
        .finish();

    let setup = calldata_loader
        .then(selector, false)
        .then(lookup_table, false)
        .then(arb_uni_sushi, true)
        .then(arb_sushi_uni, true)
        .finish();

    let code = format!("0x{}", hex::encode(setup.inner.clone()));
    println!("{}", std::str::from_utf8(&std::process::Command::new("disease")
        .arg("--code")
        .arg(code)
        .output()
        .expect("failed to execute process")
        .stdout[..]).unwrap());
}
