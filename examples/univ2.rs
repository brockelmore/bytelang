
use bytelang::{common::fn_sig, *};
use hex_literal::hex;

fn main() {

    let calldata_loader = OpChunk::calldataloader();

    let s: Selector<4> = Selector{};
    let selector = s.selector();

    let funcs = vec![
        "swap(uint256,uint256,address,bytes)",
        "mint(address)",
        "burn(address)",
        "getReserves()",
        "token0()",
        "token1()",
        "price0Cumulative()",
        "price1Cumulative()",
        "kLast()",
        "factory()",
        "MINIMUM_LIQUIDITY()",
    ];
    let lookup_table = s.lookup_table(funcs);

    let swap = OpChunk::new("swap(uint256,uint256,address,bytes)")
        .pop()  // pop off selector
        .push1(0x24)
        .mload() // load amount1
        .dup1()
        .iszero()
        .push1(0x04)
        .mload() // load amount0
        .dup1()
        .iszero()
        .swap1()
        .swap2()
        .or()
        .jumpi_named_block("insufficient_out")
        .jump_named_block_and_continue("getReservesInternal")
        .push1(0x01) // token0
        .sload()
        .dup1()      // [tok0, tok0]
        .push1(0x44)
        .mload()     // [to, tok0, tok0]
        .dup1()      // [to, to, tok0, tok0]
        .push1(0x02)
        .sload()     // [tok1, to, to, tok0, tok0]
        .dup1()      // [tok1, tok1, to, to, tok0, tok0]
        .swap5()     // [tok0, tok1, to, to, tok0, tok1]
        .swap3()     // [to, tok1, to, tok0, tok0, tok1]
        .eq()        // [eq, to, tok1, tok0, tok1]
        .swap2()      // [tok1, to, eq, tok0, tok1]
        .eq()        // [eq, eq, tok0, tok1]
        .or()
        .jumpi_named_block("invalid_to") // [tok0, tok1]
        .jump_named_block_and_continue("balance_of") // [loc, tok0, tok1]
        .jump_named_block_and_continue("balance_of") 
        .stop()
        .finish();

    let balance_of = OpChunk::new("balance_of") // [loc, target, ..]
        .swap1() // [target, ret_loc]
        .push1(0x20) // [32, target, ret_loc]
        .address() // [addr, 32, target, ret_loc]
        .finish()
        .then_named(OpChunk::mstore_update_memory_pointer_w_ptrs(), "mstore_update", false) // [old_ptr, new_ptr, 32, target, ret_loc]
        .push1(0x20) // [32, old_ptr, new_ptr, 32, target, ret_loc]
        .swap1() // [old_ptr, 32, new_ptr, 32, target, ret_loc]
        .dup4() // [target, old_ptr, 32, new_ptr, 32, target, ret_loc]
        .gas() // [gas, target, old_ptr, 32, new_ptr, 32, target, ret_loc]
        .staticcall() // [bool, target, ret_loc]
        .swap2()
        .jump()
        .finish_with_name("balance_of");


    let mint = OpChunk::new("mint(address)")
        .push1(0x02)
        .stop()
        .finish();

    let burn = OpChunk::new("burn(address)")
        .push1(0x02)
        .stop()
        .finish();

    let getReservesInternal = OpChunk::new("getReservesInternal")
        .push1(0x00)
        .sload()
        .dup1()
        .push1(0x70)
        .shl()
        .push1(0x90)
        .shr()
        .swap1()
        .push1(0x90)
        .shr()
        .swap2()
        .jump()
        .finish();

    let getReserves = OpChunk::new("getReserves()")
        .stop()
        .finish();

    let token0 = OpChunk::new("token0()")
        .push1(0x02)
        .stop()
        .finish();

    let token1 = OpChunk::new("token1()")
        .push1(0x02)
        .stop()
        .finish();

    let price0Cumulative = OpChunk::new("price0Cumulative()")
        .push1(0x02)
        .stop()
        .finish();

    let price1Cumulative = OpChunk::new("price1Cumulative()")
        .push1(0x02)
        .stop()
        .finish();

    let kLast = OpChunk::new("kLast()")
        .push1(0x02)
        .stop()
        .finish();

    let factory = OpChunk::new("factory()")
        .push1(0x02)
        .stop()
        .finish();

    let min_liq = OpChunk::new("MINIMUM_LIQUIDITY()")
        .push1(0x02)
        .stop()
        .finish();

    let insufficient_out = OpChunk::reverter("insufficient_out", "INSUFFICIENT_OUTPUT_AMOUNT");
    let invalid_to = OpChunk::reverter("invalid_to", "INVALID_TO");
    let mut setup = calldata_loader
        .then(selector, false)
        .then(lookup_table, false)
        .then(swap, true)
        .then(mint, true)
        .then(burn, true)
        .then(getReserves, true)
        .then(token0, true)
        .then(token1, true)
        .then(price0Cumulative, true)
        .then(price1Cumulative, true)
        .then(kLast, true)
        .then(factory, true)
        .then(min_liq, true)
        .then(insufficient_out, true)
        .then(invalid_to, true)
        .then(getReservesInternal, true)
        .then(balance_of, true);

    let setup = setup.finish();
    println!("{:#?}", setup);
    let code = format!("0x{}", hex::encode(setup.inner.clone()));
    println!("{}\n{}",
    code.clone(), std::str::from_utf8(&std::process::Command::new("disease")
        .arg("--code")
        .arg(code)
        .output()
        .expect("failed to execute process")
        .stdout[..]).unwrap());
}
