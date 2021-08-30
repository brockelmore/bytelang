
use bytelang::{common::fn_sig, *};
use hex_literal::hex;

fn main() {
    let mem_calldataload = OpChunk::new("mem_calldataload")
        // .push2(&hex!("1000")[..])
        // .caller()
        // .sstore()
        // .push2(&hex!("1010")[..])
        // .push32(&hex!("000000000000000000000000b7e390864a90b7b923c9f9310c6f98aafe43f707")[..])
        // .sstore()
        .calldatasize()
        .returndatasize()
        .returndatasize()
        .calldatacopy()
        .finish();

    let memload_calldata = OpChunk::new("memload_calldata")
        .returndatasize()
        .mload()
        .finish();

    let selector = OpChunk::new("selector")
        .push32_pad_right(&hex!("ffffffff")[..])
        .and()
        .push1(0xe0)
        .shr()
        .finish();

    let bad_bal = OpChunk::new("bad_bal")
        .push32_pad_right(&hex!("08c379a0")[..])
        .returndatasize()
        .mstore()
        .push1(0x20)
        .push1(0x05)
        .mstore()
        .push1(0x14)
        .push1(0x25)
        .mstore()
        .push32_pad_right(&hex!("696e73756666696369656e742062616c616e6365")[..])
        .push1(0x45)
        .mstore()
        .push1(0x60)
        .push1(0x00)
        .revert()
        .finish();

    let add_overflow = OpChunk::new("add_overflow")
        .push32_pad_right(&hex!("08c379a0")[..])
        .returndatasize()
        .mstore()
        .push1(0x20)
        .push1(0x05)
        .mstore()
        .push1(0x14)
        .push1(0x25)
        .mstore()
        .push32_pad_right(&hex!("2b6f766572666c6f77")[..])
        .push1(0x45)
        .mstore()
        .push1(0x60)
        .push1(0x00)
        .revert()
        .finish();

    let checked_add = OpChunk::new("checked_add")
        .dup1()
        .swap2()
        .add()
        .swap1()
        .dup2()
        .lt()
        .jumpi_named_block("add_overflow")
        .finish();

    let transfer_func = OpChunk::new("transfer")
        .push1(0x24)
        .mload()
        .caller()
        .sload()
        .dup1()
        .dup3()
        .gt()
        .jumpi_named_block("bad_bal")
        .push1(0x04)
        .mload()
        .dup3()
        .swap1()
        .swap2()
        .sub()
        .caller()
        .sstore()
        .dup1()
        .sload()
        .dup3()
        .finish()
        .then_named(checked_add, "transfer", false)
        .dup2()
        .sstore()
        .caller()
        .push1(0x20)
        .push1(0x24)
        .log2()
        .push1(0x01)
        .push1(0x00)
        .mstore8()
        .push1(0x01)
        .push1(0x00)
        .return_()
        .finish();

    let burn_func = OpChunk::new("burn")
        .push1(0x02)
        .stop()
        .finish();

    let lookup_table = OpChunk::new("lookup_table")
        .dup1()
        .push4(&fn_sig("transfer(address,uint256)"))
        .eq()
        .jumpi_named_block("transfer")
        .push4(&fn_sig("_burn(address,bytes32,uint256)"))
        .eq()
        .jumpi_named_block("burn")
        .finish();

    // println!("{:#?}, {:?}", hex::encode(transfer_func.inner.clone()), transfer_func.inner.clone());
    // println!("{:#?}\n{:#?}\n{:#?}\n{:#?}\n{:#?}", mem_calldataload, memload_calldata, selector, lookup_table, transfer_func);
    let setup = mem_calldataload
        .then(memload_calldata, false)
        .then(selector, false)
        .then(lookup_table, false)
        .then(transfer_func, true)
        .then(burn_func, true)
        .then(bad_bal, true)
        .then(add_overflow, true)
        .finish();
    // println!("\n{:#?}", setup);
    // println!("{:#?}\n{:#?}", hex::encode(setup.inner.clone()), setup);
    println!("{:?}", hex::encode(setup.inner.clone()));
}
