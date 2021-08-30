use std::collections::{BTreeSet, BTreeMap};
pub mod opcode;
pub mod properties;
pub mod common;

use common::*;
use opcode::OpCode;
use properties::*;
use hex_literal::hex;

pub struct Selector<const N: usize> {}

impl<const N: usize> Selector<N> {
    pub fn selector(&self) -> OpChunk {
        let mut t = "".to_string();
        for i in 0..N {
            t = t + "ff";
        }
        let shift = 256 - N*8;
        OpChunk::new("selector")
            .push32_pad_right(&hex::decode(t).unwrap())
            .and()
            .push1(shift as u8)
            .shr()
            .finish()
    }

    pub fn lookup_table(&self, funcs: Vec<&str>) -> OpChunk {
        if N < 4 {
            let mut op = OpChunk::new("lookup_table");
            for i in 0..(funcs.len() - 1) {
                op = op.dup1()
                    .push_n(N, &[(i + 1) as u8; N][..])
                    .eq()
                    .jumpi_named_block(&funcs[i])
                    .finish();
            }
            op.push_n(N, &[funcs.len() as u8; N][..])
                .eq()
                .jumpi_named_block(&funcs[funcs.len() - 1])
                .finish()
        } else {
            let mut op = OpChunk::new("lookup_table");
            for i in 0..(funcs.len() - 1) {
                op = op.dup1()
                    .push4(&fn_sig(&funcs[i]))
                    .eq()
                    .jumpi_named_block(&funcs[i])
                    .finish();
            }
            op.push4(&fn_sig(&funcs[funcs.len() - 1]))
                .eq()
                .jumpi_named_block(&funcs[funcs.len() - 1])
                .finish()
        }
    }
}

#[derive(Clone, Debug)]
pub enum ChunkError {
    MismatchStackSum(i64, u8)
}

#[derive(Clone, Debug, Default)]
pub struct BasicBlock {
    pub stack_sum: i64,
    pub entry_op_takes: Option<u8>,
    pub has_dest: bool,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Default)]
pub struct OpChunk {
    pub name: String,
    pub inner: Vec<u8>,
    pub inner_blocks: BTreeMap<String, BasicBlock>,
    pub to_find_conditional: BTreeMap<String, Vec<usize>>,
    pub to_find: BTreeMap<String, Vec<usize>>,
    pub to_find_and_continues: BTreeMap<String, Vec<(usize, usize)>>,
    pub height_required: i64,
    pub stack_sum: i64,
    pub entry_op_takes: Option<u8>,
}

impl OpChunk {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    pub fn calldataloader() -> Self {
        OpChunk::new("calldata_loader")
            .calldatasize()
            .returndatasize()
            .push1(0x02)
            .calldatacopy()
            .calldatasize()
            .dup1()
            .push1(0x08)
            .shr()
            .push1(0x00)
            .mstore8()
            .push1(0x01)
            .mstore8()
            .push1(0x02)
            .mload()
            .finish()
    }

    pub fn free_memory_pointer() -> Self {
        OpChunk::new("free_memory_pointer")
            .push1(0x00)
            .mload()
            .push1(0xf0)
            .shr()
            .push1(0x01)
            .add()
            .finish()
    }

    pub fn mstore_update_memory_pointer() -> Self {
        OpChunk::new("mstore_update_free_memory_pointer")
            .then(Self::free_memory_pointer(), false) // [ptr, val]
            .swap1() // [val, ptr]
            .dup2() // [ptr, val, ptr]
            .mstore() // [ptr]
            .push1(0x20)
            .add() // [ptr + 32]
            .dup1() // [ptr+32, ptr+32]
            .push1(0x08) // [8, ptr+32, ptr+32]
            .shr() // [ptr >> 2**3, ptr+32]
            .push1(0x00) // [0, ptr >> 2**3, ptr+32]
            .mstore8()
            .push1(0x01) // [1, ptr+32]
            .mstore8()
            .finish()
    }

    pub fn mstore_update_memory_pointer_w_old_ptr() -> Self {
        OpChunk::new("mstore_update_free_memory_pointer")
            .then(Self::free_memory_pointer(), false) // [ptr, val]
            .dup1() // [ptr, ptr, val]
            .swap2() // [val, ptr, ptr]
            .dup3() // [ptr, val, ptr, ptr]
            .mstore() // [ptr, ptr]
            .push1(0x20)
            .add() // [ptr + 32, ptr]
            .dup1() // [ptr+32, ptr+32, ptr]
            .push1(0x08) // [8, ptr+32, ptr+32, ptr]
            .shr() // [ptr >> 2**3, ptr+32, ptr]
            .push1(0x00) // [0, ptr >> 2**3, ptr+32, ptr]
            .mstore8()
            .push1(0x01) // [1, ptr+32, ptr]
            .mstore8()
            .finish()
    }

    pub fn mstore_update_memory_pointer_w_ptrs() -> Self {
        OpChunk::new("mstore_update_free_memory_pointer")
            .then_named(Self::free_memory_pointer(), "free_ptr", false) // [ptr, val]
            .dup1() // [ptr, ptr, val]
            .swap2() // [val, ptr, ptr]
            .dup3() // [ptr, val, ptr, ptr]
            .mstore() // [ptr, ptr]
            .push1(0x20)
            .add() // [ptr + 32, ptr]
            .dup1() // [ptr+32, ptr+32, ptr]
            .push1(0x08) // [8, ptr+32, ptr+32, ptr]
            .shr() // [ptr >> 2**3, ptr+32, ptr]
            .push1(0x00) // [0, ptr >> 2**3, ptr+32, ptr]
            .mstore8()
            .dup2() // [ptr+32, 1, ptr+32, ptr]
            .swap1() // [1, ptr+32, ptr+32, ptr]
            .push1(0x01) // [1, ptr+32, ptr+32, ptr]
            .mstore8()
            .swap1() // [ptr, ptr+32]
            .finish()
    }

    pub fn reverter(name: &str, error: &str) -> Self {
        assert!(error.as_bytes().len() <= 32, "Error string too long");
        Self::new(name)
            .push32_pad_right(&hex!("08c379a0")[..])
            .returndatasize()
            .mstore()
            .push1(0x20)
            .push1(0x05)
            .mstore()
            .push1(0x14)
            .push1(0x25)
            .mstore()
            .push32_pad_right(error.as_bytes())
            .push1(0x45)
            .mstore()
            .push1(0x60)
            .push1(0x00)
            .revert()
            .finish()
    }

    pub fn finish_with_name(&mut self, name: &str) -> Self {
        let mut new = self.finish();
        new.name = name.to_string();
        new
    }

    pub fn finish(&mut self) -> Self {
        // println!("{:#?}", self);
        let good: Vec<(String, Vec<(usize, usize)>)> = self.to_find_and_continues.iter()
            .filter(|(label, _loc)| {
                self.inner_blocks.contains_key(&**label)
            })
            .map(|(l, loc)| (l.clone(), loc.clone()))
            .collect();
        good.iter().for_each(|(label, locs)| {
                locs.iter().for_each(|(loc, loc1)| {
                    let correct_loc = self.inner_blocks.get(&**label).expect("wut");
                    let bytes = (correct_loc.start - 1).to_le_bytes();
                    println!("{:?}", correct_loc);
                    self.inner[*loc] = bytes[0];
                    self.inner[*loc - 1] = bytes[1];
                    let ret = (loc1 + 5).to_le_bytes();
                    self.inner[*loc1] = ret[0];
                    self.inner[*loc1 - 1] = ret[1];
                })
            });

        let good: Vec<(String, Vec<usize>)> = self.to_find.iter()
            .filter(|(label, _loc)| {
                self.inner_blocks.contains_key(&**label)
            })
            .map(|(l, loc)| (l.clone(), loc.clone()))
            .collect();
        good.iter().for_each(|(label, locs)| {
                locs.iter().for_each(|loc| {
                    let correct_loc = self.inner_blocks.get(&**label).expect("wut");
                    let bytes = (correct_loc.start - 1).to_le_bytes();
                    self.inner[*loc] = bytes[0];
                    self.inner[*loc - 1] = bytes[1];
                });
            });

        let good: Vec<(String, Vec<usize>)> = self.to_find_conditional.iter()
            .filter(|(label, _loc)| {
                self.inner_blocks.contains_key(&**label)
            })
            .map(|(l, loc)| (l.clone(), loc.clone()))
            .collect();
        good.iter().for_each(|(label, locs)| {
                locs.iter().for_each(|loc| {
                    let correct_loc = self.inner_blocks.get(&**label).expect("wut");
                    let bytes = (correct_loc.start - 1).to_le_bytes();
                    self.inner[*loc] = bytes[0];
                    self.inner[*loc - 1] = bytes[1];
                });
            });
        // println!("{:?}", self.inner);
        self.clone()
    }

    pub fn then(self, other: Self, as_jump_dest: bool) -> Self {
        let name = format!("{}=>{}", self.name, other.name);
        self.then_named(other, &name, as_jump_dest)
    }

    pub fn then_named(mut self, mut other: Self, block_name: &str, as_jump_dest: bool) -> Self {
        // println!("{}:\n{:?}",block_name, self.inner);

        if as_jump_dest {
            self.jumpdest();
        }
        let inner_end = self.inner.len() as u64;
        other.inner_blocks.iter_mut().for_each(|(_name, named_block)| {
            named_block.start += inner_end;
            named_block.end += inner_end;
        });
        // println!("{:#?}", other.to_find_conditional);
        other.to_find_and_continues.iter_mut().for_each(|(_name, locs)| {
            locs.into_iter().for_each(|(loc, loc1)| {
                *loc = *loc + inner_end as usize;
                *loc1 = *loc1 + inner_end as usize;
            });
        });
        other.to_find.iter_mut().for_each(|(_name, locs)| {
            locs.into_iter().for_each(|loc| {
                *loc = *loc + inner_end as usize;
            })
        });
        other.to_find_conditional.iter_mut().for_each(|(_name, locs)| {
            locs.into_iter().for_each(|loc| {
                *loc = *loc + inner_end as usize;
            });
        });
        // println!("{:#?}", other.to_find_conditional);
        self.inner_blocks.extend(other.inner_blocks);
        self.inner_blocks.insert(other.name.clone(), BasicBlock {
            has_dest: as_jump_dest,
            entry_op_takes: other.entry_op_takes,
            start: inner_end,
            end: inner_end + other.inner.len() as u64,
            stack_sum: other.stack_sum
        });
        self.inner.extend(other.inner);
        let height_required;
        if self.height_required > other.height_required {
            height_required = self.height_required;
        } else {
            height_required = other.height_required;
        }
        self.to_find.extend(other.to_find);
        self.to_find_and_continues.extend(other.to_find_and_continues);
        self.to_find_conditional.extend(other.to_find_conditional);
        // println!("{}:\n{:?}",block_name, self.inner);
        Self {
            name: block_name.to_string(),
            inner: self.inner,
            stack_sum: self.stack_sum + other.stack_sum,
            inner_blocks: self.inner_blocks,
            entry_op_takes: self.entry_op_takes,
            to_find: self.to_find,
            to_find_conditional: self.to_find_conditional,
            to_find_and_continues: self.to_find_and_continues,
            height_required,
        }
    }

    pub fn jump_named_block<'a>(&'a mut self, name: &str) -> &'a mut Self {
        self.push2(&[0,0][..]);
        if let Some(to_finds) = self.to_find.get_mut(name) {
            to_finds.push(self.inner.len() - 1);
        } else {
            self.to_find.insert(name.to_string(), vec![self.inner.len() - 1]);
        }
        self.jump();
        self
    }

    pub fn jump_named_block_and_continue<'a>(&'a mut self, name: &str) -> &'a mut Self {
        self.push2(&[0,0][..]);
        self.push2(&[0,0][..]);
        if let Some(to_finds) = self.to_find_and_continues.get_mut(name) {
            to_finds.push((self.inner.len() - 1, self.inner.len() - 4));
        } else {
            self.to_find_and_continues.insert(name.to_string(), vec![(self.inner.len() - 1, self.inner.len() - 4)]);
        }
        self.jump();
        self.jumpdest();
        self
    }

    pub fn jumpi_named_block<'a>(&'a mut self, name: &str) -> &'a mut Self {
        self.push2(&[0,0][..]);
        if let Some(to_finds) = self.to_find_conditional.get_mut(name) {
            to_finds.push(self.inner.len() - 1);
        } else {
            self.to_find_conditional.insert(name.to_string(), vec![self.inner.len() - 1]);
        }

        self.jumpi();
        self
    }

    pub fn stop<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::STOP;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn add<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::ADD;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn mul<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::MUL;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn sub<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SUB;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn div<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DIV;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn sdiv<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SDIV;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn mod_<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::MOD;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn smod<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SMOD;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn addmod<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::ADDMOD;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn mulmod<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::MULMOD;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn exp<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::EXP;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn signextend<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SIGNEXTEND;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn lt<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::LT;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn gt<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::GT;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn slt<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SLT;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn sgt<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SGT;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn eq<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::EQ;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn iszero<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::ISZERO;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn and<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::AND;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }

        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn or<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::OR;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn xor<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::XOR;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn not<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::NOT;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn byte<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::BYTE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn shl<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SHL;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn shr<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SHR;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn sar<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SAR;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn keccak256<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::KECCAK256;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn address<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::ADDRESS;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn balance<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::BALANCE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn origin<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::ORIGIN;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn caller<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CALLER;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn callvalue<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CALLVALUE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn calldataload<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CALLDATALOAD;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn calldatasize<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CALLDATASIZE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn calldatacopy<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CALLDATACOPY;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn codesize<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CODESIZE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn codecopy<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CODECOPY;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn gasprice<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::GASPRICE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn extcodesize<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::EXTCODESIZE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn extcodecopy<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::EXTCODECOPY;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn returndatasize<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::RETURNDATASIZE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn returndatacopy<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::RETURNDATACOPY;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn extcodehash<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::EXTCODEHASH;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn blockhash<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::BLOCKHASH;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn coinbase<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::COINBASE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn timestamp<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::TIMESTAMP;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn number<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::NUMBER;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn difficulty<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DIFFICULTY;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn gaslimit<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::GASLIMIT;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn chainid<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CHAINID;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn selfbalance<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SELFBALANCE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn basefee<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::BASEFEE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn pop<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::POP;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn mload<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::MLOAD;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn mstore<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::MSTORE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn mstore8<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::MSTORE8;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn sload<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SLOAD;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn sstore<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SSTORE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn jump<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::JUMP;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn jumpi<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::JUMPI;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn pc<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::PC;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn msize<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::MSIZE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn gas<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::GAS;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn jumpdest<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::JUMPDEST;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn push_n<'a>(&'a mut self, n: usize, data: &[u8]) -> &'a mut Self {
        let op = match n {
            1 => OpCode::PUSH1,
            2 => OpCode::PUSH2,
            3 => OpCode::PUSH3,
            4 => OpCode::PUSH4,
            5 => OpCode::PUSH5,
            6 => OpCode::PUSH6,
            7 => OpCode::PUSH7,
            8 => OpCode::PUSH8,
            9 => OpCode::PUSH9,
            10 => OpCode::PUSH10,
            11 => OpCode::PUSH11,
            12 => OpCode::PUSH12,
            13 => OpCode::PUSH13,
            14 => OpCode::PUSH14,
            15 => OpCode::PUSH15,
            16 => OpCode::PUSH16,
            17 => OpCode::PUSH17,
            18 => OpCode::PUSH18,
            19 => OpCode::PUSH19,
            20 => OpCode::PUSH20,
            21 => OpCode::PUSH21,
            22 => OpCode::PUSH22,
            23 => OpCode::PUSH23,
            24 => OpCode::PUSH24,
            25 => OpCode::PUSH25,
            26 => OpCode::PUSH26,
            27 => OpCode::PUSH27,
            28 => OpCode::PUSH28,
            29 => OpCode::PUSH29,
            30 => OpCode::PUSH30,
            31 => OpCode::PUSH31,
            32 => OpCode::PUSH32,
            _ => panic!("unsupported N for dynamic push")
        };

        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push1<'a>(&'a mut self, data: u8) -> &'a mut Self {
        let op = OpCode::PUSH1;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.push(data);
        self
    }
    pub fn push2<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 2usize, "data length expected: h2, got {} bytes", data.len());
        let op = OpCode::PUSH2;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push3<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 3usize, "data length expected: h3, got {} bytes", data.len());
        let op = OpCode::PUSH3;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push4<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 4usize, "data length expected: h4, got {} bytes", data.len());
        let op = OpCode::PUSH4;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push5<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 5usize, "data length expected: h5, got {} bytes", data.len());
        let op = OpCode::PUSH5;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push6<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 6usize, "data length expected: h6, got {} bytes", data.len());
        let op = OpCode::PUSH6;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push7<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 7usize, "data length expected: h7, got {} bytes", data.len());
        let op = OpCode::PUSH7;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push8<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 8usize, "data length expected: h8, got {} bytes", data.len());
        let op = OpCode::PUSH8;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push9<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 9usize, "data length expected: h9, got {} bytes", data.len());
        let op = OpCode::PUSH9;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push10<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 10usize, "data length expected: 10, got {} bytes", data.len());
        let op = OpCode::PUSH10;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push11<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 11usize, "data length expected: 11, got {} bytes", data.len());
        let op = OpCode::PUSH11;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push12<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 12usize, "data length expected: 12, got {} bytes", data.len());
        let op = OpCode::PUSH12;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push13<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 13usize, "data length expected: 13, got {} bytes", data.len());
        let op = OpCode::PUSH13;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push14<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 14usize, "data length expected: 14, got {} bytes", data.len());
        let op = OpCode::PUSH14;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push15<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 15usize, "data length expected: 15, got {} bytes", data.len());
        let op = OpCode::PUSH15;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push16<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 16usize, "data length expected: 16, got {} bytes", data.len());
        let op = OpCode::PUSH16;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push17<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 17usize, "data length expected: 17, got {} bytes", data.len());
        let op = OpCode::PUSH17;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push18<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 18usize, "data length expected: 18, got {} bytes", data.len());
        let op = OpCode::PUSH18;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push19<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 19usize, "data length expected: 19, got {} bytes", data.len());
        let op = OpCode::PUSH19;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push20<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 20usize, "data length expected: 20, got {} bytes", data.len());
        let op = OpCode::PUSH20;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push21<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 21usize, "data length expected: 21, got {} bytes", data.len());
        let op = OpCode::PUSH21;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push22<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 22usize, "data length expected: 22, got {} bytes", data.len());
        let op = OpCode::PUSH22;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push23<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 23usize, "data length expected: 23, got {} bytes", data.len());
        let op = OpCode::PUSH23;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push24<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 24usize, "data length expected: 24, got {} bytes", data.len());
        let op = OpCode::PUSH24;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push25<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 25usize, "data length expected: 25, got {} bytes", data.len());
        let op = OpCode::PUSH25;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push26<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 26usize, "data length expected: 26, got {} bytes", data.len());
        let op = OpCode::PUSH26;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push27<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 27usize, "data length expected: 27, got {} bytes", data.len());
        let op = OpCode::PUSH27;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push28<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 28usize, "data length expected: 28, got {} bytes", data.len());
        let op = OpCode::PUSH28;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push29<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 29usize, "data length expected: 29, got {} bytes", data.len());
        let op = OpCode::PUSH29;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push30<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 30usize, "data length expected: 30, got {} bytes", data.len());
        let op = OpCode::PUSH30;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push31<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 31usize, "data length expected: 31, got {} bytes", data.len());
        let op = OpCode::PUSH31;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push32<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        assert!(data.len() == 32usize, "data length expected: 32, got {} bytes", data.len());
        let op = OpCode::PUSH32;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data);
        self
    }
    pub fn push32_pad_right<'a>(&'a mut self, data: &[u8]) -> &'a mut Self {
        let mut data_new = [0u8; 32];
        let mut copy = data.to_vec();
        data_new[..data.len()].swap_with_slice(&mut copy);
        let op = OpCode::PUSH32;
        let props = PROPERTIES[op.to_usize()].unwrap();
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self.inner.extend(data_new);
        self
    }
    pub fn dup1<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP1;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup2<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP2;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup3<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP3;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup4<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP4;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup5<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP5;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup6<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP6;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup7<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP7;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup8<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP8;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup9<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP9;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup10<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP10;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup11<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP11;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup12<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP12;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup13<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP13;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup14<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP14;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup15<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP15;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn dup16<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DUP16;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap1<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP1;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap2<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP2;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap3<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP3;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap4<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP4;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap5<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP5;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap6<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP6;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap7<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP7;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap8<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP8;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap9<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP9;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap10<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP10;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap11<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP11;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap12<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP12;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap13<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP13;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap14<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP14;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap15<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP15;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn swap16<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SWAP16;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn log0<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::LOG0;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn log1<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::LOG1;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn log2<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::LOG2;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn log3<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::LOG3;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn log4<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::LOG4;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn create<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CREATE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn call<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CALL;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn callcode<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CALLCODE;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn return_<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::RETURN;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn delegatecall<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::DELEGATECALL;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn create2<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::CREATE2;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn staticcall<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::STATICCALL;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn revert<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::REVERT;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn invalid<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::INVALID;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
    pub fn selfdestruct<'a>(&'a mut self) -> &'a mut Self {
        let op = OpCode::SELFDESTRUCT;
        let props = PROPERTIES[op.to_usize()].unwrap();
        if self.entry_op_takes == None {
                self.entry_op_takes = Some(props.stack_height_required);
        }
        //assert!(self.stack_sum > props.stack_height_required.into(), "stack underflow @ {}", props.name);
        self.stack_sum = self.stack_sum - props.stack_height_required as i64;
        if self.stack_sum <= self.height_required {
                self.height_required = self.stack_sum.abs();
        }
        self.stack_sum =  self.stack_sum + props.stack_height_required as i64 + props.stack_height_change as i64;

        self.inner.push(op.to_u8());
        self
    }
}
