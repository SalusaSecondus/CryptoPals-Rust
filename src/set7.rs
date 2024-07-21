use std::{collections::HashMap, fmt::Display, sync::mpsc::channel, vec};

use hex::ToHex;
use lazy_static::lazy_static;
use num_traits::ToPrimitive;

use crate::{
    aes::AesKey,
    digest::{to_w32_be, Digest, DigestOneShot, MD4},
    padding::Padding,
    BitArray,
};
use anyhow::{ensure, Context, Result};
use itertools::Itertools;
use rand::RngCore;
use rand_core::OsRng;
use workerpool::{
    thunk::{Thunk, ThunkWorker},
    Pool,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RD0 {
    initial: [u8; 2],
    state: [u8; 2],
    length: usize,
    buffer: Option<Vec<u8>>,
}

impl RD0 {
    fn compress(old_state: &[u8], block: &[u8]) -> Vec<u8> {
        let mut key = vec![];
        key.extend_from_slice(old_state);
        key.resize(16, 0);
        let aes = AesKey::new(&key).unwrap();
        let mut long_state = aes.encrypt_block(block);
        long_state.resize(Self::digest_size(), 0);
        long_state
        // vec![0u8; 2]
    }
}

impl Digest for RD0 {
    fn reset(&mut self) {
        self.state = self.initial;
        self.length = 0;
    }

    fn update(&mut self, input: &[u8]) {
        let mut merged = self.buffer.take().unwrap_or_default();
        merged.extend(input);
        for block in merged.chunks(Self::block_size()) {
            if block.len() != Self::block_size() {
                self.buffer = Some(block.to_owned());
            } else {
                let new_state = Self::compress(&self.state, block);
                self.state.copy_from_slice(&new_state);
            }
        }
        self.length += input.len();
    }

    fn digest(&mut self) -> Vec<u8> {
        let encoded_length = self.length.to_u64().unwrap().to_be_bytes();
        self.update(&encoded_length);
        let remaining = self.buffer.take().unwrap_or_default();
        let padded = Padding::Pkcs7Padding(Self::block_size())
            .pad(&remaining)
            .unwrap();
        let result = Self::compress(&self.state, &padded);
        self.reset();
        result
    }

    fn digest_size() -> usize {
        2
    }

    fn block_size() -> usize {
        16
    }

    fn oid() -> Option<&'static asn1::ObjectIdentifier<'static>> {
        None
    }
}

impl Display for RD0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.state.encode_hex::<String>())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RD1 {
    initial: [u8; 4],
    state: [u8; 4],
    length: usize,
    buffer: Option<Vec<u8>>,
}

impl RD1 {
    fn compress(old_state: &[u8], block: &[u8]) -> Vec<u8> {
        let mut key = vec![];
        key.extend_from_slice(old_state);
        key.resize(16, 0);
        let aes = AesKey::new(&key).unwrap();
        let mut long_state = aes.encrypt_block(block);
        long_state.resize(Self::digest_size(), 0);
        long_state
        // vec![0u8; 2]
    }
}

impl Digest for RD1 {
    fn reset(&mut self) {
        self.state = self.initial;
        self.length = 0;
    }

    fn update(&mut self, input: &[u8]) {
        let mut merged = self.buffer.take().unwrap_or_default();
        merged.extend(input);
        for block in merged.chunks(Self::block_size()) {
            if block.len() != Self::block_size() {
                self.buffer = Some(block.to_owned());
            } else {
                let new_state = Self::compress(&self.state, block);
                self.state.copy_from_slice(&new_state);
            }
        }
        self.length += input.len();
    }

    fn digest(&mut self) -> Vec<u8> {
        let encoded_length = self.length.to_u64().unwrap().to_be_bytes();
        self.update(&encoded_length);
        let remaining = self.buffer.take().unwrap_or_default();
        let padded = Padding::Pkcs7Padding(Self::block_size())
            .pad(&remaining)
            .unwrap();
        let result = Self::compress(&self.state, &padded);
        self.reset();
        result
    }

    fn digest_size() -> usize {
        4
    }

    fn block_size() -> usize {
        16
    }

    fn oid() -> Option<&'static asn1::ObjectIdentifier<'static>> {
        None
    }
}

impl Display for RD1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.state.encode_hex::<String>())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RD2 {
    rd0: RD0,
    rd1: RD1,
}

impl Digest for RD2 {
    fn reset(&mut self) {
        self.rd0.reset();
        self.rd1.reset();
    }

    fn update(&mut self, input: &[u8]) {
        self.rd0.update(input);
        self.rd1.update(input);
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut result = self.rd0.digest();
        result.extend(self.rd1.digest());
        result
    }

    fn digest_size() -> usize {
        RD0::digest_size() + RD1::digest_size()
    }

    fn block_size() -> usize {
        16
    }

    fn oid() -> Option<&'static asn1::ObjectIdentifier<'static>> {
        None
    }
}

fn find_collision<D>(
    block_size: usize,
    start: &[u8],
    compress: D,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, usize)>
where
    D: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let pool_size = 4;

    let pool: Pool<ThunkWorker<(Vec<u8>, Vec<u8>)>> = Pool::new(pool_size);
    let (tx, rx) = channel();
    let mut rnd = OsRng;
    let mut results: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut count = 0;
    loop {
        for _ in 0..(pool_size * 2) {
            let mut input = vec![0u8; block_size];
            rnd.fill_bytes(&mut input);
            let tmp = start.to_owned();
            pool.execute_to(
                tx.clone(),
                Thunk::of(move || (compress(&tmp, &input), input)),
            );
        }
        for r in rx.iter().take(pool_size * 2) {
            count += 1;
            let output = r.0;
            let input = r.1;
            // println!("Compress({}) = {}", input.encode_hex::<String>(), output.encode_hex::<String>());
            if let Some(collision) = results.get(&output) {
                return Ok((collision.to_owned(), input, output, count));
            } else {
                results.insert(output, input);
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ExpandCollision {
    short: Vec<u8>,
    long: Vec<u8>,
    h_in: Vec<u8>,
    h_out: Vec<u8>,
    compressions: usize,
}

fn find_collision_expand<C>(
    alpha: usize,
    h_in: &[u8],
    block_size: usize,
    compress: C,
) -> Result<ExpandCollision>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let q = vec![0u8; block_size];
    let mut long = vec![0u8; (alpha - 1) * RD1::block_size()];
    let mut h_tmp = h_in.to_owned();
    let mut compressions = 0;
    for _ in 0..(alpha - 1) {
        compressions += 1;
        h_tmp = compress(&h_tmp, &q);
    }

    let mut rng = OsRng;

    let mut a_short: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut b_long: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut block = vec![0u8; block_size];
    loop {
        rng.fill_bytes(&mut block);
        // println!("Trying block: {:?}", block);
        let a_i = compress(h_in, &block);
        compressions += 1;
        let b_i = compress(&h_tmp, &block);
        compressions += 1;

        // println!("a_i = {:?}", a_i);
        // println!("b_i = {:?}", b_i);

        if let Some(old_short) = a_short.get(&b_i) {
            long.extend(&block);
            return Ok(ExpandCollision {
                short: old_short.to_owned(),
                long,
                h_in: h_in.to_owned(),
                h_out: b_i,
                compressions,
            });
        }
        if let Some(old_long) = b_long.get(&a_i) {
            long.extend(old_long);
            return Ok(ExpandCollision {
                short: block,
                long,
                h_in: h_in.to_owned(),
                h_out: a_i,
                compressions,
            });
        }
        if a_i == b_i {
            long.extend(&block);
            return Ok(ExpandCollision {
                short: block,
                long,
                h_in: h_in.to_owned(),
                h_out: b_i,
                compressions,
            });
        }
        a_short.insert(a_i, block.clone());
        b_long.insert(b_i, block.clone());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ExpandableMessage {
    h_out: Vec<u8>,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    compressions: usize,
}

fn make_expandable_message<C>(
    h_in: &[u8],
    k: usize,
    block_size: usize,
    compress: C,
) -> Result<ExpandableMessage>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut h_tmp = h_in.to_owned();
    let mut pairs = vec![(vec![], vec![]); k];

    let mut compressions = 0;
    for i in (0..=(k - 1)).rev() {
        let alpha = (1 << i) + 1;
        let step = find_collision_expand(alpha, &h_tmp, block_size, compress)?;
        pairs[k - i - 1].0 = step.short;
        pairs[k - i - 1].1 = step.long;
        h_tmp = step.h_out;
        compressions += step.compressions;
    }

    Ok(ExpandableMessage {
        h_out: h_tmp.to_owned(),
        pairs,
        compressions,
    })
}

fn expand_message(expandable_message: &ExpandableMessage, l: usize) -> Result<Vec<u8>> {
    let k = expandable_message.pairs.len();
    ensure!(l >= k);
    ensure!(l <= (1 << k) + k - 1);

    let mut m = vec![];
    let mut t = l - k;

    for (i, pair) in expandable_message.pairs.iter().enumerate() {
        let edge = 1 << (k - 1 - i);
        if t >= edge {
            m.extend(&pair.1);
            t -= edge;
        } else {
            m.extend(&pair.0);
        }
    }
    Ok(m)
}

fn second_preimage<C>(
    m: &[u8],
    h_in: &[u8],
    block_size: usize,
    compress: C,
) -> Result<(Vec<u8>, usize)>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    ensure!(m.len() % block_size == 0);
    let mut compression_count = 0;
    // Step 1: Figure out minimum k such that len(m) / block_size \in [k, k + 2^k - 1]
    let m_block_count = m.len() / block_size;
    let mut k = 1;
    while m_block_count > k + (1 << k) - 1 {
        println!("K? = {}", k);
        k += 1;
    }
    let k = k;
    println!("Step 1: k = {}", k);

    // Step 2: Create expandable message
    let expandable_message = make_expandable_message(h_in, k, block_size, compress)?;
    compression_count += expandable_message.compressions;
    println!(
        "Step 2: Expandable message out = {}",
        expandable_message.h_out.encode_hex::<String>()
    );

    // Step 3: Intermediate hash states
    let mut intermediate_hash_states: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut intermediate_state = h_in.to_vec();
    for (i, block) in m.chunks_exact(block_size).enumerate() {
        intermediate_state = compress(&intermediate_state, block);
        compression_count += 1;
        if i > k {
            intermediate_hash_states.insert(intermediate_state.clone(), i + 1);
        }
    }
    println!(
        "Step 3: intermediate hash states {}",
        intermediate_hash_states.len()
    );

    // Step 4: Find bridge block
    let mut bridge = vec![0u8; block_size];
    let mut rng = OsRng;
    compression_count += 1;
    while !intermediate_hash_states.contains_key(&compress(&expandable_message.h_out, &bridge)) {
        compression_count += 1;
        rng.fill_bytes(&mut bridge);
    }
    compression_count += 1;
    let i = *intermediate_hash_states
        .get(&compress(&expandable_message.h_out, &bridge))
        .unwrap();
    println!("Step 4: Bridge block {}", bridge.encode_hex::<String>());

    // Step 5: Build expanded message of length 1
    let mut result = expand_message(&expandable_message, i - 1)?;

    // (Check we're good but don't count these compressions against our total
    {
        let mut h_check = h_in.to_vec();
        for block in result.chunks_exact(block_size) {
            h_check = compress(&h_check, block);
        }
        ensure!(
            h_check == expandable_message.h_out,
            "Intermediate state check failed"
        );
        ensure!(result.len() == (i - 1) * block_size);
    }

    // Add bridge block
    result.extend_from_slice(&bridge);

    // Add the rest!
    result.extend_from_slice(&m[(block_size * i)..]);

    ensure!(result.len() == m.len());

    Ok((result, compression_count))
}

fn find_2n_collisions<D>(
    n: usize,
    block_size: usize,
    start: &[u8],
    compress: D,
) -> Result<(Vec<Vec<Vec<u8>>>, usize)>
where
    D: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut pairs: Vec<Vec<Vec<u8>>> = vec![];
    let mut count = 0;

    let mut current_state = start.to_owned();
    for _ in 0..n {
        let collision = find_collision(block_size, &current_state, compress)?;
        count += collision.3;
        current_state.copy_from_slice(&collision.2);
        pairs.push(vec![collision.0, collision.1]);
    }
    Ok((pairs, count))
}

fn pairs_to_product(pairs: &[Vec<Vec<u8>>]) -> impl Iterator<Item = Vec<u8>> + '_ {
    pairs
        .iter()
        .map(|v| v.iter())
        .multi_cartesian_product()
        .map(|i| i.into_iter().cloned().concat())
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct NostradamusElement {
    h_in: Vec<u8>,
    bridge: Vec<u8>,
}
fn build_nostradamus_tail_parts<C>(
    k: usize,
    block_size: usize,
    compress_size: usize,
    compress: C,
) -> Result<(Vec<NostradamusElement>, usize)>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut result = vec![];
    let targets = 1 << k;
    result.resize(
        1 << (k + 1),
        NostradamusElement {
            h_in: vec![0u8; compress_size],
            bridge: vec![0u8; block_size],
        },
    );
    let mut compressions = 0;

    // Step 1: Generate random initial states
    let mut rng = OsRng;
    for (idx, element) in result.iter_mut().enumerate().skip(targets) {
        println!("Filling {}", idx);
        rng.fill_bytes(&mut element.h_in);
    }

    // Step 2: Collide them down
    for idx in (3..result.len()).rev().step_by(2) {
        let dest_idx = (idx - 1) / 2;

        println!("Mapping ({}, {}) -> {}", idx, idx - 1, dest_idx);
        let mut a_outs: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut b_outs: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut block = vec![0u8; block_size];
        let a_in = &result[idx].h_in;
        let b_in = &result[idx - 1].h_in;

        loop {
            rng.fill_bytes(&mut block);
            // println!("Trying block: {:?}", block);
            let a_i = compress(a_in, &block);
            compressions += 1;
            let b_i = compress(b_in, &block);
            compressions += 1;

            // println!("a_i = {:?}", a_i);
            // println!("b_i = {:?}", b_i);

            if let Some(old_a) = a_outs.get(&b_i) {
                result[idx].bridge.copy_from_slice(old_a);
                result[idx - 1].bridge.copy_from_slice(&block);
                result[dest_idx].h_in.copy_from_slice(&b_i);
                break;
            } else if let Some(old_b) = b_outs.get(&a_i) {
                result[idx - 1].bridge.copy_from_slice(old_b);
                result[idx].bridge.copy_from_slice(&block);
                result[dest_idx].h_in.copy_from_slice(&a_i);
                break;
            } else if a_i == b_i {
                result[idx].bridge.copy_from_slice(&block);
                result[idx - 1].bridge.copy_from_slice(&block);
                result[dest_idx].h_in.copy_from_slice(&a_i);
                break;
            }
            a_outs.insert(a_i, block.clone());
            b_outs.insert(b_i, block.clone());
        }
    }
    Ok((result, compressions))
}

fn build_nostradamus_result<C>(
    parts: &[NostradamusElement],
    msg: &[u8],
    h_initial: &[u8],
    compress: C,
) -> Result<(Vec<u8>, usize)>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut compressions = 0;
    let mut result = vec![];
    let target_cnt = parts.len() / 2;
    let block_size = parts[0].bridge.len();

    // Step 0: Build table of known ends
    let mut targets: HashMap<Vec<u8>, usize> = HashMap::new();
    for (idx, h_end) in parts.iter().enumerate().skip(target_cnt) {
        targets.insert(h_end.h_in.clone(), idx);
    }
    let targets = targets;

    // Step 0.5: Hash message so far
    let mut h_in = h_initial.to_vec();
    for block in msg.chunks_exact(block_size) {
        result.extend(block);
        h_in = compress(&h_in, block);
        compressions += 1;
    }

    // Step 1: Find bridge
    let mut bridge = vec![0u8; block_size];
    let mut rng = OsRng;
    let target_idx;
    loop {
        rng.fill_bytes(&mut bridge);
        let h_out = compress(&h_in, &bridge);
        compressions += 1;

        if let Some(tmp) = targets.get(&h_out) {
            target_idx = *tmp;
            break;
        }
    }
    result.extend(bridge);
    result.extend(build_nostradamus_tail(parts, target_idx));

    Ok((result, compressions))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NostradamusCommitment<C>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    tail_parts: Vec<NostradamusElement>,
    pre_hash: Vec<u8>,
    total_length: usize,
    compressions: usize,
    compression: C,
}

fn build_nostradamus_commitment<C>(
    base_message_length: usize,
    tail_length: usize,
    compression: C,
    block_size: usize,
    state_size: usize,
) -> Result<NostradamusCommitment<C>>
where
    C: Send + Copy + 'static + Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let tail = build_nostradamus_tail_parts(tail_length, block_size, state_size, compression)?;

    let pre_hash = tail.0[1].h_in.clone();
    Ok(NostradamusCommitment {
        tail_parts: tail.0,
        pre_hash,
        total_length: base_message_length + tail_length + 1,
        compressions: tail.1,
        compression,
    })
}

fn build_nostradamus_tail(parts: &[NostradamusElement], start: usize) -> Vec<u8> {
    let mut result = vec![];
    let mut idx = start;
    while idx > 1 {
        result.extend(&parts[idx].bridge);
        idx /= 2;
    }
    result
}

fn massage_md4_block(block: &mut [u8]) {
    assert_eq!(block.len(), MD4::block_size());

    let md4 = MD4::default();
    let a0 = md4.h[0];
    let b0 = md4.h[1];
    let c0 = md4.h[2];
    let d0 = md4.h[3];
    let mut X: Vec<u32> = to_w32_be(block).iter().map(|w| u32::from_be(*w)).collect();
    // First condition
    {
        let mut a1 = MD4::ff(a0, b0, c0, d0, 0, 3, &X);
        // Fix the bad bit
        a1 ^= (a1.bit(6) ^ b0.bit(6)) << 6;
        X[0] = a1
            .rotate_right(3)
            .wrapping_sub(a0)
            .wrapping_sub(MD4::f(b0, c0, d0));
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum MD4Constraint {
    Equal(usize),
    One(usize),
    Zero(usize),
    Neg(usize),
    EqOffset(usize, usize),
}

impl MD4Constraint {
    fn apply(&self, new_word: u32, state: [u32; 4], word_idxs: [usize; 4]) -> u32 {
        let old_word_idx = match self {
            MD4Constraint::Equal(_) => word_idxs[1],
            MD4Constraint::EqOffset(_, old_idx) => word_idxs[*old_idx],
            _ => 0,
        };
        let old_word = state[old_word_idx];
        
        if self == &MD4Constraint::Equal(19) {
            println!(
                "Foo: new_word = {}[{}] = {}, old_word = {}[{}] = {}",
                new_word.to_le_hex(),
                self.i(),
                new_word.bit(self.i()),
                old_word.to_le_hex(),
                self.i(),
                old_word.bit(self.i())
            );
        }
        match self {
            MD4Constraint::Equal(idx) | MD4Constraint::EqOffset(idx, _) => {
                new_word.set_bit(*idx, old_word.bit(*idx))
            }
            MD4Constraint::Neg(idx) => new_word.set_bit(*idx, 1 - old_word.bit(*idx)),
            MD4Constraint::One(idx) => new_word.set_bit(*idx, 1),
            MD4Constraint::Zero(idx) => new_word.set_bit(*idx, 0),
            // MD4Constraint::EqOffset(index, ) => new_word.set_bit(*idx, val)
        }
    }

    fn require(&self, new_word: u32, state: [u32; 4], word_idxs: [usize; 4]) -> Result<()> {
        ensure!(
            new_word == self.apply(new_word, state, word_idxs),
            "{:#04x} != {:#04x}, idxs = {:?}, {:#04x}[{}] = {}",
            new_word.to_be(),
            self.apply(new_word, state, word_idxs).to_be(),
            word_idxs,
            state[word_idxs[1]].to_be(),
            self.i(),
            state[word_idxs[1]].bit(self.i())
        );
        Ok(())
    }

    fn i(&self) -> usize {
        match self {
            MD4Constraint::Equal(i)
            | MD4Constraint::One(i)
            | MD4Constraint::Zero(i)
            | MD4Constraint::Neg(i)
            | MD4Constraint::EqOffset(i, _) => *i,
        }
    }
}

impl Display for MD4Constraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

lazy_static! {
    static ref MD4CollisionConstraints: Vec<Vec<MD4Constraint>> =
        vec![
            // a1
            vec![MD4Constraint::Equal(6)],
            // d1
            vec![MD4Constraint::Zero(6), MD4Constraint::Equal(7), MD4Constraint::Equal(10)],
            // c1
            vec![MD4Constraint::One(6), MD4Constraint::One(7), MD4Constraint::Zero(10), MD4Constraint::Equal(25)],
            // b1
            vec![MD4Constraint::One(6), MD4Constraint::Zero(7), MD4Constraint::Zero(10), MD4Constraint::Zero(25)],
            // a2
            vec![MD4Constraint::One(7), MD4Constraint::One(10), MD4Constraint::Zero(25), MD4Constraint::Equal(13),
                MD4Constraint::Equal(16), MD4Constraint::Equal(17), MD4Constraint::Equal(19), MD4Constraint::Equal(22)
            ],
            // d2
            vec![MD4Constraint::Zero(13), MD4Constraint::Equal(18), MD4Constraint::Equal(19), MD4Constraint::Equal(20), MD4Constraint::Equal(21), MD4Constraint::One(25),
                MD4Constraint::Zero(16), MD4Constraint::Zero(17), MD4Constraint::Zero(19), MD4Constraint::Zero(22)
            ],
            // c2
            vec![MD4Constraint::Equal(12), MD4Constraint::Zero(13), MD4Constraint::Equal(14), MD4Constraint::Zero(18), MD4Constraint::Zero(19), MD4Constraint::One(20), MD4Constraint::Zero(21),
                MD4Constraint::Zero(16), MD4Constraint::Zero(17), MD4Constraint::Zero(19), MD4Constraint::Zero(22)
            ],
            // b2
            vec![MD4Constraint::One(12), MD4Constraint::One(13), MD4Constraint::Zero(14), MD4Constraint::Equal(16), MD4Constraint::Zero(18), MD4Constraint::Zero(19), MD4Constraint::Zero(20), MD4Constraint::Zero(21),
                MD4Constraint::Zero(16), MD4Constraint::Zero(17), MD4Constraint::Zero(19), MD4Constraint::Zero(22)
            ],
            // a3
            vec![MD4Constraint::One(12), MD4Constraint::One(13), MD4Constraint::One(14), MD4Constraint::Zero(16), MD4Constraint::Zero(18), MD4Constraint::Zero(19), MD4Constraint::Zero(20), MD4Constraint::Equal(22), MD4Constraint::One(21), MD4Constraint::Equal(25)],
            // d3
            vec![MD4Constraint::One(12), MD4Constraint::One(13), MD4Constraint::One(14), MD4Constraint::Zero(16), MD4Constraint::Zero(19), MD4Constraint::One(20), MD4Constraint::One(21), MD4Constraint::Zero(22), MD4Constraint::One(25), MD4Constraint::Equal(29)],
            // c3
            vec![MD4Constraint::One(16), MD4Constraint::Zero(19), MD4Constraint::Zero(20), MD4Constraint::Zero(21), MD4Constraint::Zero(22), MD4Constraint::Zero(25), MD4Constraint::One(29), MD4Constraint::Equal(31)],
            // b3
            vec![MD4Constraint::Zero(19), MD4Constraint::One(20), MD4Constraint::One(21), MD4Constraint::Equal(22), MD4Constraint::One(25), MD4Constraint::Zero(29), MD4Constraint::Zero(31)],
            // a4
            vec![MD4Constraint::Zero(22), MD4Constraint::Zero(25), MD4Constraint::Equal(26), MD4Constraint::Equal(28), MD4Constraint::One(29), MD4Constraint::Zero(31)],
            // d4
            vec![MD4Constraint::Zero(22), MD4Constraint::Zero(25), MD4Constraint::One(26), MD4Constraint::One(28), MD4Constraint::Zero(29), MD4Constraint::One(31)],
            // c4
            vec![MD4Constraint::Equal(18), MD4Constraint::One(22), MD4Constraint::One(25), MD4Constraint::Zero(26), MD4Constraint::Zero(28), MD4Constraint::Zero(29)],
            // b4
            vec![MD4Constraint::Zero(18), MD4Constraint::Equal(25), MD4Constraint::One(26), MD4Constraint::One(28), MD4Constraint::Zero(29), MD4Constraint::Equal(31)],
            // // a5
            vec![MD4Constraint::EqOffset(18, 2), MD4Constraint::One(25), MD4Constraint::Zero(26), MD4Constraint::One(28), MD4Constraint::One(31)],
            // // d5
            vec![MD4Constraint::Equal(18), MD4Constraint::EqOffset(25, 2), MD4Constraint::EqOffset(26, 2), MD4Constraint::EqOffset(28, 2), MD4Constraint::EqOffset(31, 2)],
            // // c5
            vec![MD4Constraint::Equal(25), MD4Constraint::Equal(26), MD4Constraint::Equal(28), MD4Constraint::Equal(29), MD4Constraint::Equal(31)],
            // // b5
            // vec![MD4Constraint::Equal(28), MD4Constraint::One(29), MD4Constraint::Zero(31)],
            // // a6
            // vec![MD4Constraint::One(28), MD4Constraint::One(31)],
            // // d6
            // vec![MD4Constraint::Equal(28)],
            // // c6
            // vec![MD4Constraint::Equal(28), MD4Constraint::Neg(29), MD4Constraint::Neg(31)],
            // // b6
            // vec![],
            // // a7
            // vec![],
            // // d7
            // vec![],
            // // c7
            // vec![],
            // // b7
            // vec![],
            // // a8
            // vec![],
            // // d8
            // vec![],
            // // c8
            // vec![],
            // // b8
            // vec![],
            // // a9
            // vec![],
            // // d9
            // vec![],
            // // c9
            // vec![],
            // // b9
            // vec![MD4Constraint::One(31)],
            // // a10
            // vec![MD4Constraint::One(31)],
            ];
}

fn apply_md4_constraints(blocks: &mut [u32], constraints: &[Vec<MD4Constraint>]) -> [u32; 4] {
    // println!("Len {}", constraints.len());
    assert!(constraints.len() == 16);
    let mut state = [MD4::I0, MD4::I1, MD4::I2, MD4::I3];
    for (step, step_constraints) in constraints.iter().enumerate() {
        let mut offset = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a_idx: usize = offset;
        let a_prev = state[a_idx];
        let b_idx = (offset + 1) % 4;
        let c_idx = (b_idx + 1) % 4;
        let d_idx = (c_idx + 1) % 4;
        let word_idxs = [a_idx, b_idx, c_idx, d_idx];

        let mut x = blocks[MD4::WORD_ORDER[step]];
        for constraint in step_constraints {
            MD4::ff1(&mut state, step, x);
            let a_next = state[a_idx];
            let fixed_a1 = constraint.apply(a_next, state, word_idxs);
            if step == 5 {
                println!("Candidate next: {} => {} by {:?}", a_next, fixed_a1, constraint);;
            }
            x = MD4::ff2word(
                fixed_a1,
                a_prev,
                state[b_idx],
                state[c_idx],
                state[d_idx],
                MD4::SHIFTS[step % 4],
            );
            state[a_idx] = a_prev; // Restore to previous state because we always advance outside the constraint
        }
        // if blocks[MD4::WORD_ORDER[step]] != x {
        //     println!("\t{}: Updating word {:#04x} to {:#04x}", step, blocks[MD4::WORD_ORDER[step]].to_le(), x.to_le());
        // }
        blocks[MD4::WORD_ORDER[step]] = x;
        MD4::ff1(&mut state, step, x);
        print_md4_state(step, state);
    }
    state
}

fn print_md4_state(step: usize, state: [u32; 4]) {
    println!(
        "{}:\ta = {:#04x}\tb = {:#04x}\tc = {:#04x}\td = {:#04x}",
        step,
        state[0],
        state[1],
        state[2],
        state[3]
    );
}

fn get_hist_state(history: &[[u32; 4]], element: usize, idx: usize) -> u32 {
    let version = if idx == 0 { 0 } else { (idx * 4) - 1 };
    history[version][element]
}

fn set_hist_state(history: &mut [[u32; 4]], element: usize, idx: usize, value: u32) {
    let version = (idx * 4) - 1;
    history[version][element] = value;
}

fn apply_md4_round2_contraints(
    blocks: &mut [u32],
    state: [u32; 4],
    constraints: &[Vec<MD4Constraint>],
) -> [u32; 4] {
    let mut state = state;
    assert_ne!(state[0], 0);
    // let a0 = MD4::I0;
    // let b0 = MD4::I1;
    // let c0 = MD4::I2;
    // let d0 = MD4::I3;
    let initial_state = [MD4::I0, MD4::I1, MD4::I2, MD4::I3];

    for (step, word_idx) in MD4::WORD_ORDER.iter().enumerate().skip(16).take(16) {
        let mut offset = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a_idx: usize = offset;
        let b_idx = (offset + 1) % 4;
        let c_idx = (b_idx + 1) % 4;
        let d_idx = (c_idx + 1) % 4;

        // let a4 = state[a_idx];
        let prev_state = state;
        MD4::gg1(&mut state, step, blocks[*word_idx]);
        print_md4_state(step, state);

        // a_5,{18,25,26,28,31}=c_4,i
        if step == 16 {
            //} || step == 17 { // a5, d5
            let a0 = initial_state[0];
            let b0 = initial_state[1];
            let c0 = initial_state[2];
            let d0 = initial_state[3];
            for constraint in &constraints[step] {
                let old_element = prev_state[a_idx];
                let mut new_element = state[a_idx];
                let word_idxs = [a_idx, b_idx, c_idx, d_idx];
                println!(
                    "{}: {:?} says {:?}",
                    step,
                    constraint,
                    constraint.require(new_element, state, word_idxs)
                );
                if constraint.require(new_element, state, word_idxs).is_ok() {
                    continue;
                }
                // println!("{:?}", state_history);
                let unmodifed = MD4::gg2word(
                    new_element,
                    old_element,
                    state[b_idx],
                    state[c_idx],
                    state[d_idx],
                    MD4::SHIFTS[4 + step % 4],
                );
                println!("{:#04x} =? {:#04x}", unmodifed.to_be(), blocks[0].to_be());

                new_element = constraint.apply(new_element, state, word_idxs);
                println!(
                    "{}: {:?} says {:?}",
                    step,
                    constraint,
                    constraint.require(new_element, state, word_idxs)
                );
                assert_ne!(new_element, old_element);

                let m0 = MD4::gg2word(
                    new_element,
                    old_element,
                    state[b_idx],
                    state[c_idx],
                    state[d_idx],
                    MD4::SHIFTS[4 + step % 4],
                );
                println!("{:#04x} =? {:#04x}", new_element.to_be(), blocks[0].to_be());

                println!(
                    "Updating word 0 {:#04x} to {:#04x}",
                    blocks[0].to_be(),
                    m0.to_be()
                );
                assert_ne!(blocks[0].to_be(), m0.to_be());
                let a1 = MD4::ff(a0, b0, c0, d0, MD4::WORD_ORDER[0], MD4::SHIFTS[0], blocks);
                let d1 = MD4::ff(d0, a1, b0, c0, MD4::WORD_ORDER[1], MD4::SHIFTS[1], blocks);
                let c1 = MD4::ff(c0, d1, a1, b0, MD4::WORD_ORDER[2], MD4::SHIFTS[2], blocks);
                let b1 = MD4::ff(b0, c1, d1, a1, MD4::WORD_ORDER[3], MD4::SHIFTS[3], blocks);
                let a2 = MD4::ff(a1, b1, c1, d1, MD4::WORD_ORDER[4], MD4::SHIFTS[0], blocks);

                println!("a1 = {:#04x}", a1.to_be());
                println!("d1 = {:#04x}", d1.to_be());

                blocks[0] = m0;

                let a1_prime = MD4::ff(a0, b0, c0, d0, MD4::WORD_ORDER[0], MD4::SHIFTS[0], blocks);

                let m1 = d1
                    .rotate_right(7)
                    .wrapping_sub(d0)
                    .wrapping_sub(MD4::f(a1_prime, b0, c0));
                blocks[1] = m1;

                let m2 = c1
                    .rotate_right(11)
                    .wrapping_sub(c0)
                    .wrapping_sub(MD4::f(d1, a1_prime, b0));
                blocks[2] = m2;

                let m3 = b1
                    .rotate_right(19)
                    .wrapping_sub(b0)
                    .wrapping_sub(MD4::f(c1, d1, a1_prime));
                blocks[3] = m3;

                let m4 = a2
                    .rotate_right(3)
                    .wrapping_sub(a1_prime)
                    .wrapping_sub(MD4::f(b1, c1, d1));
                blocks[4] = m4;

                state = prev_state;
                MD4::gg1(&mut state, step, blocks[*word_idx]);
            }
        } else if step == 18 { // c5
             // // assert_eq!(*word_idx, 5);
             // for constraint in &constraints[step] {
             //     let c5 = state[2];
             //     let word_idxs = [a_idx, b_idx, c_idx, d_idx];
             //     // println!("{}: {:?} says {:?}", step, constraint, constraint.require(c5, state, word_idxs));
             //     if constraint.require(c5, state, word_idxs).is_ok() {
             //         continue;
             //     }
             //     let i = constraint.i();
             //     // c5 = constraint.apply(c5, state, word_idxs);
             //     // let m5 = MD4::gg2word(c5, c4, state[b_idx], state[c_idx], state[d_idx], MD4::SHIFTS[4 + step % 4]);
             //     let m5 = blocks[5].overflowing_add(1 << (i - 17)).0;
             //     // println!("Updating word 5 {:#04x} to {:#04x}", blocks[5].to_be(), m5.to_be());
             //     blocks[5] = m5;
             //     let m8 = blocks[8].overflowing_sub(1 << (i - 10)).0;
             //     // println!("Updating word 8 {:#04x} to {:#04x}", blocks[8].to_be(), m8.to_be());
             //     blocks[8] = m8;
             //     let m9 = blocks[9].overflowing_sub(1 << (i - 10)).0;
             //     // println!("Updating word 9 {:#04x} to {:#04x}", blocks[9].to_be(), m9.to_be());
             //     blocks[9] = m9;
             // }
        }
    }

    state
}

fn verify_md4_constraints(blocks: &[u32], constraints: &[Vec<MD4Constraint>]) -> Result<()> {
    // assert!(constraints.len() <= 16);
    let mut state = [MD4::I0, MD4::I1, MD4::I2, MD4::I3];
    let ops = [MD4::ff1, MD4::gg1, MD4::hh1];
    println!();
    for (step, step_constraints) in constraints.iter().enumerate() {
        let round = step / 16;
        let op = ops[step / 16];
        let mut offset: usize = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a_idx: usize = offset;
        let b_idx = (offset + 1) % 4;
        let c_idx = (b_idx + 1) % 4;
        let d_idx = (c_idx + 1) % 4;
        let word_idxs = [a_idx, b_idx, c_idx, d_idx];

        let x = blocks[MD4::WORD_ORDER[step]];
        op(&mut state, step, x);
        print_md4_state(step, state);
        for constraint in step_constraints {
            let a1 = state[a_idx];
            let error_msg = format!("Step {}: {:?}", step, constraint);
            constraint
                .require(a1, state, word_idxs)
                .context(error_msg)?;
            // ensure!(constraint.require(a1, state, word_idxs).is_ok(), error_msg);
        }
        // println!("Step {}\t: {:#04x}{:#04x}{:#04x}{:#04x}", step, state[0].to_le(), state[1].to_le(), state[2].to_le(), state[3].to_le());
        // let mut md4 = MD4::default();
        // MD4::ff1(&mut state, step, MD4::SHIFTS[step % 4], x);
    }
    Ok(())
}

fn create_md4_collision_candidate() -> Result<Vec<u8>> {
    let mut rng = OsRng;
    // loop {
    let mut msg1 = vec![0u8; MD4::block_size()];
    rng.fill_bytes(&mut msg1);
    let mut block: Vec<u32> = to_w32_be(&msg1).iter().map(|w| u32::from_be(*w)).collect();
    let state = apply_md4_constraints(&mut block, &MD4CollisionConstraints[0..16]);
    // apply_md4_round2_contraints(&mut block, state, &MD4CollisionConstraints);
    let tmp = verify_md4_constraints(&block, &MD4CollisionConstraints[0..16]);
    if tmp.is_err() {
        panic!("{:?}", tmp);
        // println!("Trying again: {:?}", tmp);
        // continue;
    }
    // if verify_md4_constraints(&block, &MD4CollisionConstraints).is_ok() {
    let msg1 = block
        .iter()
        .flat_map(|b| b.to_le_bytes())
        .collect::<Vec<u8>>();
    return Ok(msg1);
    // }
    // println!("Trying again...");
    // }
}

fn create_md4_collision(msg2_limit: usize) -> Result<(Vec<u8>, Vec<u8>, usize)> {
    let pool_size = 4;

    let pool: Pool<ThunkWorker<(Vec<u8>, Vec<u8>, usize)>> = Pool::new(pool_size);
    let (tx, rx) = channel();
    // let mut results: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    // loop {
    for _ in 0..(pool_size * 2) {
        pool.execute_to(
            tx.clone(),
            Thunk::of(move || create_md4_collision_inner(msg2_limit).unwrap()),
        );
    }
    Ok(rx.recv()?)
    // }
    // for r in rx.iter().take(pool_size * 2) {
    //     count += 1;
    //     let output = r.0;
    //     let input = r.1;
    //     // println!("Compress({}) = {}", input.encode_hex::<String>(), output.encode_hex::<String>());
    //     if let Some(collision) = results.get(&output) {
    //         return Ok((collision.to_owned(), input, output, count));
    //     } else {
    //         results.insert(output, input);
    //     }
    // }
}

fn create_md4_collision_inner(msg2_limit: usize) -> Result<(Vec<u8>, Vec<u8>, usize)> {
    let mut count = 0;
    // let mut rng = OsRng;
    loop {
        let msg1 = create_md4_collision_candidate()?;

        for _ in 0..msg2_limit {
            if count % 10000 == 0 {
                println!("Trial {}", count);
            }
            let mut msg2 = msg1.clone();
            // let byte1 = rng.gen_range(0..msg2.len());
            // let byte2= rng.gen_range(0..msg2.len());
            // let byte3 = rng.gen_range(0..msg2.len());
            msg2[1] ^= 1;
            msg2[4] ^= 1;
            msg2[28] ^= 1;
            count += 1;

            if MD4::oneshot_digest(&msg1) == MD4::oneshot_digest(&msg2) {
                return Ok((msg1, msg2, count));
            }
        }
    }
}

// n = counts, r = position, p = distribution
pub fn rc4_single_byte_attack(n: [usize; 256], r: usize, p: &[[f64; 256]]) -> Result<u8> {
    ensure!(r >= 0);
    ensure!(r < p.len());
    let mut l = [0f64; 256];

    for u in 0..=255u8 {
        let mut n_u = [0usize; 256];
        for k in 0..=255u8 {
            n_u[k as usize] = n[(u ^ k) as usize];
        }
        for k in 0..=255u8 {
            l[u as usize] += (n_u[k as usize] as f64) * p[r][k as usize].log2();
        }
    }
    let mut best_val = f64::MIN;
    let mut best = 0u8;
    for u in 0..=255 {
        if l[u] > best_val {
            best_val = l[u];
            best = u as u8;
        }
    }
    Ok(best)
}


#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        aes::AesKey, oracles::{Challenge49Oracle, Challenge51Oracle}, padding::Padding, rc4::Rc4Key, xor
    };
    use anyhow::{Context, Result};
    use itertools::Itertools;

    use super::*;

    #[test]
    fn challenge49_1() -> Result<()> {
        let oracle: Challenge49Oracle = Default::default();

        let iv = [0u8; 16];
        println!("Creating");
        let tag1 = oracle.sign1(&iv, "7", "7", 1000000)?;
        println!("Verifying");
        assert!(oracle.verify1(&iv, &tag1, "7", "7", 1000000).is_ok());
        println!("Bad verif");
        assert!(oracle.verify1(&iv, &tag1, "5", "7", 1000000).is_err());

        let diff = b'7' ^ b'9';
        let mut iv2 = iv;
        iv2[5] = diff;
        println!("Hacked");
        assert!(oracle.verify1(&iv2, &tag1, "9", "7", 1000000).is_ok());
        Ok(())
    }

    #[test]
    fn challenge49_2() -> Result<()> {
        let oracle: Challenge49Oracle = Default::default();
        let pkcs7 = Padding::Pkcs7Padding(16);

        let txns1 = vec![("0", 1), ("15", 32), ("2", 45)];
        let good_mac = oracle.sign2("1", &txns1)?;
        println!("Good mac: {}", hex::encode(&good_mac));
        let good_signed = pkcs7.pad(Challenge49Oracle::sts2("1", &txns1).as_bytes())?;

        let txns2 = vec![("99", 1000000), ("99", 10), ("99", 1000000)];
        println!("{}", Challenge49Oracle::sts2("99", &txns2));
        let evil_mac = oracle.sign2("99", &txns2)?;
        let evil_base = pkcs7.pad(Challenge49Oracle::sts2("99", &txns2).as_bytes())?;

        let mut forged = good_signed.clone();
        let mut evil_chunks = evil_base.chunks_exact(16);
        let first_evil = evil_chunks.next().context("Too few chunks")?; // Drop first chunk
                                                                        // let glue_chunk = evil_chunks.next().context("Too few chunks")?;
                                                                        // let xored = glue_chunk.to_owned();
        let xored = xor(first_evil, &good_mac);
        forged.extend_from_slice(&xored);
        evil_chunks.for_each(|c| forged.extend_from_slice(c));
        println!("{}", hex::encode(&forged));
        let forged = pkcs7.unpad(&forged)?;
        assert!(oracle.verify_mac(&[0u8; 16], &forged, &evil_mac));
        Ok(())
    }

    #[test]
    fn challenge50() -> Result<()> {
        let iv = &[0u8; 16];
        let pkcs7 = Padding::Pkcs7Padding(16);
        let key = AesKey::new(b"YELLOW SUBMARINE")?;
        let good_js = "alert('MZA who was that?');\n";
        let good_hash = "296b8d7cb78a243dda4d0a61d33bbdd1";
        assert_eq!(good_hash, hex::encode(key.cbc_mac(iv, good_js.as_bytes())?));
        let padded_good_js = pkcs7.pad(good_js.as_bytes())?;
        println!("{}", hex::encode(&padded_good_js));
        let encrypted_good = key.encrypt_cbc(&[0u8; 16], &padded_good_js)?;
        println!("Encrypted good: {}", hex::encode(&encrypted_good));

        let decrypted_tag =
            key.decrypt_block(encrypted_good.chunks_exact(16).last().context("To few")?);
        let expected_end_pt = xor(
            encrypted_good
                .chunks_exact(16)
                .tail(2)
                .next()
                .context("too few")?,
            &decrypted_tag,
        );
        println!("{}", hex::encode(expected_end_pt));

        let target_pt = "alert('Ayo, the Wu is back!');\n <!--                            -->";
        let padded_target = pkcs7.pad(target_pt.as_bytes())?;
        println!("Padded target: {}", hex::encode(&padded_target));
        let final_target = padded_target.chunks_exact(16).last().unwrap();
        let encrypted_target = key.encrypt_cbc(iv, &padded_target)?;

        let mut replaced_end = vec![];
        replaced_end.extend_from_slice(&encrypted_target[..encrypted_target.len() - 16]);
        replaced_end.extend_from_slice(&hex::decode(good_hash)?);
        println!("encrypted_target: {}", hex::encode(&encrypted_target));
        println!("replaced_end:     {}", hex::encode(&replaced_end));
        let tmp_len = replaced_end.len();

        for idx in 0..16 {
            replaced_end[tmp_len - 32 + idx] = 0;
        }
        let decrypted_replaced_end = key.decrypt_cbc(iv, &replaced_end)?;
        println!("decrypted_target: {}", hex::encode(&decrypted_replaced_end));
        let final_diff = xor(
            final_target,
            decrypted_replaced_end.chunks_exact(16).last().unwrap(),
        );
        println!("final_diff: {}", hex::encode(&final_diff));
        for (idx, val) in final_diff.iter().enumerate() {
            replaced_end[tmp_len - 32 + idx] = *val;
        }
        println!("replaced_end:     {}", hex::encode(&replaced_end));
        let decrypted_replaced_end = key.decrypt_cbc(iv, &replaced_end)?;
        let decrypted_replaced_end = pkcs7.unpad(&decrypted_replaced_end)?;
        println!("decrypted_target: {}", hex::encode(&decrypted_replaced_end));

        assert_eq!(
            good_hash,
            hex::encode(key.cbc_mac(iv, &decrypted_replaced_end)?)
        );
        Ok(())
    }

    #[test]
    fn challenge51_1() -> Result<()> {
        let base64_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=";
        let oracle = Challenge51Oracle::new();
        let junk: &str = "#!?:@&[]^";
        println!("Length: {}", oracle.oracle1("sessionid=A")?);
        println!("Length: {}", oracle.oracle1("sessionid=T")?);

        let mut guess: Vec<char> = vec![];

        while guess.last().unwrap_or(&'A') != &'=' {
            let mut best_guess = '?';
            let mut best_guess_value: usize;
            for first_guess in base64_chars.chars() {
                for second_guess in base64_chars.chars() {
                    let full_guess = format!(
                        "Cookie: sessionid={}{}{}{}",
                        guess.iter().join(""),
                        junk,
                        first_guess,
                        second_guess
                    );
                    let len2 = oracle.oracle1(&full_guess)?;
                    let full_guess = format!(
                        "Cookie: sessionid={}{}{}{}",
                        guess.iter().join(""),
                        first_guess,
                        second_guess,
                        junk
                    );
                    let len1 = oracle.oracle1(&full_guess)?;
                    // println!("{}{}? {} <> {}", first_guess, second_guess, len1, len2);
                    if len1 < len2 {
                        best_guess = first_guess;
                        best_guess_value = len1;
                        println!(
                            "{} -> {}: (Best: {} = {})",
                            full_guess, len1, best_guess, best_guess_value
                        );
                    }
                }
            }
            guess.push(best_guess);
            println!("Guessing {}", best_guess);
            // todo!();
        }
        let final_guess = guess.iter().join("");
        println!("Final guess: {}", final_guess);
        oracle.check(&final_guess)
    }

    #[test]
    fn challenge51_2() -> Result<()> {
        let base64_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=";
        let oracle = Challenge51Oracle::new();
        let pad_src = "#!?{}:/@&[}*],^-$\"_';|,/.#-?]@[^*_!\\}{";
        let junk: &str = "#!?:@&[]^-$\"';|,.";

        // Find initial padding
        let mut initial_padding = "".to_string();
        let no_padded_guess_len =
            oracle.oracle2(&format!("{}Cookie: sessionid={}", &initial_padding, junk))?;
        println!("No padding length {}", no_padded_guess_len);
        for j in pad_src.chars() {
            initial_padding += &j.to_string();
            let padded_guess_len =
                oracle.oracle2(&format!("{}Cookie: sessionid={}", &initial_padding, junk))?;
            println!(
                "Trying padding {} with length {}",
                &initial_padding, padded_guess_len
            );
            if padded_guess_len > no_padded_guess_len {
                initial_padding.pop();
                initial_padding.pop();
                println!("Using padding {}", &initial_padding);
                break;
            }
        }

        let mut guess: Vec<char> = vec![];

        while guess.last().unwrap_or(&'A') != &'=' {
            let mut best_guess = '?';
            let mut best_guess_value: usize;
            for first_guess in base64_chars.chars() {
                for second_guess in base64_chars.chars() {
                    let full_guess = format!(
                        "{}Cookie: sessionid={}{}{}{}",
                        initial_padding,
                        guess.iter().join(""),
                        junk,
                        first_guess,
                        second_guess
                    );
                    let len2 = oracle.oracle2(&full_guess)?;
                    let full_guess = format!(
                        "{}Cookie: sessionid={}{}{}{}",
                        initial_padding,
                        guess.iter().join(""),
                        first_guess,
                        second_guess,
                        junk
                    );
                    let len1 = oracle.oracle2(&full_guess)?;
                    // println!("{}{}? {} <> {}", first_guess, second_guess, len1, len2);
                    if len1 < len2 {
                        best_guess = first_guess;
                        best_guess_value = len1;
                        println!(
                            "{} -> {}: (Best: {} = {})",
                            full_guess, len1, best_guess, best_guess_value
                        );
                    }
                }
            }
            if best_guess == '?' {
                initial_padding.pop();
                println!("New prefix: {}", initial_padding);
            } else {
                guess.push(best_guess);
                println!("Guessing {}", best_guess);
            }
            // todo!();
        }
        let final_guess = guess.iter().join("");
        println!("Final guess: {}", final_guess);
        oracle.check(&final_guess)
    }

    #[test]
    fn challenge52_smoke() -> Result<()> {
        let mut dgst = RD0::default();

        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());

        let collisions = find_collision(RD0::block_size(), &[0u8; 2], RD0::compress)?;

        dgst.update(&collisions.0);
        println!(
            "rd0({}) = {}",
            &collisions.0.encode_hex::<String>(),
            dgst.digest().encode_hex::<String>()
        );
        dgst.update(&collisions.1);
        println!(
            "rd0({}) = {}",
            &collisions.1.encode_hex::<String>(),
            dgst.digest().encode_hex::<String>()
        );
        println!("Took {} compressions!", collisions.3);
        Ok(())
    }

    #[test]
    fn challenge52_smoke2() -> Result<()> {
        let mut dgst = RD1::default();

        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());

        let collisions = find_collision(RD1::block_size(), &[0u8; 4], RD1::compress)?;

        dgst.update(&collisions.0);
        println!(
            "rd1({}) = {}",
            &collisions.0.encode_hex::<String>(),
            dgst.digest().encode_hex::<String>()
        );
        dgst.update(&collisions.1);
        println!(
            "rd1({}) = {}",
            &collisions.1.encode_hex::<String>(),
            dgst.digest().encode_hex::<String>()
        );
        println!("Took {} compressions!", collisions.3);
        Ok(())
    }

    #[test]
    fn challenge52_smoke3() -> Result<()> {
        let mut dgst = RD2::default();

        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Greg");
        println!("rd0(\"Greg\") = {}", dgst.digest().encode_hex::<String>());
        dgst.update(b"Sarah");
        println!("rd0(\"Sarah\") = {}", dgst.digest().encode_hex::<String>());

        Ok(())
    }

    #[test]
    fn challenge52_1() -> Result<()> {
        let mut dgst = RD0::default();
        let collisions = find_2n_collisions(10, RD0::block_size(), &[0u8; 2], RD0::compress)?;
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for c in pairs_to_product(&collisions.0) {
            dgst.update(&c);
            println!(
                "rd0({}) = {}",
                &c.encode_hex::<String>(),
                dgst.digest().encode_hex::<String>()
            );
            assert!(seen.insert(c));
        }
        println!("Took {} compressions!", collisions.1);
        Ok(())
    }

    #[test]
    fn challenge52_2() -> Result<()> {
        let collisions = find_2n_collisions(20, RD0::block_size(), &[0u8; 2], RD0::compress)?;
        let mut seen: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        println!("Took {} compressions!", collisions.1);
        let mut compressions = collisions.1;

        let mut rd1 = RD1::default();
        for c in pairs_to_product(&collisions.0) {
            rd1.update(&c);
            let dgst = rd1.digest();
            compressions += 1;
            if let Some(other) = seen.get(&dgst) {
                let mut rd2 = RD2::default();
                rd2.update(other);
                let dgst1 = rd2.digest();
                rd2.update(&c);
                let dgst2 = rd2.digest();
                println!(
                    "rd2({}) -> {}",
                    other.encode_hex::<String>(),
                    dgst1.encode_hex::<String>()
                );
                println!(
                    "rd2({}) -> {}",
                    c.encode_hex::<String>(),
                    dgst2.encode_hex::<String>()
                );
                println!("Took {} compressions!", compressions);
                assert_ne!(other, &c);
                assert_eq!(dgst1, dgst2);
                break;
            } else {
                seen.insert(dgst, c);
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "smoke"]
    fn challenge53_smoke() -> Result<()> {
        let result = find_collision_expand(3, &[0u8; 16], 16, RD1::compress)?;
        let mut digest = RD1::default();
        digest.update(&result.short);
        println!("{:?}", digest);
        digest.reset();
        digest.update(&result.long);
        println!("{:?}", digest);
        println!("{:?}", result);

        let k = 10;
        let expandable_message = make_expandable_message(&[0u8; 16], k, 16, RD1::compress)?;
        // println!("{:?}", expandable_message);
        digest.reset();
        for c in expandable_message.pairs.iter() {
            digest.update(&c.0);
        }
        println!("{:?}", digest);
        digest.reset();
        for c in expandable_message.pairs.iter() {
            digest.update(&c.1);
        }
        println!("{:?}", digest);

        let limit = (1 << k) + k - 1;
        println!("Actually expanding");
        let mut expected = None;
        for len in k..=limit {
            let m = expand_message(&expandable_message, len)?;
            // println!("m = {}", m.encode_hex::<String>());
            assert_eq!(len * RD1::block_size(), m.len());
            digest.reset();
            digest.update(&m);
            // println!("{:?}", digest);
            if let Some(expected) = expected {
                assert_eq!(expected, digest.state);
            } else {
                expected = Some(digest.state);
            }
        }
        Ok(())
    }

    #[test]
    fn challenge53() -> Result<()> {
        let mut rd1 = RD1::default();
        let mut rng = OsRng;
        let mut msg = vec![0u8; RD1::block_size() * (1 << 20)];
        rng.fill_bytes(&mut msg);
        rd1.update(&msg);
        let expected_hash = rd1.digest();

        let preimage = second_preimage(&msg, &rd1.initial, RD1::block_size(), RD1::compress)?;
        rd1.update(&preimage.0);
        let actual_hash = rd1.digest();

        assert_eq!(expected_hash, actual_hash);
        assert_ne!(msg, preimage.0);

        rd1.reset();
        rd1.update(&msg);
        println!("rd1(..) -> {}", rd1.digest().encode_hex::<String>());

        rd1.reset();
        rd1.update(&preimage.0);
        println!("rd1(..) -> {}", rd1.digest().encode_hex::<String>());

        println!("compressions executed: {}", preimage.1);
        Ok(())
    }

    #[test]
    #[ignore = "smoke"]
    fn challenge54_smoke() -> Result<()> {
        let k = 3;
        let tail =
            build_nostradamus_tail_parts(k, RD1::block_size(), RD1::digest_size(), RD1::compress)?;

        println!("{:?}", tail);

        let mut rd1 = RD1::default();
        for (idx, elem) in tail.0.iter().enumerate().skip(1).rev() {
            println!("{}: {:?}", idx, elem);
            rd1.reset();
            rd1.state.copy_from_slice(&elem.h_in);
            rd1.update(&elem.bridge);
            println!("\t{:?}", rd1.state);
        }

        println!();
        let targets = 1 << k;
        for idx in targets..(2 * targets) {
            rd1.reset();
            rd1.state.copy_from_slice(&tail.0[idx].h_in);
            let tmp = build_nostradamus_tail(&tail.0, idx);
            println!("{}, {:?}", idx, tmp);
            rd1.update(&tmp);
            println!("\t{:?}", rd1.state);
            assert_eq!(rd1.state.to_vec(), tail.0[1].h_in);
        }
        Ok(())
    }

    #[test]
    #[ignore = "slow"]
    fn challenge54() -> Result<()> {
        let commitment = build_nostradamus_commitment(
            2,
            10,
            RD1::compress,
            RD1::block_size(),
            RD1::digest_size(),
        )?;

        let mut rd1 = RD1::default();
        rd1.state.copy_from_slice(&commitment.pre_hash);
        rd1.length = commitment.total_length * RD1::block_size();
        let committed_hash = rd1.digest();
        println!("Committed hash = {}", committed_hash.encode_hex::<String>());

        // Messages!
        let msgs = vec![
            //123456789abcdef0123456789abcdef
            "Star wars is the best!",
            "Star trek is the best!",
            "I prefer Battlestar Galactica",
            "Babylon 5 is underloved.",
        ];
        for m in msgs {
            println!("{}", m);
            let mut padded_base = m.as_bytes().to_vec();
            padded_base.resize(2 * RD1::block_size(), 0);
            let forged_msg = build_nostradamus_result(
                &commitment.tail_parts,
                &padded_base,
                &[0u8; 16],
                RD1::compress,
            )?;
            rd1.reset();
            rd1.update(&forged_msg.0);
            let forged_commitment = rd1.digest();
            println!(
                "\t{}\n{} with {}+{}={} compressions",
                forged_msg.0.encode_hex::<String>(),
                forged_commitment.encode_hex::<String>(),
                commitment.compressions,
                forged_msg.1,
                commitment.compressions + forged_msg.1
            );
            assert_eq!(committed_hash, forged_commitment);
        }
        Ok(())
    }

    #[test]
    #[ignore = "Not working"]
    fn challenge55_smoke() -> Result<()> {
        // let mut msg = vec![0u8; MD4::block_size()];
        // let mut rng = OsRng;
        // let used_constraints = &MD4CollisionConstraints;
        for _ in 0..10 {
            let msg = create_md4_collision_candidate()?;
            // rng.fill_bytes(&mut msg);
            // println!("Old msg: {}", msg.encode_hex::<String>());
            let block: Vec<u32> = to_w32_be(&msg).iter().map(|w| u32::from_be(*w)).collect();
            // let state = apply_md4_constraints(&mut block, &MD4CollisionConstraints[0..16]);
            // let msg = block
            //     .iter()
            //     .flat_map(|b| b.to_le_bytes())
            //     .collect::<Vec<u8>>();

            // apply_md4_round2_contraints(&mut block, state, &MD4CollisionConstraints);
            // println!("New msg: {}", msg.encode_hex::<String>());

            verify_md4_constraints(&block, &MD4CollisionConstraints[0..17])?;

            // MD4::oneshot_digest(&msg);
            println!();
        }

        // let sample = hex::decode("a6af943ce36f0cf4adcb12bef7f0dc1f526dd914bd3da3cafde14467ab129e640b4c41819915cb43db752155ae4b895fc71b9b0d384d06ef3118bbc643ae6384")?;
        // let block: Vec<u32> = to_w32_be(&sample)
        //     .iter()
        //     .map(|w| u32::from_be(*w))
        //     .collect();
        // verify_md4_constraints(&block, &MD4CollisionConstraints)?;

        Ok(())
    }

    #[test]
    #[ignore = "Not working"]
    fn challenge55() -> Result<()> {
        let collision = create_md4_collision(1)?;
        println!("After {} attempts", collision.2);
        assert_ne!(collision.0, collision.1);
        let hash1: String = MD4::oneshot_digest(&collision.0).encode_hex();
        let hash2: String = MD4::oneshot_digest(&collision.1).encode_hex();
        assert_eq!(hash1, hash2);

        Ok(())
    }

    #[test]
    // #[ignore = "slow"]
    fn challenge56_detect_bias() -> Result<()> {
        // Second byte should be zero 1/128 of the time
        let trials = 4096000;
        let mut zero_count = 0;
        let zeros = [0u8; 32];

        let mut length_bias_count = 0;
        for _ in 0..trials {
            let mut key = Rc4Key::random();
            let ciphertext = key.crypt(&zeros);
            // key.next_byte();
            if ciphertext[1] == 0 {
                zero_count += 1;
            }

            if ciphertext[31] == 224 {
                length_bias_count += 1;
            }
        }
        let expected = trials / 256;
        println!("Expected = {}, actual = {}", expected, zero_count);
        assert!(zero_count as f32  >= (expected as f32 * 1.5));

        println!("Expected = {}, actual = {}", expected, length_bias_count);
        assert!(length_bias_count as f32  >= (expected as f32 * 1.002));
        Ok(())
    }

    // #[test]
    fn challenge56_generate_table() -> Result<()> {
        let pool_size = 12;
        let trials = 1usize << 32;
        let f_trials = trials as f64;

        let pool: Pool<ThunkWorker<Vec<u8>>> = Pool::new(pool_size);
        let (tx, rx) = channel();
        let mut counts = [[0f64; 256]; 32];

        let mut i = 0;
        println!("Active count: {}", pool.active_count());
        for _ in 0..=pool_size {
            println!("Enqueed");
            pool.execute_to(tx.clone(), Thunk::of(|| {
                let zeros = [0u8; 32];
                Rc4Key::random().crypt(&zeros) }));
        }
        println!("Active count: {}", pool.active_count());

        while i < trials {
            // println!("Fod");
            if i % (1025 * 1025) == 0 {
                println!("Trial {} ({})", i, (i as f64 / f_trials));
            }
            let tmp = rx.recv()?;
            for (idx, val) in tmp.iter().enumerate() {
                counts[idx][*val as usize] += 1f64;
            }
            i += 1;

            pool.execute_to(tx.clone(), Thunk::of(|| {
                let zeros = [0u8; 32];
                Rc4Key::random().crypt(&zeros) }));
        }
        // for _i in 0..(trials / pool_size) {
        //     for _ in 0..pool_size {            
        //     pool.execute_to(tx.clone(), Thunk::of(|| {
        //         let zeros = [0u8; 32];
        //         Rc4Key::random().crypt(&zeros) }));
        //     }


        //     let mut key = Rc4Key::random();
        //     for r_count in counts.iter_mut() {
        //         r_count[key.next_byte() as usize] += 1f64;
        //     }
        // }


        for r_count in counts.iter_mut() {
            for elem in r_count.iter_mut() {
                *elem /= f_trials;
            }
        }

        println!("{:?}", counts);
        Ok(())
    }

    #[test]
    fn challenge56_recovery_smoke() -> Result<()> {
        let target = [0u8, 7u8];
        let mut counts = [0usize; 256];
        for _i in 0..10240 {
            let mut key = Rc4Key::random();
            let ct = key.crypt(&target);
            counts[ct[1] as usize] += 1;
        }
        println!("Counts = {:?}", counts);
        let recovered = rc4_single_byte_attack(counts, 1, &crate::rc4::distribution::DISTRIBUTION)?;
        assert_eq!(recovered, target[1]);
        Ok(())
    }
}
