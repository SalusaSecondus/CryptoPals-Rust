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
                println!(
                    "Candidate next: {} => {} by {:?}",
                    a_next, fixed_a1, constraint
                );
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
        step, state[0], state[1], state[2], state[3]
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
    Ok(msg1)
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
    for u in 10..=126 {
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
        aes::AesKey,
        oracles::{Challenge49Oracle, Challenge51Oracle, Challenge56Oracle},
        padding::Padding,
        rc4::{Rc4Key, RC4_DISTRIBUTION},
        xor,
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
        assert!(zero_count as f32 >= (expected as f32 * 1.5));

        println!("Expected = {}, actual = {}", expected, length_bias_count);
        assert!(length_bias_count as f32 >= (expected as f32 * 1.002));
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
            pool.execute_to(
                tx.clone(),
                Thunk::of(|| {
                    let zeros = [0u8; 32];
                    Rc4Key::random().crypt(&zeros)
                }),
            );
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

            pool.execute_to(
                tx.clone(),
                Thunk::of(|| {
                    let zeros = [0u8; 32];
                    Rc4Key::random().crypt(&zeros)
                }),
            );
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
        let target = [0u8, b'A'];
        let mut counts = [0usize; 256];
        for _i in 0..10240 {
            let mut key = Rc4Key::random();
            let ct = key.crypt(&target);
            counts[ct[1] as usize] += 1;
        }
        println!("Counts = {:?}", counts);
        let recovered = rc4_single_byte_attack(counts, 1, &RC4_DISTRIBUTION)?;
        assert_eq!(recovered, target[1]);
        Ok(())
    }

    #[test]
    fn challenge56() -> Result<()> {
        let oracle = Challenge56Oracle::new();
        let length = oracle.encrypt(&[]).len();
        let mut counts = vec![[33390888, 33398452, 33391146, 33393479, 33393729, 33406424, 33397896, 33396764, 33396680, 33403682, 33396079, 33404140, 33393986, 33404054, 33397989, 33405167, 33397695, 33402558, 33398428, 33408773, 33405927, 33399774, 33408498, 33405712, 33402904, 33419997, 33399421, 33413041, 33411549, 33399285, 33415429, 33398106, 33408701, 33416204, 33419602, 33402897, 33423531, 33408329, 33396824, 33420941, 33400914, 33414650, 33398709, 33420525, 33419296, 33412904, 33408884, 33414634, 33418802, 33419199, 33415001, 33422302, 33420619, 33414309, 33424353, 33428411, 33420443, 33424688, 33411601, 33414370, 33422858, 33425719, 33423345, 33422812, 33122232, 33319977, 67150295, 33277779, 33336688, 33336760, 33326307, 33332089, 33331964, 33336491, 33325874, 33346195, 33345748, 33340534, 33342297, 33335629, 33350376, 33345678, 33342605, 33352091, 33366423, 33363043, 33354942, 33355640, 33358900, 33360001, 33359298, 33362257, 33361286, 33347459, 33357323, 33354822, 33356594, 33366618, 33365742, 33371481, 33385151, 33383360, 33373721, 33373311, 33371220, 33379090, 33372115, 33385956, 33371561, 33372260, 33380414, 33377307, 33376381, 33379954, 33380551, 33384613, 33376746, 33390018, 33388873, 33381133, 33380490, 33394596, 33386329, 33393114, 33392160, 33401367, 33393095, 33389764, 33461079, 33473812, 33460285, 33470547, 33461971, 33463346, 33463434, 33468707, 33470509, 33474805, 33461743, 33467823, 33472886, 33451348, 33468426, 33471321, 33470105, 33467976, 33464865, 33479691, 33465704, 33473839, 33473929, 33471000, 33469210, 33475114, 33481944, 33474222, 33489245, 33469317, 33484662, 33476648, 33465086, 33490088, 33475475, 33486138, 33477917, 33476083, 33489066, 33478628, 33481637, 33485430, 33470262, 33481039, 33481905, 33474476, 33485434, 33475603, 33481215, 33485538, 33473310, 33489631, 33484974, 33485693, 33475664, 33486731, 33477705, 33497095, 33483678, 33499267, 33506691, 33488461, 33486178, 33486573, 33420677, 33418356, 33416851, 33317571, 33423187, 33424821, 33416917, 33426493, 33441302, 33438134, 33420809, 33442774, 33440104, 33424985, 33433536, 33434444, 33434867, 33433442, 33430162, 33438582, 33439362, 33439605, 33433830, 33444633, 33440670, 33448859, 33441979, 33450123, 33450672, 33439370, 33445915, 33442001, 33446473, 33453367, 33441015, 33451090, 33446663, 33455461, 33445782, 33453353, 33451584, 33456787, 33448929, 33451626, 33447378, 33447893, 33577292, 33447505, 33452315, 33455464, 33451926, 33469904, 33461050, 33465331, 33452021, 33461461, 33455492, 33465262, 33452422, 33456777, 33477925, 33465344, 33449580, 33464786], [33534343, 33527566, 33529254, 33537769, 33538925, 33531692, 33534175, 33532923, 33542635, 33535456, 33538163, 33535650, 33531194, 33524361, 33536086, 33538247, 33538467, 33529793, 33530042, 33534270, 33536963, 33542060, 33536411, 33534293, 33542424, 33539225, 33546697, 33529388, 33539038, 33551360, 33541851, 33534160, 33538703, 33541600, 33538977, 33540512, 33535375, 33540726, 33540541, 33545736, 33539207, 33545588, 33535606, 33533025, 33548583, 33530982, 33529331, 33538129, 33543425, 33545659, 33548969, 33533939, 33542431, 33537053, 33540185, 33536198, 33547473, 33548511, 33544548, 33559932, 33529112, 33549132, 33551081, 33542847, 33518455, 33514015, 33529554, 33510158, 33538914, 33601436, 33581401, 33519406, 33517212, 33517295, 33525967, 33519128, 33528887, 33505108, 33516120, 33520730, 33517626, 33521768, 33528571, 33516343, 33520360, 33524613, 33514299, 33518597, 33533285, 33519917, 33527793, 33530392, 33524942, 33517295, 33524252, 33530711, 33526169, 33526692, 33524439, 33521364, 33536249, 33536300, 33527513, 33531913, 33526554, 33533685, 33525800, 33527540, 33529893, 33533318, 33520569, 33527910, 33536678, 33532147, 33524518, 33530961, 33534166, 33525324, 33536691, 33529374, 33536148, 33533994, 33534130, 33528775, 33524886, 33528706, 33530449, 33529673, 33572353, 33573559, 33569205, 33579095, 33574625, 33565328, 33581637, 33564578, 33569285, 33578223, 33587575, 33571884, 33579832, 33574585, 33582613, 33586287, 33581277, 33591260, 33584294, 33592796, 33574919, 33582125, 33584285, 33574914, 33573368, 33589882, 33588650, 33581478, 33585444, 33580280, 33584990, 33581118, 33599864, 33592768, 33599427, 33604010, 33597833, 33594694, 33590838, 33592462, 33603225, 33591195, 33604576, 33596588, 33602812, 33592016, 33592524, 33594250, 33605473, 33603414, 33608856, 33612231, 33597760, 33592583, 33595850, 33596868, 33609046, 33606813, 33616610, 33607488, 33607399, 33613362, 33606819, 33605770, 33550694, 33547229, 33544535, 33543954, 33544068, 33556673, 33670125, 33543049, 33543413, 33549555, 33549956, 33556896, 33551410, 33543652, 33544670, 33556786, 33551312, 33557900, 33554098, 33554769, 33559760, 33561730, 33558991, 33547378, 33563975, 33552084, 33566375, 33562079, 33547742, 33551808, 33565174, 33545560, 33560838, 33562386, 33560297, 33564918, 33559177, 33555658, 33567919, 33553188, 33566656, 33574102, 33562492, 33563684, 33563666, 33565863, 33565575, 33563729, 33568017, 33563831, 33568312, 33562462, 33567628, 33567097, 33569583, 33566367, 33570432, 33566955, 33569266, 33574795, 33570159, 33557271, 33575496, 33567130], [33521988, 33520954, 33526658, 33523890, 33522643, 33529121, 33523535, 33529232, 33529756, 33529254, 33534406, 33512022, 33525715, 33526386, 33526996, 33531320, 33529574, 33525526, 33531748, 33529897, 33530259, 33530784, 33524848, 33532698, 33525627, 33518048, 33529741, 33530370, 33536613, 33523269, 33524344, 33528042, 33727483, 33551852, 33660038, 33525426, 33712779, 33512449, 33522518, 33521542, 33522689, 33519296, 33521153, 33514595, 33518973, 33511620, 33516845, 33517451, 33536509, 33529641, 33517137, 33514544, 33513399, 33525126, 33526135, 33522004, 33535985, 33518597, 33524613, 33523903, 33521022, 33524677, 33521181, 33518019, 33534974, 33553118, 33531563, 33543908, 33542169, 33523701, 33537003, 33532329, 33543563, 33544134, 33531162, 33534274, 33539405, 33543951, 33535867, 33544643, 33544587, 33542762, 33553622, 33552245, 33539338, 33543033, 33545152, 33538401, 33542511, 33544175, 33542117, 33551325, 33545734, 33545823, 33547862, 33550715, 33527669, 33528048, 33531398, 33533635, 33534216, 33536577, 33526196, 33530958, 33526688, 33537276, 33530532, 33530576, 33538637, 33533761, 33533050, 33535900, 33533723, 33531938, 33529920, 33530431, 33533714, 33545562, 33522383, 33529184, 33538213, 33541152, 33535388, 33544698, 33535406, 33533416, 33543089, 33540048, 33551618, 33560443, 33550376, 33559602, 33570016, 33559229, 33553694, 33562553, 33561426, 33563989, 33556415, 33557681, 33554355, 33565892, 33550470, 33555177, 33561499, 33572746, 33568130, 33554831, 33556034, 33570131, 33565415, 33564417, 33563839, 33569049, 33576700, 33567749, 33561751, 33570364, 33561914, 33568716, 33547015, 33545336, 33550289, 33546206, 33538702, 33556576, 33554526, 33550853, 33552263, 33549019, 33546277, 33552496, 33556310, 33558407, 33554689, 33546712, 33552131, 33552363, 33547899, 33562331, 33549709, 33555645, 33552328, 33547022, 33561078, 33566680, 33550218, 33549277, 33553713, 33559583, 33556764, 33559605, 33592659, 33586317, 33595915, 33598649, 33589038, 33601282, 33592922, 33595680, 33593940, 33596025, 33583412, 33610734, 33593609, 33593437, 33598640, 33596113, 33591110, 33599784, 33608137, 33601694, 33598630, 33597360, 33602404, 33606873, 33605538, 33601722, 33603815, 33616709, 33601618, 33601700, 33611822, 33616900, 33575157, 33575474, 33570623, 33564791, 33572893, 33575613, 33577292, 33584423, 33572787, 33570296, 33579737, 33576515, 33580154, 33583193, 33576083, 33583272, 33581898, 33578826, 33576524, 33574272, 33575673, 33589165, 33588688, 33583975, 33571096, 33583316, 33583886, 33584771, 33585840, 33586265, 33591753, 33584897], [33534489, 33540727, 33541711, 33525483, 33539277, 33539167, 33539254, 33538837, 33546022, 33543003, 33534770, 33541331, 33534401, 33531158, 33544897, 33540443, 33542168, 33530479, 33526921, 33533485, 33525206, 33535483, 33537143, 33532567, 33533257, 33530650, 33542210, 33538922, 33536825, 33537918, 33535244, 33527107, 33548995, 33538998, 33544838, 33541090, 33541911, 33544099, 33535572, 33543439, 33539826, 33542996, 33550372, 33546498, 33552130, 33540114, 33545169, 33541435, 33536932, 33546963, 33543002, 33547306, 33537222, 33537446, 33538949, 33543989, 33531943, 33546581, 33541304, 33528702, 33547396, 33533263, 33539349, 33547906, 33522388, 33511413, 33526987, 33514982, 33524126, 33521198, 33522054, 33522169, 33521609, 33519291, 33522090, 33519547, 33525168, 33517890, 33531749, 33514769, 33549356, 33541308, 33535184, 33716726, 33521388, 33513643, 33755549, 33537449, 33516849, 33519372, 33515051, 33526281, 33507834, 33519144, 33515381, 33522797, 33529425, 33530424, 33522555, 33530896, 33531741, 33529792, 33517207, 33534193, 33544285, 33531190, 33528106, 33515701, 33522078, 33526076, 33522634, 33535083, 33527059, 33524849, 33529086, 33531008, 33526592, 33526920, 33531266, 33528472, 33520630, 33530634, 33514066, 33529037, 33519493, 33516394, 33521298, 33528149, 33585088, 33579429, 33586790, 33576119, 33580152, 33584391, 33586678, 33588200, 33585620, 33582233, 33578325, 33586795, 33599463, 33582957, 33584431, 33586274, 33573617, 33568614, 33570293, 33567568, 33579890, 33574916, 33583670, 33570503, 33572828, 33580026, 33585968, 33578029, 33578346, 33574959, 33578580, 33575035, 33605682, 33603809, 33612178, 33606280, 33594093, 33618304, 33614670, 33603597, 33604864, 33598191, 33612145, 33610941, 33611949, 33601935, 33618972, 33599445, 33602034, 33591229, 33585985, 33590667, 33593645, 33578701, 33586074, 33591254, 33588624, 33599815, 33582865, 33598333, 33592434, 33608161, 33598137, 33596887, 33544863, 33543743, 33540362, 33557490, 33548421, 33544252, 33548128, 33544522, 33552394, 33563773, 33561697, 33551404, 33556580, 33552794, 33552118, 33565567, 33547545, 33537408, 33547279, 33548698, 33555818, 33550460, 33554845, 33547213, 33550488, 33548667, 33547663, 33548413, 33546692, 33545036, 33549760, 33542717, 33576065, 33560435, 33560419, 33570946, 33562026, 33565318, 33561639, 33568252, 33572416, 33577996, 33571431, 33575232, 33576445, 33567779, 33569671, 33569555, 33557502, 33565728, 33554168, 33560657, 33559240, 33565330, 33557863, 33554465, 33557659, 33565018, 33553837, 33561142, 33567836, 33561093, 33556380, 33553181], [33530625, 33532804, 33535907, 33535677, 33545116, 33535865, 33539667, 33529189, 33536709, 33538658, 33547903, 33531501, 33537354, 33532811, 33540839, 33539407, 33540170, 33535252, 33539433, 33536909, 33525668, 33530438, 33516998, 33525653, 33536032, 33535467, 33536969, 33533728, 33533842, 33535156, 33539679, 33538648, 33538283, 33525126, 33546077, 33542164, 33539843, 33538047, 33539636, 33547542, 33542786, 33542407, 33536015, 33550211, 33546754, 33544286, 33556183, 33549977, 33536363, 33542695, 33540953, 33555248, 33537999, 33537669, 33548158, 33538988, 33537976, 33535480, 33541756, 33549131, 33531365, 33535778, 33544955, 33544593, 33517902, 33525925, 33519789, 33517038, 33520933, 33515590, 33524376, 33516201, 33529530, 33523589, 33516842, 33524819, 33521889, 33520307, 33514855, 33523584, 33542317, 33528069, 33508046, 33762879, 33551254, 33729433, 33531444, 33533910, 33534512, 33514666, 33528372, 33526195, 33518212, 33526222, 33511561, 33523717, 33518272, 33518519, 33522718, 33519908, 33529937, 33525910, 33530255, 33526908, 33536756, 33531361, 33531331, 33541527, 33539159, 33524868, 33527915, 33534468, 33527929, 33520177, 33527057, 33533942, 33519843, 33519200, 33519020, 33523673, 33532332, 33523977, 33530281, 33534118, 33532399, 33513481, 33526847, 33525109, 33582398, 33582691, 33580705, 33584927, 33579681, 33582190, 33585898, 33587354, 33585009, 33584015, 33597863, 33593937, 33583362, 33590581, 33591358, 33581509, 33576455, 33566700, 33585554, 33577880, 33568333, 33581188, 33571138, 33573864, 33568943, 33576685, 33579968, 33580253, 33574290, 33567086, 33564984, 33575666, 33599843, 33596652, 33596874, 33602572, 33599113, 33600544, 33610203, 33594608, 33614057, 33616955, 33609047, 33622533, 33601008, 33587674, 33603176, 33593957, 33585880, 33586484, 33609355, 33597536, 33593987, 33596483, 33584491, 33593111, 33606800, 33598432, 33606711, 33595097, 33576499, 33593773, 33602338, 33599539, 33557965, 33548551, 33561083, 33556020, 33552195, 33556862, 33542155, 33550940, 33554874, 33556428, 33557189, 33552803, 33556010, 33564552, 33546176, 33563045, 33563588, 33538095, 33550775, 33543332, 33542331, 33555173, 33549949, 33538420, 33559175, 33550675, 33552506, 33547418, 33531856, 33552279, 33534144, 33547588, 33564046, 33562185, 33566130, 33560530, 33565428, 33558334, 33563704, 33571107, 33576228, 33562536, 33570615, 33559976, 33565585, 33563654, 33569147, 33563994, 33560284, 33557103, 33566998, 33567176, 33560764, 33559041, 33570848, 33558105, 33553345, 33558583, 33564444, 33561978, 33557859, 33559125, 33562066, 33554032], [33534887, 33525122, 33538326, 33533992, 33540010, 33539065, 33532113, 33537793, 33535768, 33540381, 33530589, 33535450, 33533054, 33539668, 33531627, 33531570, 33525808, 33523273, 33534588, 33528681, 33537502, 33536988, 33526926, 33533089, 33538596, 33533779, 33535545, 33537874, 33537213, 33535607, 33527000, 33529721, 33540129, 33534580, 33547321, 33540732, 33557746, 33539387, 33531569, 33541504, 33542967, 33548788, 33537004, 33536264, 33547149, 33549663, 33537274, 33547909, 33531737, 33535304, 33536256, 33539294, 33535539, 33542593, 33532124, 33541172, 33536493, 33542838, 33538279, 33545856, 33531159, 33549199, 33532042, 33540828, 33518825, 33531239, 33521376, 33518156, 33530469, 33518832, 33527605, 33532029, 33522009, 33515478, 33514556, 33519755, 33520870, 33523882, 33518269, 33523165, 33542850, 33538033, 33735842, 33539132, 33535479, 33758803, 33538711, 33541001, 33515509, 33512922, 33510738, 33526157, 33512599, 33516237, 33524653, 33519755, 33524404, 33534594, 33531374, 33523800, 33538263, 33517684, 33511026, 33527720, 33521277, 33531472, 33534835, 33530348, 33525493, 33520335, 33527637, 33527652, 33527643, 33533686, 33526753, 33517082, 33536096, 33530291, 33518869, 33526077, 33522068, 33525388, 33523873, 33528251, 33524385, 33524051, 33528779, 33519376, 33576502, 33585814, 33583174, 33579575, 33586150, 33593261, 33581053, 33580076, 33587916, 33590287, 33588037, 33588924, 33585577, 33592398, 33580407, 33586380, 33579211, 33574218, 33576709, 33569488, 33564629, 33577957, 33569499, 33570629, 33573888, 33583458, 33574975, 33583712, 33578214, 33584897, 33575997, 33575351, 33601239, 33594954, 33599048, 33593255, 33601284, 33605994, 33613939, 33595334, 33604573, 33612433, 33602051, 33600904, 33601030, 33609413, 33599719, 33599190, 33592324, 33595802, 33600633, 33593553, 33587012, 33596010, 33587398, 33588436, 33587100, 33594520, 33585656, 33597514, 33597787, 33604281, 33601493, 33591092, 33552249, 33559195, 33545969, 33549939, 33546117, 33554954, 33544248, 33563604, 33554846, 33562294, 33561569, 33561699, 33557137, 33555119, 33554307, 33553237, 33548617, 33555433, 33554343, 33536515, 33554292, 33550484, 33549645, 33545660, 33555347, 33567396, 33546382, 33548841, 33551994, 33556228, 33550193, 33548789, 33572198, 33566041, 33557968, 33570077, 33565866, 33569725, 33562625, 33576706, 33567808, 33564073, 33575887, 33573112, 33562427, 33578920, 33578400, 33571495, 33555177, 33559078, 33561389, 33551607, 33547896, 33566814, 33548328, 33552906, 33576106, 33564075, 33557533, 33565177, 33562028, 33563594, 33568280, 33573478], [33531978, 33521230, 33531266, 33529255, 33542980, 33533969, 33540748, 33522705, 33521150, 33534410, 33536767, 33534960, 33528381, 33531999, 33524356, 33536069, 33537543, 33534768, 33539553, 33526112, 33532295, 33541576, 33536068, 33532710, 33539799, 33536891, 33532725, 33534476, 33533410, 33534616, 33531571, 33528467, 33536695, 33539194, 33543178, 33543942, 33545977, 33534964, 33541383, 33538049, 33541623, 33552038, 33546220, 33538294, 33543990, 33534136, 33544799, 33540590, 33534676, 33535863, 33548162, 33537749, 33546073, 33537988, 33542915, 33539446, 33542205, 33542179, 33550296, 33549919, 33550730, 33543443, 33540297, 33550570, 33535286, 33551062, 33540113, 33534370, 33541503, 33729179, 33539164, 33540594, 33516330, 33518812, 33512890, 33516072, 33515228, 33751499, 33504867, 33521745, 33522489, 33512842, 33530798, 33524220, 33530187, 33517792, 33516453, 33522455, 33529778, 33526177, 33520178, 33520150, 33526358, 33530116, 33516243, 33518546, 33516890, 33529867, 33535185, 33534026, 33525524, 33521078, 33529209, 33518079, 33530835, 33519675, 33522319, 33534441, 33533879, 33536052, 33534727, 33521370, 33524285, 33529994, 33529732, 33524779, 33529492, 33520321, 33532994, 33535130, 33530627, 33537053, 33520296, 33532487, 33534472, 33525262, 33521374, 33522320, 33569000, 33568787, 33585800, 33574403, 33570930, 33575835, 33571679, 33569206, 33583991, 33574085, 33578091, 33576474, 33576527, 33582362, 33578247, 33575127, 33583953, 33580227, 33591031, 33576376, 33575973, 33584475, 33583111, 33582477, 33598240, 33578443, 33583252, 33590038, 33593313, 33586898, 33596051, 33585271, 33596486, 33588692, 33588054, 33584161, 33584784, 33593547, 33592571, 33583291, 33592376, 33591739, 33606720, 33607865, 33597258, 33588978, 33597876, 33588374, 33606576, 33597712, 33601596, 33598296, 33604998, 33599623, 33595468, 33593525, 33603211, 33607887, 33610921, 33603323, 33599497, 33605649, 33615226, 33605099, 33544943, 33547411, 33547132, 33554139, 33551813, 33549177, 33554055, 33538749, 33561121, 33555052, 33541714, 33554172, 33550628, 33551334, 33558433, 33552117, 33557233, 33557372, 33552637, 33550949, 33545365, 33549574, 33548355, 33555829, 33560867, 33557666, 33545825, 33552863, 33555332, 33559984, 33557868, 33556024, 33547406, 33547591, 33560528, 33549260, 33548820, 33559122, 33559630, 33556407, 33569142, 33560362, 33568513, 33567495, 33559499, 33549784, 33551340, 33565255, 33568950, 33568911, 33570066, 33574121, 33574830, 33562495, 33567798, 33567510, 33574577, 33563555, 33567279, 33565905, 33565479, 33562217, 33563238, 33571066], [33520308, 33533119, 33524039, 33528207, 33528388, 33522556, 33527893, 33526718, 33528059, 33521504, 33519118, 33522533, 33523006, 33539521, 33530148, 33530362, 33532667, 33531725, 33521887, 33528645, 33514376, 33525217, 33525206, 33528778, 33521269, 33522547, 33528778, 33521262, 33536967, 33522700, 33525565, 33538887, 33730416, 33537851, 33540702, 33536526, 33538071, 33533009, 33544028, 33542941, 33537132, 33751048, 33521250, 33524673, 33516719, 33506815, 33512963, 33513068, 33517650, 33522425, 33526317, 33514593, 33521744, 33531126, 33519008, 33522705, 33513164, 33524898, 33518104, 33519043, 33542475, 33517315, 33529381, 33529182, 33544434, 33540796, 33533718, 33535868, 33534523, 33542542, 33536047, 33533678, 33541502, 33537040, 33540110, 33529658, 33546967, 33542346, 33545137, 33537191, 33547542, 33547833, 33551839, 33549879, 33536629, 33533127, 33541371, 33543583, 33548736, 33547247, 33538011, 33554567, 33534102, 33539452, 33545687, 33543034, 33540057, 33530231, 33520059, 33532612, 33536757, 33522133, 33527489, 33530688, 33528341, 33524482, 33534986, 33540660, 33517272, 33546899, 33535569, 33534085, 33529122, 33536942, 33533191, 33535041, 33545022, 33531927, 33543523, 33526699, 33537949, 33527570, 33540596, 33536816, 33541008, 33533607, 33533234, 33543724, 33558364, 33560798, 33556679, 33553825, 33560027, 33562019, 33558836, 33571234, 33563036, 33558095, 33552344, 33564204, 33563213, 33563717, 33564180, 33560251, 33557921, 33560793, 33570576, 33566121, 33568165, 33562522, 33568996, 33566718, 33575095, 33573267, 33565335, 33562043, 33567333, 33574364, 33573196, 33581250, 33549358, 33541495, 33547619, 33543314, 33550440, 33558121, 33545263, 33534147, 33543653, 33550817, 33547798, 33548846, 33548353, 33538949, 33552764, 33543035, 33560134, 33554528, 33534617, 33548976, 33546622, 33552447, 33557787, 33555268, 33546301, 33558695, 33562502, 33551803, 33548854, 33556539, 33551488, 33568967, 33585893, 33588718, 33585528, 33597609, 33590459, 33597293, 33594681, 33592233, 33590777, 33591460, 33589295, 33611320, 33600037, 33598867, 33606905, 33593228, 33608134, 33601094, 33597308, 33605645, 33596810, 33602123, 33601994, 33600987, 33597357, 33600373, 33602217, 33614728, 33622243, 33606342, 33611264, 33608332, 33578877, 33567332, 33572017, 33573115, 33568034, 33577518, 33574618, 33582093, 33572580, 33580745, 33573282, 33588550, 33577537, 33576528, 33587485, 33568241, 33579380, 33579686, 33573395, 33581571, 33582320, 33580498, 33583804, 33583851, 33594162, 33581101, 33588805, 33589678, 33589151, 33583859, 33596516, 33582208], [33528793, 33533964, 33532208, 33538663, 33541830, 33538148, 33535776, 33537212, 33542897, 33545625, 33537081, 33533030, 33535184, 33541518, 33537732, 33543889, 33528566, 33532893, 33538398, 33528661, 33521873, 33525276, 33531845, 33534072, 33523528, 33538970, 33530887, 33524618, 33540181, 33533864, 33529301, 33534324, 33544356, 33546281, 33544747, 33539191, 33539068, 33548252, 33547131, 33544172, 33553185, 33539281, 33545205, 33554984, 33543568, 33540019, 33542644, 33544793, 33538101, 33534912, 33547359, 33542160, 33536200, 33538269, 33533698, 33538901, 33530240, 33544633, 33535394, 33540706, 33531919, 33534919, 33548618, 33536890, 33520933, 33518084, 33532994, 33526336, 33515826, 33515080, 33518209, 33523414, 33528294, 33523861, 33516997, 33528302, 33520775, 33519816, 33510926, 33519080, 33542612, 33538368, 33543447, 33528947, 33721816, 33539703, 33541799, 33548409, 33515821, 33518289, 33517921, 33531855, 33540091, 33540319, 33752542, 33520448, 33517258, 33533980, 33526507, 33540725, 33529763, 33524437, 33529658, 33528663, 33522003, 33516895, 33529043, 33538622, 33544762, 33529933, 33526558, 33527814, 33528097, 33532268, 33522530, 33521175, 33521710, 33515489, 33521051, 33525760, 33524559, 33524272, 33525178, 33535415, 33528163, 33537015, 33524331, 33530595, 33584450, 33578836, 33576676, 33585041, 33585281, 33583367, 33573746, 33580734, 33588158, 33580029, 33586410, 33590578, 33587574, 33578094, 33583280, 33586728, 33578419, 33572442, 33565038, 33572051, 33561075, 33574918, 33572757, 33585536, 33583049, 33578960, 33584694, 33581429, 33575515, 33576898, 33573972, 33573472, 33591024, 33593969, 33605514, 33609688, 33604242, 33595325, 33597297, 33601362, 33606846, 33619246, 33604751, 33620488, 33603535, 33605136, 33615405, 33597254, 33596979, 33585717, 33590341, 33592895, 33584585, 33594998, 33593271, 33585232, 33598189, 33594539, 33594657, 33591432, 33589323, 33592332, 33590457, 33607079, 33551921, 33557808, 33551141, 33560955, 33553459, 33556130, 33546835, 33559392, 33544106, 33553069, 33564007, 33559860, 33556783, 33554874, 33552998, 33551032, 33548463, 33545902, 33552079, 33551242, 33546568, 33538798, 33548220, 33550879, 33543818, 33554862, 33545186, 33544761, 33555977, 33549655, 33545334, 33548775, 33567594, 33563376, 33548725, 33569333, 33551297, 33570758, 33565522, 33563810, 33571911, 33562954, 33566493, 33567102, 33569476, 33566607, 33568847, 33561299, 33563345, 33567042, 33561928, 33552113, 33545581, 33558473, 33552101, 33561603, 33558855, 33572758, 33565640, 33562163, 33561446, 33566338, 33551808, 33564944], [33535147, 33528788, 33532659, 33526487, 33524408, 33526307, 33532252, 33523621, 33539008, 33528915, 33520861, 33528424, 33541342, 33530904, 33529054, 33542347, 33539248, 33533016, 33528936, 33537919, 33540305, 33534366, 33530261, 33531885, 33540628, 33531768, 33524903, 33536563, 33530483, 33539524, 33542201, 33538089, 33534584, 33542013, 33544787, 33537032, 33555711, 33545137, 33542924, 33538310, 33532824, 33538466, 33529528, 33536732, 33537669, 33542799, 33541590, 33548826, 33546076, 33544156, 33548578, 33536532, 33545739, 33536453, 33550781, 33546806, 33551385, 33537431, 33539741, 33544698, 33545365, 33542034, 33539292, 33537676, 33530322, 33518413, 33522951, 33518871, 33742348, 33532262, 33536737, 33552363, 33540348, 33538446, 33536457, 33549304, 33536251, 33540665, 33533133, 33718868, 33530219, 33520571, 33521320, 33527693, 33517598, 33534184, 33511602, 33510270, 33518828, 33521703, 33516954, 33522392, 33522781, 33516704, 33520214, 33518149, 33536053, 33526753, 33528327, 33527765, 33515634, 33521071, 33523814, 33530497, 33523418, 33524239, 33519176, 33516017, 33523376, 33522230, 33518127, 33523123, 33522381, 33534278, 33530428, 33535650, 33527406, 33537133, 33516267, 33533873, 33532278, 33537824, 33520855, 33528237, 33529860, 33534700, 33529937, 33526876, 33585256, 33581536, 33588557, 33583244, 33571070, 33577664, 33578921, 33576555, 33566410, 33574151, 33579816, 33572089, 33570138, 33574746, 33571950, 33569748, 33596123, 33587243, 33593329, 33594817, 33591698, 33590452, 33585395, 33588794, 33600081, 33576839, 33584557, 33586807, 33587978, 33578407, 33576490, 33584978, 33587003, 33597301, 33600087, 33584927, 33594308, 33597642, 33594328, 33596176, 33594536, 33593331, 33593348, 33588247, 33602341, 33597489, 33587338, 33587569, 33601135, 33614232, 33603054, 33609877, 33612775, 33603362, 33602839, 33605204, 33608691, 33594248, 33601901, 33605296, 33594857, 33604420, 33598078, 33601225, 33558171, 33547531, 33550383, 33550553, 33549112, 33548589, 33534905, 33554241, 33540481, 33542044, 33541262, 33540929, 33548764, 33545351, 33542462, 33549787, 33552070, 33555011, 33555409, 33560407, 33545668, 33561763, 33548401, 33551869, 33557952, 33555046, 33547177, 33548596, 33556496, 33546088, 33546232, 33551001, 33567006, 33556050, 33567971, 33556030, 33544498, 33559655, 33557719, 33571654, 33562014, 33558896, 33559083, 33557859, 33561862, 33562546, 33559172, 33558995, 33563477, 33569182, 33573490, 33571132, 33572362, 33565441, 33569574, 33576411, 33558467, 33564401, 33567226, 33572247, 33563329, 33565163, 33565959, 33560148], [33522706, 33524895, 33522886, 33532195, 33528116, 33520789, 33533427, 33517982, 33526763, 33526080, 33530379, 33531504, 33525514, 33533157, 33540439, 33531070, 33520368, 33526020, 33534505, 33543936, 33527429, 33527062, 33536792, 33534850, 33523457, 33527205, 33529776, 33525161, 33537524, 33525477, 33532362, 33526725, 33714007, 33535420, 33540418, 33544824, 33547287, 33528632, 33530875, 33541639, 33536074, 33540303, 33542075, 33537084, 33737343, 33513437, 33513206, 33525717, 33516549, 33523303, 33518579, 33525798, 33527587, 33516941, 33519280, 33509925, 33515482, 33525367, 33519277, 33513910, 33517471, 33530210, 33522138, 33519946, 33536960, 33539490, 33543128, 33540336, 33540135, 33537744, 33542784, 33540096, 33537971, 33543433, 33534716, 33536046, 33539323, 33536355, 33541612, 33539831, 33540280, 33551950, 33544209, 33548831, 33549642, 33545955, 33548364, 33544099, 33532776, 33541263, 33546384, 33546446, 33550324, 33550277, 33546234, 33543501, 33528446, 33533168, 33532642, 33535225, 33530630, 33533767, 33514415, 33532012, 33534842, 33522852, 33541041, 33526470, 33530084, 33545763, 33532248, 33528814, 33530565, 33532614, 33533592, 33534129, 33535132, 33535740, 33546631, 33534023, 33529907, 33536897, 33535954, 33530206, 33540864, 33523191, 33537036, 33544545, 33559573, 33563443, 33564801, 33556342, 33549658, 33561663, 33552612, 33553350, 33565545, 33567493, 33562205, 33561234, 33564884, 33567627, 33572738, 33560616, 33564834, 33556624, 33567264, 33567610, 33565853, 33571710, 33564239, 33557407, 33573323, 33554988, 33572182, 33569142, 33559645, 33564325, 33562415, 33570286, 33548364, 33535870, 33549086, 33545583, 33548549, 33555571, 33541346, 33549375, 33555113, 33545773, 33555022, 33555608, 33547312, 33557447, 33551214, 33547607, 33549699, 33550295, 33559660, 33549464, 33560616, 33547262, 33555224, 33556041, 33549456, 33556419, 33566125, 33549863, 33556844, 33550416, 33563084, 33551595, 33586683, 33580452, 33584797, 33587888, 33583057, 33591204, 33592775, 33584405, 33601063, 33598497, 33587272, 33590987, 33590950, 33608361, 33607910, 33599320, 33602033, 33592766, 33595705, 33607605, 33615463, 33607259, 33602977, 33604064, 33600634, 33608086, 33602192, 33615379, 33606639, 33601324, 33603090, 33604864, 33571240, 33569407, 33568887, 33573643, 33575522, 33572913, 33564187, 33570794, 33569532, 33572962, 33575529, 33573269, 33565396, 33583124, 33578002, 33578207, 33577247, 33582847, 33585682, 33574583, 33587809, 33587747, 33591221, 33575076, 33590637, 33578295, 33582466, 33584440, 33576338, 33591640, 33581656, 33591464], [33539489, 33541096, 33529194, 33529599, 33529585, 33536356, 33540852, 33532193, 33537194, 33528528, 33525930, 33531758, 33531843, 33522198, 33534481, 33536085, 33530728, 33540949, 33535298, 33533218, 33541942, 33526195, 33533835, 33530949, 33524922, 33533789, 33530031, 33539968, 33540793, 33537684, 33529199, 33534470, 33536622, 33545671, 33533090, 33540539, 33535314, 33535697, 33539949, 33536842, 33538868, 33544628, 33547653, 33535157, 33537679, 33539424, 33536122, 33546219, 33539427, 33535565, 33545497, 33535866, 33539205, 33543697, 33541306, 33550291, 33537423, 33547652, 33531825, 33555403, 33539236, 33534796, 33549264, 33545310, 33540832, 33535700, 33546043, 33545466, 33714294, 33545669, 33549717, 33540419, 33527744, 33739469, 33524737, 33525293, 33542973, 33535072, 33542118, 33528356, 33522801, 33526993, 33533868, 33521841, 33520178, 33520780, 33517311, 33520347, 33530493, 33524153, 33523669, 33526535, 33519833, 33521122, 33519456, 33517528, 33534503, 33522394, 33515642, 33526176, 33525523, 33524725, 33528668, 33533634, 33519287, 33529159, 33513646, 33520196, 33522845, 33531006, 33532748, 33541117, 33531689, 33521524, 33518767, 33530531, 33524050, 33533467, 33536246, 33531923, 33537032, 33539014, 33527659, 33526389, 33528699, 33530847, 33530860, 33528186, 33566829, 33582568, 33579644, 33569766, 33578431, 33572976, 33561100, 33571042, 33579082, 33571426, 33569931, 33579732, 33589632, 33573572, 33577040, 33577753, 33581776, 33571540, 33579469, 33581742, 33582415, 33578958, 33571913, 33576672, 33585903, 33580992, 33595358, 33591413, 33590098, 33577242, 33591523, 33572168, 33590448, 33597263, 33594788, 33585822, 33589729, 33593645, 33594947, 33582068, 33594983, 33597107, 33587479, 33603771, 33592241, 33586253, 33589299, 33591054, 33596310, 33603298, 33598487, 33596016, 33597109, 33596315, 33602949, 33604028, 33608756, 33607810, 33608128, 33604568, 33595787, 33613310, 33611193, 33604274, 33551154, 33550933, 33545268, 33548250, 33548263, 33551237, 33553543, 33544071, 33546776, 33554799, 33546116, 33552435, 33540328, 33537498, 33546199, 33540871, 33551808, 33555245, 33558878, 33549951, 33546834, 33563831, 33560603, 33538545, 33552092, 33552693, 33554413, 33551377, 33556455, 33556070, 33545785, 33554098, 33570891, 33564819, 33549444, 33559299, 33571568, 33562691, 33549929, 33561962, 33567767, 33566604, 33563001, 33571999, 33563212, 33557743, 33561151, 33565599, 33570688, 33568074, 33565912, 33561309, 33558124, 33558508, 33551203, 33572104, 33575863, 33563629, 33578102, 33573371, 33575224, 33561134, 33570149, 33567609], [33535468, 33538838, 33543030, 33534209, 33539340, 33526407, 33529573, 33546907, 33537901, 33535305, 33540942, 33539184, 33536236, 33540833, 33535115, 33539729, 33536822, 33527330, 33532096, 33530666, 33540279, 33529346, 33516208, 33528812, 33524446, 33536241, 33531905, 33535695, 33531122, 33537186, 33525508, 33540620, 33538494, 33540290, 33543545, 33547447, 33543017, 33544614, 33548739, 33537391, 33533836, 33548918, 33540121, 33544631, 33544414, 33544849, 33546706, 33553912, 33537927, 33542082, 33542710, 33542393, 33543434, 33551324, 33543864, 33539487, 33540399, 33539242, 33536264, 33549079, 33543164, 33541892, 33541540, 33533853, 33522313, 33516021, 33526368, 33522110, 33518483, 33522986, 33513571, 33518227, 33517089, 33516729, 33518722, 33514842, 33524219, 33519020, 33528869, 33527301, 33543543, 33542742, 33713643, 33547589, 33541420, 33528312, 33538985, 33534128, 33542806, 33525646, 33543040, 33537553, 33747762, 33526260, 33527722, 33532193, 33524477, 33530946, 33528687, 33528148, 33522744, 33528931, 33526327, 33529206, 33532023, 33531543, 33521230, 33533200, 33534211, 33530126, 33515687, 33529069, 33521063, 33521238, 33525060, 33537330, 33522525, 33529770, 33520925, 33519628, 33531580, 33523246, 33519765, 33528746, 33531050, 33526506, 33528138, 33522331, 33581136, 33576029, 33579317, 33578165, 33577569, 33583980, 33582852, 33588797, 33587009, 33577648, 33580574, 33580171, 33579701, 33590648, 33593233, 33590271, 33570825, 33570641, 33566266, 33573422, 33570516, 33571379, 33586418, 33565944, 33576935, 33574932, 33578687, 33572955, 33574166, 33588436, 33579513, 33572181, 33607322, 33597050, 33607726, 33597810, 33603878, 33600051, 33602971, 33602484, 33598936, 33609823, 33594896, 33603649, 33610911, 33614535, 33604375, 33606813, 33586043, 33587730, 33577004, 33585029, 33593714, 33588700, 33578408, 33583892, 33590748, 33594024, 33588713, 33596671, 33603175, 33604069, 33603855, 33597617, 33552478, 33552807, 33548682, 33557137, 33552707, 33552561, 33552762, 33556101, 33556390, 33560884, 33548411, 33555206, 33561321, 33556665, 33561211, 33553484, 33541233, 33539344, 33556108, 33545946, 33547839, 33544906, 33552391, 33542259, 33547652, 33550359, 33550002, 33560880, 33547237, 33549621, 33543285, 33559863, 33569129, 33571072, 33563805, 33558478, 33557087, 33565484, 33564737, 33561093, 33570083, 33572378, 33564885, 33568668, 33582163, 33570580, 33565338, 33554912, 33557852, 33548991, 33548061, 33558492, 33546979, 33568276, 33553307, 33553850, 33563864, 33567026, 33563819, 33559797, 33564930, 33557817, 33561767, 33570655], [33535783, 33537434, 33529952, 33525212, 33525421, 33538549, 33529895, 33531501, 33526253, 33532209, 33530665, 33528541, 33539741, 33520856, 33528239, 33530437, 33533734, 33537441, 33533944, 33530573, 33534350, 33545457, 33530531, 33535893, 33543949, 33539871, 33527328, 33535728, 33540333, 33539768, 33541801, 33541924, 33532783, 33537279, 33535775, 33532308, 33554401, 33537208, 33545565, 33540521, 33529678, 33541601, 33541256, 33549673, 33554953, 33538998, 33536713, 33523289, 33539656, 33551512, 33548098, 33541801, 33540257, 33555894, 33552000, 33541036, 33548082, 33527837, 33537043, 33545770, 33551328, 33541873, 33545901, 33541513, 33535006, 33536377, 33547558, 33539266, 33539561, 33542908, 33731270, 33535136, 33532572, 33714854, 33537099, 33547498, 33547538, 33536409, 33535240, 33540516, 33529847, 33528048, 33527427, 33522820, 33520908, 33529338, 33524329, 33524894, 33518834, 33517901, 33511466, 33529689, 33521249, 33529122, 33524068, 33529162, 33529740, 33526807, 33527533, 33526101, 33516768, 33522786, 33531908, 33519365, 33535803, 33529223, 33522039, 33528766, 33527789, 33533370, 33531613, 33524661, 33518645, 33538372, 33520033, 33525157, 33541875, 33526262, 33519816, 33529177, 33521537, 33530950, 33527629, 33523820, 33532222, 33529557, 33527910, 33526941, 33583749, 33575071, 33576834, 33568853, 33576411, 33576473, 33567025, 33582030, 33572851, 33577607, 33572199, 33567945, 33575529, 33572424, 33565312, 33572872, 33585166, 33579218, 33576999, 33586620, 33596770, 33584345, 33589275, 33584149, 33578563, 33592382, 33582600, 33581706, 33577462, 33582118, 33582368, 33576459, 33593289, 33593306, 33586511, 33588042, 33596910, 33592978, 33588362, 33596188, 33584177, 33595997, 33594091, 33593257, 33594707, 33584765, 33585099, 33601191, 33602034, 33603340, 33606779, 33598483, 33599968, 33603491, 33606353, 33609134, 33591484, 33608562, 33603630, 33598503, 33596413, 33602774, 33596156, 33592393, 33552462, 33550909, 33549700, 33540777, 33552112, 33542529, 33553897, 33543072, 33542717, 33541254, 33540260, 33549986, 33540804, 33543599, 33550766, 33554842, 33563769, 33547968, 33557282, 33557068, 33553527, 33559744, 33553139, 33561303, 33545805, 33558210, 33542853, 33549607, 33559406, 33544912, 33553489, 33551084, 33560782, 33563336, 33565843, 33560292, 33566870, 33561450, 33564953, 33562329, 33553935, 33554291, 33550153, 33562053, 33554210, 33560598, 33544407, 33565398, 33575131, 33559603, 33559485, 33577571, 33567793, 33575829, 33558080, 33573326, 33575237, 33564339, 33571117, 33564880, 33563318, 33560713, 33567040, 33566626], [33522515, 33521389, 33524396, 33519919, 33524652, 33530318, 33520893, 33525091, 33527078, 33522974, 33532796, 33527021, 33528991, 33530498, 33525287, 33522615, 33537647, 33535806, 33535410, 33537387, 33532401, 33529473, 33529082, 33530491, 33527877, 33530801, 33532505, 33525725, 33528278, 33535116, 33535886, 33531297, 33532271, 33538998, 33540298, 33534180, 33537759, 33527568, 33532839, 33539783, 33534746, 33532696, 33530743, 33539902, 33534616, 33540324, 33528218, 33536192, 33539926, 33534947, 33532408, 33535837, 33547962, 33546455, 33537030, 33533621, 33529958, 33526300, 33546439, 33527315, 33536947, 33534197, 33533794, 33544469, 33555662, 33523930, 33543267, 33535599, 33547023, 33543704, 33545779, 33534724, 33544552, 33535712, 33546586, 33540533, 33530898, 33532965, 33717482, 33536984, 33518804, 33512692, 33519659, 33524984, 33500820, 33518381, 33505997, 33511008, 33513908, 33526027, 33517257, 33517744, 33522665, 33523027, 33707978, 33510451, 33525837, 33523344, 33527787, 33512352, 33519671, 33526533, 33515712, 33528268, 33525674, 33531875, 33524940, 33511645, 33513754, 33522112, 33514769, 33518919, 33527477, 33539868, 33526322, 33530566, 33516815, 33518373, 33521971, 33528050, 33531115, 33515704, 33521398, 33526805, 33516778, 33526331, 33521782, 33533673, 33572656, 33570312, 33565493, 33571795, 33555686, 33566503, 33569875, 33573430, 33564736, 33565755, 33569816, 33571265, 33567901, 33562973, 33558734, 33574549, 33589149, 33575973, 33583380, 33574467, 33586531, 33567296, 33573125, 33574476, 33570805, 33576632, 33567487, 33572618, 33573989, 33573024, 33571616, 33576136, 33584468, 33592675, 33588111, 33590886, 33586549, 33583912, 33584465, 33584906, 33581489, 33578898, 33581113, 33589150, 33578782, 33577754, 33576964, 33579731, 33610527, 33610494, 33607412, 33614964, 33613101, 33603378, 33600395, 33608867, 33598782, 33606149, 33606337, 33605863, 33599131, 33596263, 34753169, 33605796, 33542118, 33546787, 33554959, 33535249, 33548840, 33541589, 33539577, 33537791, 33543043, 33549118, 33549053, 33546073, 33530811, 33545398, 33548139, 33541236, 33550016, 33549329, 33554532, 33551896, 33547467, 33549398, 33551187, 33547608, 33543204, 33557265, 33544413, 33550464, 33546234, 33556507, 33549644, 33543802, 33552019, 33556132, 33548829, 33554299, 33555635, 33561058, 33547948, 33555060, 33547846, 33563333, 33555240, 33555354, 33552651, 33554016, 33557113, 33557000, 33567911, 33562576, 33561906, 33560872, 33572148, 33572349, 33562058, 33562802, 33559219, 33559808, 33554484, 33566343, 33572622, 33552753, 33565571, 33562851], [33532445, 33537408, 33525387, 33541446, 33544597, 33532735, 33533998, 33522885, 33526299, 33543809, 33533434, 33527324, 33532065, 33520261, 33533647, 33527240, 33537076, 33546486, 33545086, 33527755, 33530594, 33545505, 33534694, 33538672, 33530163, 33536176, 33527306, 33542761, 33531504, 33532492, 33528384, 33545945, 33541026, 33538262, 33538283, 33540897, 33550833, 33533653, 33550331, 33541483, 33537099, 33539537, 33538302, 33531989, 33547359, 33549423, 33541101, 33540426, 33549382, 33541971, 33543239, 33542240, 33545863, 33547119, 33548390, 33544666, 33544278, 33549167, 33539417, 33533566, 33545694, 33544636, 33543309, 33541403, 33541170, 33535442, 33544736, 33535877, 33544846, 33536411, 33540726, 33532645, 33532065, 33537843, 33540467, 33711372, 33538775, 33538472, 33555840, 33540692, 33510764, 33528732, 33525913, 33515045, 33535196, 33531162, 33525493, 33518323, 33523547, 33520997, 33725080, 33516696, 33511935, 33517244, 33528161, 33524887, 33528888, 33523260, 33524730, 33530093, 33536257, 33523784, 33531362, 33519837, 33529001, 33527417, 33528121, 33513967, 33516080, 33516352, 33527725, 33528589, 33529381, 33531565, 33521966, 33535927, 33532656, 33525546, 33532024, 33532670, 33512458, 33520885, 33518739, 33532973, 33526289, 33522387, 33524837, 33523884, 33565403, 33574779, 33572154, 33579245, 33580468, 33577158, 33585821, 33579659, 33567810, 33578723, 33564743, 33568415, 33574209, 33579326, 33573001, 33566130, 33589702, 33581131, 33588320, 33586468, 33587832, 33581108, 33583231, 33583161, 33575566, 33586190, 33575369, 33584235, 33565362, 33583353, 33587694, 33574322, 33589794, 33597614, 33590565, 33594710, 33600347, 33590944, 33601542, 33587813, 33588000, 33583094, 33598854, 33586048, 33594307, 33586883, 33591045, 33587475, 33608983, 33608614, 33600006, 33608901, 33609184, 33613351, 33605869, 33601759, 33597719, 33595334, 33607122, 33593023, 33605441, 33602456, 33593104, 33602943, 33545237, 33550081, 33547650, 33551847, 33556707, 33544800, 33545451, 33545510, 33544867, 33555816, 33554650, 33550999, 33546211, 33548759, 33538778, 33545926, 33549216, 33550568, 33556670, 33555758, 33548469, 33544511, 33554655, 33553001, 33549583, 33555286, 33542550, 33547249, 33554922, 33557237, 33558346, 33555269, 33558932, 33561557, 33556332, 33561702, 33561818, 33567920, 33578848, 33553308, 33562147, 33564573, 33561346, 33561526, 33553552, 33559813, 33554362, 33568900, 33566788, 33553538, 33574332, 33567701, 33573825, 33579340, 33558468, 33564828, 33567282, 33553524, 33557377, 33566305, 33561983, 33572423, 33569869, 33574735], [33527379, 33523478, 33523212, 33528402, 33518391, 33527482, 33521886, 33520616, 33528195, 33528061, 33527356, 33520630, 33527321, 33534983, 33525249, 33523561, 33529481, 33534376, 33530289, 33529285, 33521731, 33525586, 33520799, 33526264, 33528215, 33524155, 33534382, 33532249, 33527047, 33522281, 33530204, 33525621, 33708775, 33529512, 33535606, 33548611, 33546749, 33540073, 33533302, 33543887, 33534560, 33529560, 33539565, 33538176, 33538559, 33547550, 33543241, 33541073, 33544606, 33533263, 33731121, 33523415, 33521212, 33518114, 33520835, 33515064, 33519817, 33530353, 33534946, 33531385, 33521540, 33524034, 33523635, 33511398, 33535623, 33533885, 33537882, 33536115, 33533359, 33541447, 33538037, 33539189, 33540609, 33545951, 33552835, 33550913, 33550604, 33541806, 33534230, 33548372, 33549340, 33544125, 33530835, 33543821, 33532040, 33543848, 33535900, 33540207, 33543200, 33540822, 33548984, 33528369, 33548434, 33552809, 33545960, 33540626, 33534451, 33549369, 33531061, 33533602, 33525625, 33532286, 33539542, 33538433, 33546787, 33545407, 33534666, 33527069, 33533642, 33537749, 33533322, 33536512, 33531053, 33519096, 33532377, 33534512, 33533744, 33537225, 33539278, 33545374, 33544595, 33541565, 33537616, 33536013, 33534677, 33534921, 33526004, 33541042, 33564951, 33558761, 33559886, 33562390, 33550800, 33561330, 33560451, 33571520, 33558578, 33558505, 33559385, 33559486, 33563714, 33568062, 33559522, 33562393, 33558766, 33566861, 33561992, 33563323, 33562052, 33554942, 33558857, 33568039, 33550402, 33559824, 33571988, 33557976, 33568668, 33564268, 33563856, 33572755, 33555256, 33534927, 33545714, 33546857, 33547463, 33554520, 33548957, 33544028, 33546802, 33551230, 33547304, 33554329, 33541268, 33549752, 33550375, 33554584, 33551549, 33545766, 33547510, 33550391, 33546328, 33556774, 33556310, 33545946, 33553859, 33547600, 33562699, 33549371, 33546979, 33555246, 33550824, 33569250, 33590366, 33590760, 33583360, 33593368, 33594293, 33590624, 33589950, 33599778, 33582630, 33602063, 33601816, 33594032, 33592801, 33595852, 33595561, 33589488, 33596852, 33593425, 33593882, 33607031, 33592019, 33601435, 33609187, 33598125, 33606501, 33593328, 33606161, 33598016, 33605735, 33610745, 33606036, 33605554, 33577318, 33575244, 33562373, 33564296, 33567216, 33579628, 33570583, 33567417, 33564150, 33577811, 33575158, 33583116, 33580121, 33584113, 33570255, 33585939, 33568508, 33581354, 33579795, 33582087, 33572189, 33585208, 33585564, 33567381, 33581611, 33576184, 33591448, 33597990, 33580015, 33585368, 33588920, 33590891], [33530720, 33521037, 33520627, 33535867, 33533289, 33534218, 33535156, 33532276, 33526009, 33536429, 33532119, 33526361, 33530497, 33541847, 33539257, 33531868, 33531230, 33535726, 33525099, 33533844, 33543844, 33536478, 33530807, 33521116, 33524398, 33531152, 33524613, 33529187, 33532077, 33527692, 33529404, 33526467, 33541420, 33537908, 33535152, 33537344, 33548199, 33539689, 33554332, 33538073, 33529515, 33543215, 33541812, 33528922, 33542385, 33546417, 33540817, 33538403, 33530773, 33542165, 33543097, 33538496, 33541105, 33543835, 33538088, 33547188, 33533308, 33543988, 33545171, 33540867, 33537443, 33534350, 33540381, 33535795, 33533156, 33525068, 33522087, 33520283, 33519939, 33517550, 33526855, 33526932, 33547681, 33540140, 33728455, 33537567, 33521305, 33525501, 33529340, 33518771, 33535378, 33547006, 33552573, 33539134, 33538005, 33539689, 33554607, 33552974, 33540830, 33719830, 33541868, 33540832, 33537472, 33542337, 33548806, 33532981, 33531054, 33529040, 33536922, 33513635, 33535939, 33528743, 33535263, 33545008, 33531580, 33530162, 33530365, 33531058, 33524141, 33531968, 33532852, 33531753, 33521123, 33524553, 33522334, 33534750, 33528810, 33521245, 33529738, 33520959, 33522930, 33526027, 33524853, 33535409, 33525514, 33515924, 33520381, 33523847, 33586341, 33591013, 33575448, 33584342, 33587669, 33585222, 33589581, 33593400, 33575424, 33575152, 33583106, 33581748, 33582251, 33567551, 33577982, 33578184, 33572793, 33571675, 33579698, 33575450, 33569127, 33570134, 33578830, 33580824, 33566493, 33576724, 33571063, 33582354, 33576229, 33588892, 33568889, 33566143, 33605910, 33615754, 33600395, 33607749, 33605238, 33608630, 33602048, 33614706, 33589881, 33593754, 33607791, 33596213, 33604226, 33585824, 33599091, 33603202, 33585972, 33579603, 33595534, 33591132, 33589059, 33598395, 33591133, 33590263, 33580821, 33581528, 33595945, 33585010, 33584236, 33589069, 33589148, 33586881, 33554852, 33548785, 33554004, 33562821, 33547989, 33559455, 33557438, 33552890, 33547605, 33554464, 33544125, 33562634, 33550215, 33558135, 33556910, 33559501, 33546793, 33556520, 33548117, 33558257, 33552443, 33544306, 33552618, 33551215, 33538179, 33566014, 33549828, 33553748, 33542876, 33552124, 33535418, 33552434, 33570006, 33567973, 33573953, 33566444, 33569679, 33562739, 33570439, 33567171, 33551703, 33568897, 33552123, 33564008, 33568746, 33568299, 33565020, 33575193, 33570170, 33561181, 33559232, 33558402, 33563162, 33566179, 33565998, 33567306, 33545774, 33551144, 33555822, 33561203, 33566061, 33566369, 33564842, 33539572], [33529317, 33536416, 33528289, 33538266, 33529354, 33529467, 33525930, 33540432, 33533163, 33539895, 33541886, 33527447, 33527091, 33536906, 33533426, 33547079, 33536255, 33545111, 33535354, 33538146, 33530676, 33526004, 33533656, 33535959, 33530738, 33545661, 33542210, 33531652, 33531636, 33544429, 33552343, 33536001, 33546904, 33543388, 33551079, 33534905, 33551157, 33536380, 33534704, 33544480, 33543361, 33540958, 33541951, 33536132, 33537648, 33533046, 33534627, 33539911, 33546973, 33538668, 33546788, 33547257, 33538541, 33546659, 33542777, 33540861, 33542633, 33548419, 33548823, 33552333, 33538606, 33541140, 33543783, 33551162, 33539216, 33545249, 33539771, 33551432, 33542314, 33551973, 33544605, 33536256, 33542274, 33537121, 33539938, 33535220, 33541936, 33544702, 33536945, 33706272, 33528280, 33522902, 33518233, 33527945, 33516429, 33518401, 33520824, 33533948, 33520665, 33523928, 33519870, 33714250, 33530786, 33549418, 33547802, 33549957, 33522734, 33525539, 33511110, 33541339, 33528871, 33530061, 33524787, 33521698, 33512806, 33523194, 33513871, 33522411, 33527497, 33515032, 33524884, 33523011, 33521371, 33524102, 33528029, 33526486, 33534544, 33530024, 33528057, 33525436, 33527399, 33514618, 33541373, 33531695, 33535917, 33528850, 33522972, 33532953, 33570889, 33582696, 33579573, 33574317, 33576270, 33565569, 33573742, 33575010, 33560475, 33559655, 33575186, 33565777, 33574294, 33572185, 33580372, 33562620, 33581140, 33588464, 33574342, 33575544, 33586212, 33572603, 33574235, 33577586, 33586073, 33584372, 33582171, 33574791, 33574887, 33589813, 33587496, 33579743, 33591371, 33593829, 33601576, 33595231, 33589870, 33591500, 33593889, 33580492, 33585766, 33586840, 33592941, 33599564, 33592729, 33592723, 33585494, 33585169, 33596293, 33607209, 33600242, 33604118, 33601866, 33599426, 33606571, 33609965, 33596330, 33594687, 33609139, 33596486, 33603332, 33598836, 33600255, 33601301, 33538348, 33540315, 33559819, 33544635, 33552256, 33543973, 33540169, 33543540, 33547340, 33545653, 33539802, 33550013, 33547518, 33552611, 33553540, 33553035, 33561326, 33541245, 33554260, 33563852, 33561301, 33551861, 33554240, 33555872, 33553977, 33552708, 33553259, 33554760, 33561042, 33550328, 33549636, 33555304, 33564179, 33556643, 33563096, 33558630, 33562122, 33561616, 33553274, 33553084, 33557693, 33552276, 33553046, 33551559, 33560124, 33565085, 33562460, 33554526, 33572364, 33567678, 33559433, 33574028, 33572234, 33561169, 33570339, 33565557, 33569407, 33562731, 33567904, 33563583, 33561092, 33554241, 33565079, 33559878], [33534923, 33529222, 33535189, 33534538, 33525419, 33542669, 33540033, 33540451, 33548657, 33534796, 33542985, 33541595, 33537057, 33531384, 33544869, 33534850, 33545325, 33540833, 33526830, 33524973, 33533028, 33514063, 33539516, 33520390, 33528544, 33538726, 33537793, 33535479, 33532220, 33538858, 33536374, 33533671, 33538981, 33548032, 33549234, 33544661, 33541525, 33540651, 33552739, 33546145, 33548280, 33546624, 33543438, 33547181, 33552185, 33547894, 33547468, 33547509, 33533491, 33544400, 33541941, 33530614, 33536948, 33539447, 33531148, 33548528, 33541238, 33543763, 33540743, 33546980, 33541581, 33531976, 33534445, 33537194, 33722405, 33529202, 33522546, 33519499, 33538071, 33540000, 33538700, 33546591, 33521187, 33521612, 33524080, 33532977, 33524564, 33522559, 33524548, 33539879, 33547943, 33538666, 33540480, 33550043, 33528056, 33709555, 33531215, 33541321, 33533919, 33532583, 33540501, 33545787, 33538101, 33541656, 33543756, 33538752, 33528770, 33529072, 33522777, 33532680, 33536033, 33531679, 33528632, 33531996, 33526807, 33527160, 33519529, 33528133, 33524583, 33527532, 33527324, 33526768, 33521001, 33527308, 33523997, 33533643, 33526996, 33518639, 33524148, 33527334, 33518258, 33532081, 33539509, 33520005, 33526718, 33524573, 33521207, 33526313, 33579944, 33589236, 33590092, 33583418, 33581559, 33574959, 33576914, 33589830, 33582027, 33590271, 33587426, 33577223, 33588160, 33570721, 33576971, 33577039, 33571575, 33566452, 33564594, 33564302, 33578079, 33560393, 33572654, 33560174, 33572586, 33581373, 33578308, 33584353, 33574998, 33579461, 33573095, 33573328, 33587386, 33593573, 33600352, 33595715, 33594782, 33596998, 33597738, 33605656, 33603759, 33609903, 33602319, 33606736, 33603277, 33600137, 33599599, 33605789, 33585593, 33583642, 33586923, 33587990, 33592294, 33575667, 33594516, 33591807, 33591501, 33580690, 33603628, 33587347, 33594298, 33595298, 33599387, 33598548, 33543656, 33549601, 33553444, 33554005, 33557457, 33568204, 33545477, 33549836, 33556992, 33555796, 33554580, 33554364, 33558629, 33563245, 33548612, 33542989, 33536046, 33538669, 33546501, 33555877, 33537531, 33552256, 33548199, 33531980, 33541422, 33549812, 33556794, 33550378, 33548100, 33546808, 33542014, 33552287, 33565059, 33556048, 33568099, 33573286, 33557756, 33563324, 33566773, 33562983, 33562586, 33570033, 33563378, 33577647, 33558458, 33563997, 33568121, 33565295, 33575272, 33564202, 33562732, 33565966, 33553054, 33549558, 33558770, 33554851, 33565174, 33560948, 33564729, 33555352, 33552208, 33547929, 33552361, 33568516], [33537964, 33532273, 33534619, 33540133, 33527955, 33530203, 33540295, 33528668, 33535722, 33535455, 33527135, 33545062, 33539759, 33542893, 33546692, 33543183, 33537478, 33531238, 33534075, 33528562, 33537160, 33533179, 33542998, 33535294, 33526837, 33535064, 33531793, 33531000, 33538116, 33535645, 33533679, 33529298, 33538172, 33538314, 33539333, 33524416, 33541976, 33543469, 33538325, 33547390, 33546006, 33541857, 33543318, 33558972, 33551751, 33549169, 33550999, 33543669, 33538378, 33537281, 33543324, 33537217, 33532262, 33544548, 33536572, 33540080, 33541730, 33546214, 33546636, 33544275, 33544527, 33534389, 33550830, 33531588, 33547277, 33537998, 33533938, 33545107, 33716471, 33534265, 33534802, 33537259, 33521496, 33513740, 33523571, 33514097, 33524357, 33522779, 33518610, 33515835, 33530579, 33535499, 33705691, 33543172, 33546735, 33544741, 33540426, 33540412, 33548641, 33541533, 33535877, 33550651, 33546254, 33540630, 33532416, 33529493, 33524151, 33528651, 33522690, 33544894, 33531582, 33516345, 33532288, 33527858, 33528759, 33530884, 33544894, 33523258, 33525832, 33540982, 33531587, 33534411, 33523345, 33520083, 33516507, 33520548, 33521314, 33526514, 33522555, 33517487, 33525039, 33518042, 33522523, 33522025, 33531167, 33531078, 33536069, 33524373, 33579187, 33571048, 33575040, 33577385, 33582713, 33571340, 33586940, 33582237, 33593558, 33576659, 33588674, 33588495, 33590192, 33576933, 33590807, 33586359, 33580510, 33578930, 33572589, 33576054, 33568000, 33576282, 33573160, 33574412, 33574772, 33580140, 33560648, 33574612, 33574752, 33566157, 33568221, 33557231, 33598825, 33600802, 33600440, 33598043, 33592427, 33607973, 33597905, 33606700, 33592757, 33602225, 33598412, 33599402, 33603448, 33607537, 33610128, 33604832, 33584331, 33591537, 33579642, 33584675, 33589160, 33588012, 33592628, 33593649, 33592219, 33593291, 33593242, 33582772, 33591537, 33587709, 33595293, 33597616, 33546532, 33552491, 33548102, 33556220, 33556025, 33553565, 33552481, 33552443, 33560394, 33554705, 33561085, 33552912, 33550460, 33560527, 33560479, 33548695, 33544855, 33548714, 33558399, 33545466, 33547516, 33538259, 33547468, 33545405, 33543202, 33551679, 33541067, 33540041, 33548569, 33554454, 33549653, 33547419, 33567416, 33552189, 33566917, 33563332, 33555714, 33561531, 33558555, 33568438, 33566952, 33564196, 33564403, 33568796, 33568516, 33567353, 33565600, 33572128, 33558987, 33573988, 33550155, 33560942, 33549515, 33562549, 33552151, 33564026, 33560288, 33563071, 33556480, 33563013, 33555996, 33560041, 33559339, 33561026], [33531371, 33506040, 33529819, 33526399, 33522743, 33524100, 33531036, 33521150, 33526177, 33536352, 33525625, 33526924, 33536775, 33525617, 33524272, 33532945, 33517352, 33531496, 33524014, 33524968, 33526522, 33525614, 33527056, 33524046, 33532439, 33521597, 33527139, 33525812, 33532660, 33524903, 33531468, 33528726, 33704022, 33537501, 33532343, 33532539, 33544400, 33539603, 33536898, 33543645, 33543335, 33539407, 33551395, 33542036, 33551625, 33534738, 33543023, 33534950, 33547141, 33537682, 33541245, 33533753, 33534302, 33554436, 33534880, 33712630, 33523780, 33528636, 33521019, 33526993, 33519057, 33528138, 33524139, 33524028, 33542077, 33538300, 33540994, 33539869, 33536537, 33537741, 33536574, 33539846, 33537412, 33545915, 33539783, 33553351, 33536833, 33541926, 33539521, 33544915, 33550583, 33538292, 33545235, 33538903, 33543990, 33546999, 33533758, 33545633, 33540671, 33528668, 33538912, 33553211, 33548311, 33540194, 33544518, 33542606, 33536466, 33527285, 33526195, 33525994, 33537812, 33541245, 33526431, 33528518, 33541208, 33522600, 33536863, 33527844, 33541832, 33531734, 33533893, 33528109, 33531900, 33533763, 33533894, 33538250, 33532167, 33533439, 33524774, 33539002, 33533576, 33543343, 33547616, 33539587, 33537079, 33537662, 33537770, 33546385, 33559051, 33550489, 33567906, 33553785, 33558764, 33551994, 33553567, 33569289, 33559440, 33561914, 33572247, 33549655, 33563525, 33560982, 33563690, 33566114, 33569030, 33552455, 33570774, 33574682, 33575267, 33560351, 33566441, 33560546, 33569699, 33572326, 33573009, 33564018, 33563002, 33568094, 33564941, 33559386, 33551479, 33556028, 33549097, 33541341, 33551875, 33553065, 33541667, 33550596, 33555328, 33545455, 33554736, 33548672, 33550376, 33550508, 33542473, 33551993, 33545994, 33547161, 33535166, 33550409, 33558131, 33565606, 33549452, 33553651, 33553171, 33544040, 33564452, 33545636, 33552899, 33550021, 33546555, 33550736, 33588834, 33587374, 33586811, 33593127, 33586423, 33582352, 33579136, 33593140, 33596663, 33598929, 33589973, 33595734, 33604094, 33591551, 33584726, 33594853, 33586678, 33597066, 33597684, 33591065, 33600438, 33604043, 33594088, 33615932, 33591497, 33590138, 33605736, 33610172, 33611203, 33601367, 33607058, 33601364, 33563862, 33572458, 33563231, 33582080, 33579731, 33569185, 33575478, 33567715, 33582201, 33563580, 33567894, 33570785, 33575001, 33569665, 33564694, 33579732, 33579917, 33587677, 33583737, 33573569, 33573752, 33580283, 33583362, 33576822, 33584465, 33584965, 33574943, 33583294, 33586510, 33585205, 33586200, 33576358], [33538538, 33543042, 33523589, 33533263, 33528806, 33523793, 33531087, 33539790, 33536420, 33521448, 33527994, 33528624, 33532525, 33536253, 33528751, 33527813, 33535626, 33533733, 33528299, 33538015, 33537541, 33526656, 33535238, 33537800, 33541720, 33537717, 33540080, 33524762, 33539485, 33531758, 33532094, 33540220, 33544292, 33531499, 33547093, 33547531, 33545907, 33528108, 33537652, 33557031, 33538190, 33542077, 33539815, 33535645, 33530239, 33534007, 33548676, 33536769, 33556421, 33543519, 33542008, 33552496, 33538272, 33542940, 33545798, 33542340, 33538227, 33544475, 33553540, 33542394, 33542078, 33544407, 33554538, 33547924, 33539755, 33540029, 33544570, 33548980, 33544338, 33547985, 33542863, 33534708, 33541590, 33541380, 33547662, 33537018, 33543056, 33542090, 33535885, 33702081, 33519542, 33527554, 33520173, 33529753, 33526556, 33525696, 33525410, 33715437, 33538951, 33549353, 33538280, 33541824, 33550288, 33540091, 33534192, 33526631, 33527807, 33532440, 33529059, 33526571, 33523830, 33533370, 33529359, 33533900, 33534811, 33522183, 33510591, 33516699, 33529381, 33526863, 33526055, 33527548, 33525869, 33527824, 33527092, 33536871, 33528022, 33524243, 33532509, 33532050, 33534691, 33520256, 33531670, 33532900, 33531087, 33513497, 33532856, 33527007, 33572774, 33579942, 33575419, 33565565, 33580721, 33570547, 33573691, 33572592, 33581551, 33574422, 33568445, 33570098, 33568001, 33580713, 33563509, 33567942, 33576601, 33587560, 33584001, 33581507, 33578717, 33587633, 33586228, 33563741, 33582825, 33578431, 33573792, 33570910, 33574829, 33579714, 33575631, 33590710, 33586725, 33603002, 33590733, 33586492, 33593872, 33590770, 33589671, 33592858, 33583359, 33584312, 33589850, 33595527, 33587035, 33587006, 33589959, 33585615, 33604935, 33603438, 33597705, 33612690, 33604921, 33598327, 33611405, 33600849, 33601225, 33611223, 33593638, 33601487, 33603876, 33590346, 33589751, 33582948, 33544844, 33547325, 33549328, 33544618, 33551921, 33540321, 33551156, 33545112, 33545790, 33552931, 33542609, 33550246, 33553978, 33540341, 33544053, 33547333, 33558374, 33570755, 33543684, 33555272, 33560107, 33547397, 33547047, 33558937, 33546504, 33550372, 33551223, 33556166, 33546631, 33547679, 33547609, 33553766, 33552817, 33567619, 33551436, 33560294, 33559246, 33553507, 33559548, 33551057, 33557618, 33553977, 33560284, 33551726, 33548670, 33555004, 33553979, 33558790, 33577646, 33572647, 33567853, 33559372, 33567970, 33567833, 33566635, 33566838, 33570483, 33571294, 33565879, 33570946, 33573049, 33565726, 33562380, 33563708], [33538028, 33526974, 33537055, 33532795, 33527709, 33540722, 33534961, 33542687, 33536920, 33533974, 33533043, 33529051, 33529535, 33544451, 33533008, 33536386, 33525782, 33541651, 33531685, 33524509, 33536216, 33537132, 33530064, 33526881, 33539243, 33531998, 33542648, 33546190, 33533439, 33532988, 33534750, 33540739, 33555387, 33538840, 33554405, 33532720, 33540657, 33545435, 33547655, 33549759, 33540607, 33558593, 33542018, 33543875, 33549308, 33542106, 33540239, 33545106, 33544166, 33540724, 33530582, 33541962, 33541010, 33533943, 33532599, 33549709, 33543325, 33548023, 33545412, 33540546, 33541892, 33541668, 33521525, 33536553, 33544399, 33544455, 33541745, 33541062, 33550452, 33528847, 33548310, 33542591, 33525145, 33524248, 33527020, 33532213, 33526997, 33530706, 33533633, 33710213, 33539199, 33534206, 33542648, 33533480, 33531815, 33539882, 33696231, 33539239, 33553356, 33545226, 33538434, 33541906, 33535441, 33545344, 33531641, 33533039, 33511156, 33528770, 33532021, 33532837, 33530005, 33532422, 33531951, 33531802, 33530056, 33526449, 33534343, 33535314, 33527317, 33521632, 33529092, 33532404, 33529274, 33535070, 33522177, 33526151, 33525951, 33522856, 33530663, 33531734, 33530653, 33520585, 33528505, 33525349, 33523852, 33527657, 33525254, 33521498, 33586835, 33582402, 33576837, 33585985, 33574018, 33580113, 33575015, 33571876, 33586033, 33586264, 33585065, 33583982, 33587872, 33580973, 33581779, 33593021, 33557802, 33569746, 33574558, 33564817, 33571209, 33564955, 33573000, 33569875, 33581573, 33580291, 33583940, 33574513, 33564968, 33566245, 33570719, 33566875, 33598588, 33606884, 33591843, 33599533, 33592748, 33596637, 33591468, 33596056, 33588840, 33603409, 33599792, 33597656, 33590137, 33598043, 33604204, 33602288, 33590099, 33577960, 33590308, 33593820, 33584314, 33597372, 33578987, 33587593, 33591609, 33586483, 33584894, 33588792, 33589854, 33583731, 33583906, 33588137, 33552067, 33552876, 33556950, 33554937, 33553514, 33542452, 33559403, 33543837, 33552948, 33543065, 33562788, 33566914, 33551628, 33559284, 33560133, 33548289, 33550681, 33557419, 33540248, 33544171, 33545688, 33545936, 33546239, 33551430, 33557860, 33556437, 33545197, 33546535, 33551593, 33552694, 33541172, 33556979, 33557102, 33564683, 33564410, 33562673, 33558906, 33557827, 33554294, 33569504, 33563656, 33566191, 33563125, 33571491, 33568212, 33569239, 33570546, 33571584, 33558990, 33564310, 33552172, 33558357, 33552293, 33549737, 33557445, 33561036, 33568933, 33549244, 33568070, 33552617, 33570008, 33566007, 33556218, 33553721], [33544772, 33529332, 33532179, 33527873, 33532770, 33535312, 33523308, 33522991, 33541311, 33522057, 33520816, 33534634, 33524347, 33523327, 33531681, 33534149, 33545183, 33530988, 33535569, 33535658, 33533054, 33535845, 33533413, 33527255, 33552926, 33536606, 33537075, 33531540, 33553944, 33540255, 33543575, 33542144, 33517906, 33548785, 33541562, 33549015, 33541604, 33540061, 33537073, 33544456, 33540154, 33538576, 33552081, 33541285, 33537529, 33540321, 33543176, 33539442, 33543389, 33543031, 33541426, 33536395, 33544437, 33558494, 33552092, 33549766, 33532305, 33545707, 33543773, 33553896, 33553157, 33552337, 33538798, 33536366, 33529396, 33701419, 33540231, 33539241, 33539146, 33543852, 33542396, 33535319, 33543721, 33536068, 33536145, 33544983, 33537967, 33528166, 33545579, 33536709, 33532953, 33538905, 33536277, 33533635, 33540310, 33538728, 33540107, 33541255, 33530836, 33538839, 33525351, 33709822, 33540552, 33522472, 33529965, 33528059, 33516706, 33517686, 33519054, 33512414, 33533638, 33525588, 33526249, 33528201, 33520608, 33523703, 33533859, 33526220, 33536515, 33523807, 33523678, 33525367, 33536609, 33527263, 33524879, 33520723, 33523576, 33529126, 33526403, 33524029, 33535073, 33512817, 33531104, 33535163, 33527607, 33524939, 33528385, 33535956, 33563770, 33561777, 33570394, 33564787, 33568341, 33568820, 33556666, 33567262, 33571732, 33571866, 33576559, 33574842, 33579289, 33570384, 33571634, 33576097, 33582546, 33581515, 33585003, 33592165, 33582742, 33576058, 33570756, 33579112, 33579075, 33574934, 33578870, 33580444, 33580606, 33583498, 33584765, 33581495, 33585378, 33594845, 33585067, 33587972, 33591451, 33596056, 33584146, 33593329, 33596951, 33589493, 33596697, 33588375, 33599088, 33582107, 33589873, 33596432, 33595478, 33590715, 33596592, 33598146, 33601729, 33609403, 33592164, 33605227, 33597916, 33603387, 33599863, 33606466, 33601988, 33596155, 33605409, 33603790, 33552164, 33541422, 33548660, 33554862, 33550029, 33541052, 33543897, 33562802, 33542185, 33546599, 33553140, 33539226, 33564602, 33551384, 33544688, 33538740, 33542900, 33560539, 33550617, 33547480, 33556596, 33555801, 33558682, 33551745, 33555245, 33557334, 33550120, 33555629, 33553209, 33548956, 33562894, 33559040, 33561712, 33567162, 33556532, 33554871, 33560188, 33547710, 33567966, 33560349, 33564712, 33554448, 33555221, 33556651, 33566186, 33561342, 33554634, 33564514, 33568995, 33563618, 33563256, 33559009, 33565889, 33564465, 33577199, 33560099, 33567457, 33568617, 33570909, 33567584, 33562974, 33560192, 33562568, 33566199], [33531713, 33530791, 33544052, 33536249, 33544803, 33532839, 33519892, 33535939, 33526199, 33531600, 33537769, 33542192, 33540275, 33541641, 33536249, 33531624, 33536335, 33536902, 33542876, 33530489, 33536413, 33543387, 33543807, 33538273, 33538110, 33533483, 33533180, 33536491, 33526655, 33534897, 33535441, 33547082, 33544082, 33542119, 33525742, 33542898, 33533517, 33548817, 33549977, 33533935, 33540252, 33551755, 33552051, 33546652, 33544377, 33531755, 33535142, 33545160, 33539284, 33546243, 33556589, 33543300, 33543793, 33544238, 33542248, 33532704, 33543747, 33535179, 33541765, 33534040, 33538472, 33538673, 33540650, 33556402, 33548949, 33536456, 33547116, 33533376, 33536464, 33538661, 33524258, 33541844, 33535909, 33547181, 33531342, 33541584, 33705247, 33540491, 33536955, 33543290, 33518475, 33525917, 33519158, 33527594, 33544201, 33536850, 33541053, 33703661, 33541815, 33542545, 33546701, 33535384, 33534600, 33542403, 33537999, 33535312, 33517388, 33526021, 33529058, 33525608, 33519102, 33526629, 33521893, 33522875, 33517650, 33518231, 33529155, 33520346, 33527268, 33534098, 33523539, 33530952, 33517380, 33524963, 33534497, 33515976, 33525143, 33533510, 33537952, 33522508, 33529944, 33526331, 33526098, 33528798, 33530123, 33526175, 33521545, 33528309, 33578708, 33576696, 33575977, 33568026, 33571619, 33573293, 33562620, 33572203, 33558839, 33570495, 33582488, 33574208, 33570762, 33569177, 33570554, 33583156, 33581810, 33584654, 33588935, 33582950, 33577243, 33588485, 33585635, 33577819, 33585672, 33576269, 33567616, 33573095, 33575835, 33573002, 33572287, 33583696, 33581391, 33592521, 33602411, 33597671, 33585357, 33579298, 33596633, 33594862, 33590652, 33594049, 33589206, 33589132, 33582541, 33588669, 33588860, 33586400, 33590978, 33606347, 33595998, 33594983, 33596136, 33597884, 33611286, 33599358, 33589084, 33594240, 33600096, 33597159, 33587956, 33598046, 33586236, 33600536, 33550197, 33558145, 33547744, 33557433, 33548825, 33544280, 33546597, 33544771, 33540823, 33555081, 33545099, 33553813, 33547502, 33541819, 33554077, 33547596, 33555980, 33566553, 33554467, 33565135, 33554630, 33553224, 33558269, 33551040, 33556039, 33551951, 33559816, 33557544, 33550701, 33538613, 33547973, 33555503, 33563381, 33555141, 33557966, 33567547, 33564044, 33554332, 33559166, 33569012, 33555266, 33546330, 33564221, 33550876, 33568552, 33561245, 33562439, 33561461, 33554853, 33568432, 33568634, 33573413, 33572645, 33568286, 33562517, 33565335, 33559990, 33559292, 33566016, 33562895, 33574261, 33561326, 33568381, 33561235], [33537878, 33533202, 33530972, 33533324, 33522350, 33537038, 33527769, 33529108, 33537915, 33532987, 33531759, 33546662, 33530753, 33541313, 33540477, 33527512, 33519914, 33538266, 33529815, 33528023, 33533814, 33536035, 33527814, 33518803, 33531388, 33528843, 33534789, 33542626, 33525760, 33538660, 33532694, 33537543, 33540724, 33543776, 33539218, 33545249, 33540273, 33547354, 33546065, 33539965, 33542118, 33549966, 33550580, 33542160, 33544396, 33540674, 33533047, 33536929, 33542525, 33551536, 33541005, 33542051, 33540730, 33542590, 33540401, 33541380, 33538369, 33535957, 33543334, 33535879, 33543059, 33542440, 33533003, 33548882, 33540909, 33548402, 33538612, 33542802, 33539931, 33551816, 33539946, 33540865, 33704613, 33531962, 33535477, 33528528, 33546704, 33541154, 33550545, 33533957, 33537387, 33536277, 33537310, 33538599, 33703616, 33540426, 33538241, 33536487, 33546476, 33534409, 33532057, 33536587, 33544536, 33532372, 33539943, 33539952, 33523220, 33518650, 33541445, 33529725, 33532426, 33543039, 33535999, 33533395, 33527927, 33538616, 33535284, 33523335, 33527206, 33532544, 33523265, 33529250, 33527833, 33528653, 33528133, 33534952, 33531823, 33521364, 33514162, 33518436, 33518612, 33524180, 33526222, 33527316, 33529497, 33528091, 33523886, 33527092, 33578195, 33589590, 33572860, 33576689, 33577573, 33582092, 33577540, 33569132, 33584949, 33581599, 33580130, 33591745, 33583658, 33576338, 33582541, 33585317, 33579660, 33565776, 33568687, 33579108, 33574092, 33570286, 33572778, 33575911, 33576789, 33570720, 33567017, 33574302, 33564902, 33565926, 33562817, 33573327, 33598794, 33589803, 33605090, 33597323, 33597905, 33602534, 33597108, 33588479, 33600778, 33609074, 33599459, 33612039, 33602348, 33597844, 33607499, 33600268, 33597852, 33591269, 33575703, 33586231, 33587778, 33579115, 33584095, 33585910, 33585984, 33606617, 33596317, 33587165, 33588974, 33593688, 33587550, 33605243, 33550325, 33547687, 33546108, 33554114, 33543451, 33544768, 33548423, 33544270, 33558852, 33551491, 33551919, 33562692, 33551297, 33555983, 33553724, 33556978, 33539945, 33538357, 33560994, 33548473, 33555746, 33541875, 33554011, 33546441, 33556437, 33546065, 33547145, 33549216, 33553231, 33551219, 33548424, 33545060, 33565088, 33572765, 33557507, 33557253, 33567539, 33562467, 33560427, 33566381, 33573078, 33554435, 33570331, 33558267, 33564751, 33570206, 33583985, 33569729, 33553219, 33540018, 33561280, 33559359, 33553119, 33557996, 33553853, 33557702, 33558409, 33567215, 33563965, 33551271, 33556041, 33573319, 33546211, 33556886], [33537144, 33526845, 33526910, 33531006, 33523300, 33534058, 33530559, 33538991, 33529108, 33530150, 33535829, 33530587, 33531954, 33525647, 33542097, 33527497, 33532567, 33536870, 33546369, 33541689, 33545903, 33541473, 33540942, 33547017, 33521998, 33544496, 33524798, 33541106, 33529174, 33534531, 33532653, 33530614, 33535268, 33543385, 33546133, 33546233, 33542346, 33538005, 33537743, 33546283, 33538695, 33534429, 33543157, 33538532, 33546480, 33539564, 33546350, 33537950, 33547437, 33536721, 33541495, 33540074, 33546213, 33542660, 33548667, 33549235, 33549836, 33541874, 33544210, 33545552, 33547196, 33540916, 33543471, 33543571, 33537189, 33534750, 33541411, 33538788, 33535767, 33544736, 33545685, 33529822, 33549456, 33705957, 33537473, 33526240, 33538000, 33536544, 33536548, 33539272, 33552341, 33549413, 33539804, 33530657, 33704308, 33537301, 33530464, 33519576, 33536906, 33541461, 33540472, 33539332, 33534744, 33540029, 33534291, 33538886, 33533696, 33531937, 33521600, 33524333, 33531457, 33529867, 33525614, 33522094, 33534509, 33526402, 33529906, 33524067, 33526284, 33526211, 33533124, 33515174, 33520063, 33526761, 33530691, 33534544, 33537521, 33535635, 33533987, 33522648, 33535019, 33526421, 33525493, 33530583, 33524923, 33533679, 33534754, 33515439, 33579161, 33560841, 33578175, 33576948, 33563618, 33570317, 33565024, 33569823, 33567780, 33568199, 33567633, 33568339, 33568039, 33557674, 33565886, 33564481, 33586508, 33583131, 33576410, 33579237, 33586011, 33578218, 33579674, 33586332, 33583170, 33584730, 33573928, 33572788, 33587496, 33577170, 33577946, 33582039, 33595882, 33589302, 33593128, 33581858, 33602081, 33588961, 33597119, 33603738, 33575422, 33570724, 33588913, 33587124, 33587578, 33587638, 33589250, 33579947, 33601153, 33591586, 33603489, 33587902, 33594249, 33597391, 33605531, 33594619, 33595434, 33583316, 33592025, 33591682, 33593510, 33597794, 33598972, 33601344, 33548810, 33551344, 33556170, 33553608, 33550266, 33546114, 33550403, 33550745, 33540207, 33544458, 33540759, 33534627, 33546575, 33549253, 33541623, 33547977, 33547204, 33557962, 33558124, 33563638, 33556547, 33552815, 33549990, 33560825, 33552993, 33547297, 33556495, 33547228, 33545386, 33549898, 33554596, 33548828, 33568798, 33563271, 33567855, 33561723, 33561931, 33563705, 33565196, 33561506, 33562612, 33561562, 33548088, 33559823, 33565143, 33558498, 33566157, 33557169, 33563056, 33568485, 33570402, 33566098, 33585977, 33569047, 33565636, 33559592, 33562094, 33567382, 33572614, 33570861, 33567993, 33567319, 33568167, 33563057], [33531557, 33537141, 33537520, 33530213, 33535367, 33526352, 33527961, 33538095, 33536978, 33524770, 33538025, 33539271, 33537282, 33531511, 33529683, 33529918, 33538605, 33541181, 33536667, 33545344, 33541538, 33546896, 33528103, 33534823, 33532048, 33531802, 33541365, 33544191, 33532833, 33535900, 33530078, 33524439, 33536696, 33533497, 33543791, 33542477, 33540127, 33526432, 33531382, 33530634, 33540957, 33531115, 33542871, 33539342, 33537614, 33537576, 33535956, 33544624, 33533303, 33535858, 33547821, 33549706, 33540371, 33544459, 33556819, 33547268, 33544081, 33535751, 33552643, 33543072, 33537354, 33550125, 33546766, 33542538, 33538271, 33533306, 33541012, 33539266, 33542236, 33540453, 33543202, 33534189, 33549017, 33540841, 33550075, 33527840, 33529695, 33542057, 33698253, 33534447, 33707032, 33513999, 33544669, 33542041, 33529315, 33543104, 33545337, 33529743, 33546479, 33540596, 33538301, 33542331, 33542484, 33547603, 33542043, 33542116, 33528412, 33528639, 33521707, 33521847, 33529853, 33526545, 33526336, 33528135, 33535870, 33524812, 33526045, 33532047, 33522058, 33526176, 33527152, 33528193, 33530248, 33538252, 33526732, 33529756, 33519207, 33526449, 33527454, 33524009, 33540226, 33533194, 33528054, 33535074, 33529879, 33531960, 33532299, 33527624, 33581780, 33575182, 33574540, 33577754, 33579580, 33571217, 33577530, 33573617, 33572961, 33572310, 33571090, 33569800, 33565242, 33564937, 33576304, 33564481, 33589248, 33583957, 33574431, 33585815, 33577651, 33580547, 33576427, 33589929, 33580109, 33592527, 33577959, 33583263, 33573357, 33580219, 33577245, 33577314, 33596810, 33587789, 33588475, 33593265, 33589042, 33591364, 33586379, 33587271, 33579486, 33570785, 33587009, 33587369, 33585281, 33585639, 33580243, 33583711, 33602073, 33607482, 33612065, 33602086, 33601546, 33596467, 33606929, 33605139, 33592880, 33590927, 33596143, 33595248, 33601759, 33593003, 33589538, 33597453, 33548946, 33540246, 33546019, 33530727, 33548920, 33548324, 33553126, 33549971, 33550738, 33547443, 33548437, 33552848, 33541681, 33538266, 33553901, 33560310, 33549481, 33559974, 33553772, 33563338, 33543456, 33549649, 33558780, 33550058, 33554897, 33546010, 33558709, 33545097, 33556176, 33549536, 33554918, 33555742, 33562152, 33559846, 33556559, 33556236, 33563723, 33555231, 33566730, 33562194, 33557852, 33563946, 33548701, 33560283, 33547439, 33557692, 33542798, 33555488, 33579218, 33568329, 33566490, 33572071, 33563763, 33572057, 33566670, 33565480, 33559309, 33561368, 33564451, 33556217, 33558965, 33567648, 33567485, 33563646], [33529374, 33531730, 33542178, 33528542, 33543599, 33523669, 33537989, 33524815, 33538994, 33537465, 33546313, 33531024, 33543173, 33528157, 33532709, 33525329, 33539486, 33522101, 33547940, 33525892, 33538352, 33534112, 33540454, 33528265, 33539312, 33531885, 33548307, 33527830, 33544169, 33531047, 33541718, 33530204, 33548541, 33533389, 33547392, 33533704, 33535446, 33532910, 33557346, 33531475, 33546510, 33529976, 33537604, 33535711, 33547199, 33533324, 33560574, 33522592, 33550917, 33541959, 33549651, 33536676, 33552250, 33538907, 33543901, 33535884, 33554235, 33536570, 33545779, 33540223, 33548980, 33534935, 33550651, 33529609, 33530145, 33540122, 33531554, 33537476, 33531967, 33697860, 33543205, 33538931, 33535990, 33540117, 33536351, 33547382, 33545476, 33539704, 33542556, 33551356, 33540865, 33543956, 33549345, 33526061, 33543043, 33550186, 33536775, 33537262, 33546399, 33536578, 33703929, 33535976, 33536958, 33538735, 33547860, 33544972, 33536251, 33519866, 33531836, 33515075, 33535026, 33523806, 33529860, 33535902, 33540025, 33518441, 33549745, 33522635, 33524580, 33527681, 33533114, 33521482, 33549266, 33526060, 33531583, 33519249, 33540645, 33535524, 33530191, 33518221, 33541592, 33537928, 33543808, 33520464, 33522675, 33521220, 33536876, 33529813, 33576191, 33573870, 33571078, 33563381, 33566180, 33563713, 33573666, 33566378, 33576751, 33572591, 33583459, 33575304, 33573197, 33567400, 33575536, 33562391, 33600108, 33567111, 33586567, 33574593, 33585443, 33565679, 33588626, 33571561, 33593436, 33570020, 33588539, 33577284, 33581370, 33585594, 33584952, 33575402, 33573065, 33578383, 33582015, 33573113, 33577807, 33577787, 33588836, 33566327, 33582620, 33581997, 33590045, 33566489, 33587207, 33579346, 33579876, 33579913, 33593572, 33592107, 33609270, 33603170, 33599587, 33590622, 33597718, 33598314, 33611564, 33604706, 33607088, 33612706, 33597871, 33603029, 33602889, 33597033, 33555129, 33534069, 33542807, 33541407, 33550961, 33548024, 33546909, 33539786, 33547909, 33535047, 33551759, 33542603, 33551435, 33539537, 33552047, 33551608, 33563089, 33544094, 33554327, 33539944, 33557017, 33551796, 33562025, 33541173, 33561646, 33565630, 33559937, 33554981, 33553404, 33555544, 33568907, 33555156, 33561107, 33557667, 33571295, 33550432, 33560966, 33544842, 33567127, 33542584, 33565248, 33553481, 33569501, 33559564, 33561547, 33553107, 33571837, 33552159, 33568745, 33560230, 33564896, 33563474, 33573019, 33562641, 33564756, 33557545, 33557062, 33567312, 33582834, 33561782, 33563697, 33547005, 33572261, 33561233]];
        // let mut counts = vec![[0usize; 256]; length];

        let pool_size = 12;
        let trials = 1usize << 24;
        let f_trials = trials as f64;

        let pool: Pool<ThunkWorker<Vec<u8>>> = Pool::new(pool_size);
        let (tx, rx) = channel();

        let mut i = 0;
        println!("Active count: {}", pool.active_count());
        for _ in 0..=pool_size {
            println!("Enqueed");
            let tmp = oracle.clone();
            pool.execute_to(
                tx.clone(),
                Thunk::of(move || {
                    tmp.encrypt(&[b'A'])
                }),
            );
        }
        println!("Active count: {}", pool.active_count());

        while i < trials {
            // println!("Fod");
            if i % (1024 * 1024) == 0 {
                println!("Trial {} ({})", i, (i as f64 / f_trials));
            }
            let tmp = rx.recv()?;
            for (idx, val) in tmp.iter().enumerate().skip(1) {
                counts[idx - 1][*val as usize] += 1;
            }
            i += 1;
            let tmp = oracle.clone();

            pool.execute_to(
                tx.clone(),
                Thunk::of(move || {
                    tmp.encrypt(&[b'A'])
                }),
            );
        }

        let mut result = vec![0u8; length];
        for (r, val) in result.iter_mut().enumerate() {
            *val = rc4_single_byte_attack(counts[r], r + 1, &RC4_DISTRIBUTION)?;
        }
        println!("Saved state: {:?}", counts);
        println!("Hex: {}", result.encode_hex::<String>());
        println!("Result: {}", String::from_utf8_lossy(&result));

        assert!(oracle.check(&result));
        Ok(())
    }
}
