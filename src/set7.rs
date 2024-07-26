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
    let mut x: Vec<u32> = to_w32_be(block).iter().map(|w| u32::from_be(*w)).collect();
    // First condition
    {
        let mut a1 = MD4::ff(a0, b0, c0, d0, 0, 3, &x);
        // Fix the bad bit
        a1 ^= (a1.bit(6) ^ b0.bit(6)) << 6;
        x[0] = a1
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
        let _round = step / 16;
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
    let _state = apply_md4_constraints(&mut block, &MD4CollisionConstraints[0..16]);
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
    #[ignore = "slow"]
    fn challenge56() -> Result<()> {
        let oracle = Challenge56Oracle::new();
        let length = oracle.encrypt(&[]).len();
        let mut counts = vec![
            [
                2088579, 2086178, 2087128, 2087156, 2086754, 2084416, 2085954, 2087457, 2086900,
                2087392, 2087742, 2089035, 2088056, 2087653, 2089598, 2089204, 2084734, 2089082,
                2085781, 2087692, 2088391, 2087259, 2090005, 2084849, 2086523, 2087545, 2089503,
                2087983, 2088219, 2088228, 2088913, 2090214, 2086619, 2087912, 2086605, 2087643,
                2089797, 2089332, 2086835, 2087917, 2085308, 2084906, 2087182, 2089400, 2088932,
                2086577, 2086925, 2090238, 2088981, 2090905, 2086938, 2091348, 2092454, 2086577,
                2088707, 2087729, 2085876, 2091392, 2087208, 2087901, 2090384, 2088653, 2088618,
                2089740, 2070935, 2080883, 4198111, 2077562, 2086113, 2084917, 2081932, 2082159,
                2082622, 2083225, 2082378, 2083690, 2085786, 2084117, 2083666, 2084591, 2082112,
                2086231, 2084269, 2083406, 2088029, 2084965, 2086004, 2084426, 2083317, 2085006,
                2086129, 2086230, 2087502, 2086438, 2086371, 2085268, 2083634, 2087155, 2084371,
                2085112, 2086079, 2085511, 2085497, 2083972, 2086319, 2089038, 2085004, 2087231,
                2087310, 2086683, 2085247, 2086202, 2084617, 2089073, 2086695, 2087682, 2087701,
                2089325, 2087220, 2085006, 2086342, 2085187, 2085750, 2086431, 2089558, 2087436,
                2086055, 2087436, 2090009, 2092984, 2091568, 2091727, 2090119, 2091406, 2091692,
                2090921, 2091940, 2092661, 2093143, 2090375, 2091899, 2093582, 2091557, 2089039,
                2092608, 2092113, 2092281, 2094595, 2092223, 2092305, 2092343, 2092567, 2090667,
                2092072, 2090991, 2088949, 2093917, 2091216, 2091745, 2091975, 2091536, 2094737,
                2093903, 2090382, 2091087, 2092708, 2092371, 2091930, 2091598, 2093599, 2089176,
                2090658, 2092966, 2096698, 2094183, 2094663, 2092483, 2089817, 2091496, 2094481,
                2089534, 2091982, 2090349, 2092275, 2094175, 2094278, 2090834, 2093024, 2093342,
                2093991, 2093880, 2090447, 2088015, 2088982, 2087560, 2082580, 2088993, 2087525,
                2087492, 2088614, 2090861, 2090208, 2088897, 2089398, 2089585, 2089969, 2090116,
                2088827, 2089569, 2090763, 2089951, 2090297, 2091056, 2089065, 2091274, 2089045,
                2092557, 2090059, 2089823, 2089812, 2091497, 2090398, 2091021, 2090610, 2090559,
                2089383, 2091426, 2092574, 2087471, 2089286, 2090157, 2089427, 2091385, 2089244,
                2091472, 2093056, 2090633, 2090287, 2096289, 2092307, 2091542, 2090032, 2091829,
                2090078, 2091654, 2091550, 2091722, 2090755, 2089650, 2092514, 2089969, 2089546,
                2091920, 2095207, 2091582, 2092284,
            ],
            [
                2094136, 2095039, 2097744, 2096297, 2098396, 2096637, 2095409, 2094543, 2094441,
                2096491, 2093128, 2096131, 2095632, 2094779, 2096078, 2095731, 2096586, 2096104,
                2094381, 2098821, 2095933, 2096247, 2094639, 2097882, 2096454, 2098028, 2096321,
                2097295, 2097137, 2094675, 2092840, 2096199, 2097771, 2099009, 2096413, 2095767,
                2094541, 2098494, 2094811, 2094861, 2096442, 2099254, 2096676, 2097532, 2098029,
                2096589, 2097771, 2095944, 2098433, 2096584, 2097732, 2096492, 2097093, 2099755,
                2094624, 2098319, 2096883, 2097711, 2097097, 2096281, 2099289, 2097300, 2096521,
                2096858, 2094256, 2095143, 2095636, 2094026, 2095948, 2099544, 2099889, 2096167,
                2095513, 2096175, 2097663, 2095045, 2095042, 2093065, 2092932, 2094325, 2094679,
                2094948, 2097974, 2093558, 2094936, 2094081, 2095403, 2095765, 2095395, 2096708,
                2095091, 2094694, 2097862, 2094276, 2094726, 2097873, 2098478, 2095212, 2094720,
                2094391, 2094370, 2096028, 2094505, 2094437, 2095146, 2092650, 2094725, 2096931,
                2099110, 2093052, 2091370, 2094854, 2099205, 2098232, 2095112, 2096552, 2094668,
                2095790, 2094062, 2095178, 2095326, 2095239, 2096846, 2095753, 2094154, 2094288,
                2094689, 2095541, 2096962, 2098978, 2097413, 2100542, 2098965, 2099048, 2099379,
                2097004, 2095352, 2097730, 2098358, 2097554, 2100051, 2097569, 2100023, 2097646,
                2096561, 2098706, 2097798, 2099066, 2096900, 2100305, 2098516, 2097904, 2099948,
                2096308, 2099113, 2098121, 2097949, 2100913, 2101969, 2097099, 2101939, 2100783,
                2100690, 2100098, 2102394, 2098644, 2098789, 2099918, 2098010, 2099917, 2100044,
                2100142, 2098777, 2099727, 2100199, 2101541, 2103025, 2099722, 2100799, 2099742,
                2098195, 2099189, 2099941, 2100647, 2100078, 2098901, 2098959, 2101087, 2101135,
                2099393, 2099340, 2100907, 2093852, 2096589, 2097990, 2097353, 2094247, 2096012,
                2103427, 2098452, 2097775, 2097561, 2096317, 2097849, 2097236, 2099117, 2098055,
                2096914, 2096949, 2098053, 2100763, 2097513, 2097538, 2097271, 2095995, 2097065,
                2098476, 2098194, 2096511, 2097879, 2096171, 2097858, 2093712, 2096052, 2096483,
                2096951, 2096515, 2098766, 2095357, 2097416, 2097625, 2095808, 2096543, 2099687,
                2100130, 2097330, 2099008, 2099060, 2096111, 2095405, 2096147, 2097653, 2098043,
                2098794, 2095766, 2096438, 2098147, 2100404, 2097831, 2099150, 2097164, 2094825,
                2097315, 2095718, 2098512, 2097660,
            ],
            [
                2096646, 2096374, 2097991, 2094811, 2095531, 2094462, 2094876, 2095441, 2096866,
                2095885, 2096959, 2096415, 2092479, 2094866, 2094998, 2092845, 2096410, 2095112,
                2094454, 2093958, 2094480, 2095544, 2096503, 2095263, 2094731, 2096578, 2094465,
                2096992, 2096584, 2094910, 2096996, 2093659, 2105564, 2096084, 2104186, 2096933,
                2106975, 2094472, 2094423, 2094305, 2095902, 2095048, 2091712, 2094828, 2096243,
                2095825, 2096950, 2096576, 2096506, 2096779, 2093680, 2093487, 2096313, 2094831,
                2097563, 2095454, 2096021, 2096888, 2094640, 2093186, 2094541, 2094066, 2095597,
                2095274, 2095438, 2094456, 2095161, 2097712, 2098264, 2094115, 2095032, 2097086,
                2096464, 2097089, 2097729, 2097686, 2096529, 2093430, 2096956, 2096355, 2096523,
                2096366, 2098063, 2097619, 2095096, 2096601, 2097670, 2096714, 2095174, 2097282,
                2098112, 2096452, 2096119, 2096823, 2098962, 2096975, 2095199, 2094991, 2094940,
                2094384, 2095341, 2095063, 2098647, 2095494, 2093760, 2098162, 2097175, 2094005,
                2097013, 2096204, 2099515, 2096978, 2095399, 2095516, 2097145, 2095854, 2091919,
                2097457, 2095996, 2094941, 2096493, 2096596, 2094549, 2094976, 2095487, 2096420,
                2098817, 2097740, 2098147, 2096031, 2098123, 2096256, 2095510, 2100321, 2094283,
                2097654, 2097048, 2097019, 2097588, 2095809, 2099027, 2097760, 2097753, 2097727,
                2096631, 2098302, 2097705, 2098513, 2100973, 2098989, 2097322, 2096575, 2097376,
                2098710, 2097052, 2099087, 2099155, 2097387, 2099724, 2096714, 2094323, 2096950,
                2096390, 2095914, 2100956, 2098651, 2094363, 2097451, 2098067, 2097855, 2097264,
                2098557, 2095869, 2097018, 2096854, 2098584, 2096749, 2096016, 2096134, 2098066,
                2098191, 2098013, 2097782, 2097664, 2097282, 2098001, 2096268, 2097392, 2097353,
                2098058, 2096728, 2094971, 2099238, 2098666, 2099022, 2099981, 2098231, 2100662,
                2099192, 2099059, 2099233, 2097842, 2100096, 2098421, 2100533, 2101718, 2097517,
                2099627, 2096783, 2100622, 2101103, 2098206, 2101172, 2101221, 2099880, 2101164,
                2101281, 2096814, 2100102, 2100909, 2099741, 2100641, 2101136, 2100793, 2097208,
                2098428, 2099025, 2097905, 2098232, 2099708, 2099204, 2095875, 2097618, 2098315,
                2096849, 2098072, 2100093, 2098613, 2098122, 2096823, 2099901, 2100009, 2096661,
                2096888, 2098960, 2096070, 2097572, 2097737, 2096599, 2099958, 2097858, 2100708,
                2097593, 2101010, 2099988, 2099534,
            ],
            [
                2096962, 2096250, 2097375, 2096377, 2095202, 2098081, 2096062, 2094045, 2094982,
                2098969, 2094474, 2098162, 2095453, 2095346, 2095233, 2097312, 2094763, 2097788,
                2096885, 2096540, 2094450, 2096343, 2094934, 2097528, 2095909, 2094448, 2094430,
                2095106, 2096586, 2093971, 2095757, 2095890, 2097266, 2098274, 2095537, 2093098,
                2097199, 2095096, 2099061, 2094880, 2096409, 2095381, 2097617, 2094872, 2094523,
                2096438, 2096867, 2096319, 2095287, 2094964, 2096732, 2096552, 2097242, 2095915,
                2094691, 2096728, 2095647, 2098720, 2095864, 2096145, 2093819, 2097035, 2095593,
                2093250, 2096607, 2093980, 2094640, 2095756, 2097395, 2094284, 2094408, 2098134,
                2094828, 2093643, 2095786, 2097157, 2094168, 2094976, 2095320, 2095143, 2096344,
                2093738, 2096041, 2107350, 2096193, 2094960, 2109579, 2098039, 2094917, 2096072,
                2096348, 2092111, 2091854, 2095004, 2097064, 2095718, 2095891, 2095305, 2094304,
                2093955, 2094534, 2095364, 2096414, 2096432, 2095763, 2095661, 2093212, 2093679,
                2095660, 2096168, 2092982, 2094973, 2093148, 2093724, 2096481, 2097110, 2096555,
                2095700, 2094576, 2095691, 2092561, 2094841, 2096212, 2095731, 2095850, 2096592,
                2095198, 2092445, 2099758, 2099623, 2100097, 2096973, 2099988, 2098711, 2098682,
                2100344, 2098724, 2099282, 2098405, 2099962, 2097507, 2098474, 2095206, 2098907,
                2097797, 2099511, 2097378, 2097695, 2098593, 2099793, 2097211, 2099203, 2096474,
                2099150, 2099475, 2099355, 2099560, 2098149, 2097618, 2099111, 2100007, 2100287,
                2099072, 2101990, 2097772, 2100118, 2099405, 2101051, 2101918, 2100314, 2099955,
                2102267, 2100419, 2101886, 2097855, 2101306, 2100526, 2100148, 2100538, 2099583,
                2100909, 2098289, 2101451, 2100080, 2099890, 2098907, 2103444, 2101089, 2097203,
                2099942, 2100570, 2097675, 2096871, 2095147, 2094943, 2096933, 2099262, 2100731,
                2097808, 2095767, 2099340, 2097062, 2098526, 2097726, 2095385, 2097687, 2096606,
                2096941, 2096334, 2096271, 2098726, 2095634, 2097461, 2098107, 2096327, 2097114,
                2095422, 2098359, 2100177, 2097741, 2096291, 2098140, 2096185, 2096581, 2098038,
                2095385, 2098689, 2101153, 2097919, 2096969, 2098197, 2096535, 2097300, 2098002,
                2097719, 2099646, 2098456, 2100842, 2101798, 2100048, 2096080, 2097067, 2097526,
                2099043, 2097531, 2097937, 2098736, 2101109, 2096126, 2097569, 2096694, 2094657,
                2096173, 2096644, 2095815, 2096419,
            ],
            [
                2097593, 2096384, 2092942, 2095730, 2095823, 2097148, 2097496, 2097493, 2094204,
                2094981, 2096429, 2095906, 2096095, 2098823, 2098024, 2097724, 2095558, 2097796,
                2095876, 2095221, 2095041, 2095714, 2095656, 2097029, 2095402, 2095471, 2096359,
                2094285, 2096501, 2096937, 2095240, 2095884, 2098228, 2095695, 2098312, 2096844,
                2096071, 2096529, 2097188, 2096537, 2097533, 2096832, 2097745, 2096201, 2095640,
                2094976, 2096869, 2096026, 2098549, 2095678, 2095285, 2096324, 2096985, 2097281,
                2092658, 2095985, 2097060, 2095369, 2097503, 2097735, 2097299, 2096803, 2096557,
                2097282, 2094532, 2094027, 2094556, 2092371, 2095612, 2095125, 2094780, 2096011,
                2093389, 2097752, 2099395, 2095993, 2096106, 2095572, 2093729, 2095858, 2096320,
                2098428, 2094832, 2110936, 2094683, 2107858, 2095790, 2098986, 2095624, 2094978,
                2094971, 2096505, 2094592, 2092707, 2095685, 2094294, 2093457, 2096842, 2093154,
                2097422, 2096001, 2095269, 2093616, 2094227, 2095847, 2096243, 2094896, 2096162,
                2094476, 2096136, 2094088, 2096761, 2094493, 2094668, 2094036, 2094427, 2098333,
                2095063, 2097544, 2095088, 2097148, 2096637, 2095533, 2093955, 2093296, 2096900,
                2094186, 2094047, 2099850, 2099402, 2097891, 2098014, 2098858, 2099594, 2095616,
                2099261, 2097461, 2101111, 2097844, 2097214, 2099022, 2100120, 2098108, 2097873,
                2095582, 2097837, 2099469, 2098108, 2099121, 2098177, 2099250, 2099870, 2098547,
                2100904, 2094505, 2097580, 2100113, 2100640, 2097638, 2097980, 2101409, 2102200,
                2098405, 2101672, 2101559, 2099967, 2100274, 2098031, 2101160, 2098308, 2099968,
                2100436, 2101462, 2100698, 2103903, 2098901, 2098575, 2097601, 2097326, 2101203,
                2098231, 2096916, 2098183, 2095984, 2100531, 2100187, 2101618, 2100429, 2099532,
                2099427, 2097529, 2096986, 2097489, 2096842, 2098115, 2100547, 2096596, 2095239,
                2098521, 2097617, 2094399, 2098575, 2096304, 2097315, 2096301, 2100364, 2095262,
                2100460, 2096799, 2097423, 2096826, 2095030, 2095282, 2096962, 2094445, 2095182,
                2098175, 2098801, 2097926, 2099016, 2096935, 2097743, 2096840, 2097837, 2100384,
                2096645, 2094314, 2095756, 2100137, 2096910, 2096385, 2096939, 2097871, 2097291,
                2097532, 2097618, 2097783, 2097712, 2097909, 2097548, 2098215, 2095339, 2098242,
                2096156, 2099331, 2095990, 2097745, 2098122, 2094571, 2099264, 2098533, 2099400,
                2097318, 2097891, 2097649, 2095781,
            ],
            [
                2095012, 2096179, 2096002, 2094644, 2096829, 2098798, 2094889, 2096580, 2096170,
                2096274, 2095977, 2100733, 2097082, 2094807, 2093946, 2094751, 2096458, 2094774,
                2096505, 2095921, 2094767, 2096758, 2096965, 2097151, 2095191, 2093966, 2097329,
                2096346, 2096886, 2096804, 2095687, 2094876, 2094653, 2097106, 2095821, 2094861,
                2096284, 2094936, 2094753, 2095804, 2097436, 2095630, 2096799, 2098122, 2094343,
                2097492, 2095178, 2097641, 2095176, 2096240, 2096094, 2098488, 2099373, 2096386,
                2097550, 2096067, 2098010, 2095540, 2096138, 2094555, 2095285, 2097268, 2094638,
                2098468, 2096058, 2093619, 2093799, 2097012, 2095342, 2095483, 2095641, 2094812,
                2095762, 2095652, 2097187, 2093063, 2093689, 2093909, 2096147, 2092579, 2094579,
                2098092, 2107999, 2095529, 2095842, 2109759, 2096322, 2094568, 2093127, 2096789,
                2094144, 2096154, 2096140, 2093300, 2096691, 2096001, 2093000, 2098057, 2095326,
                2096316, 2095221, 2091870, 2095370, 2096874, 2095073, 2092664, 2097923, 2095213,
                2096889, 2096857, 2094281, 2095755, 2096526, 2096294, 2094144, 2094879, 2096190,
                2097076, 2096851, 2096852, 2095461, 2094148, 2097053, 2097667, 2098021, 2095105,
                2096089, 2098678, 2097008, 2097919, 2097081, 2101467, 2096063, 2096861, 2097944,
                2100262, 2099392, 2100290, 2099390, 2098902, 2098919, 2099732, 2097456, 2099438,
                2098086, 2101845, 2098153, 2096172, 2100472, 2098387, 2097409, 2098180, 2097519,
                2096494, 2094001, 2099456, 2094261, 2099572, 2100697, 2098846, 2099763, 2099297,
                2100615, 2101122, 2100299, 2100641, 2100464, 2099356, 2104430, 2101823, 2099852,
                2100509, 2102913, 2100066, 2100502, 2099268, 2099823, 2100107, 2098092, 2096368,
                2096953, 2097365, 2096607, 2098177, 2096983, 2098360, 2101702, 2099147, 2101338,
                2100031, 2101580, 2098815, 2097860, 2097411, 2096967, 2097854, 2101806, 2096615,
                2096741, 2096483, 2098234, 2097880, 2096239, 2096813, 2093808, 2096838, 2096777,
                2096515, 2097469, 2095863, 2096934, 2093421, 2097494, 2093584, 2095483, 2096678,
                2097365, 2097054, 2093903, 2098469, 2098380, 2096665, 2096842, 2096037, 2098079,
                2098901, 2096554, 2096437, 2099934, 2097226, 2100606, 2100298, 2099787, 2099149,
                2100835, 2098107, 2097229, 2097528, 2098392, 2100426, 2096507, 2099936, 2095489,
                2098710, 2097225, 2097758, 2096917, 2098129, 2096957, 2096815, 2094554, 2094670,
                2098424, 2098527, 2098281, 2096296,
            ],
            [
                2094538, 2092431, 2095003, 2095195, 2098763, 2096323, 2095374, 2096078, 2095699,
                2095485, 2093247, 2096220, 2095014, 2096287, 2096919, 2094190, 2097048, 2094753,
                2093865, 2099360, 2096842, 2095062, 2096256, 2096670, 2094601, 2094196, 2096154,
                2098859, 2097873, 2095865, 2096093, 2098243, 2097148, 2094985, 2096548, 2094965,
                2097698, 2095845, 2094164, 2094328, 2094247, 2095322, 2097730, 2094330, 2097787,
                2095618, 2098116, 2096659, 2096479, 2098767, 2093307, 2097322, 2094632, 2097099,
                2096932, 2096991, 2095834, 2096542, 2096294, 2096621, 2096617, 2095368, 2097080,
                2096697, 2097073, 2097418, 2095809, 2096703, 2094618, 2109728, 2094787, 2098105,
                2095774, 2093204, 2094431, 2093956, 2093993, 2110067, 2093828, 2092576, 2097962,
                2094689, 2093531, 2096699, 2096423, 2094028, 2094071, 2094718, 2097482, 2095833,
                2095060, 2096502, 2096066, 2094168, 2098787, 2093632, 2095037, 2095387, 2094267,
                2092561, 2096179, 2094658, 2096602, 2096679, 2095133, 2097677, 2094443, 2095718,
                2097424, 2096523, 2095930, 2094997, 2095228, 2093864, 2095080, 2095066, 2097055,
                2095860, 2097485, 2096765, 2096304, 2094363, 2094879, 2098472, 2095722, 2097811,
                2094539, 2095411, 2097291, 2096727, 2099751, 2097344, 2099177, 2095815, 2099341,
                2098832, 2097123, 2097621, 2098954, 2099375, 2099011, 2096571, 2097587, 2097741,
                2099572, 2098527, 2096514, 2099432, 2097911, 2100501, 2097881, 2097689, 2099659,
                2100003, 2100649, 2099796, 2099702, 2097551, 2099063, 2098610, 2101419, 2102436,
                2099123, 2099271, 2097722, 2098276, 2100711, 2100739, 2098876, 2099075, 2097713,
                2098645, 2102989, 2098729, 2099956, 2101355, 2100024, 2099637, 2100014, 2102820,
                2099548, 2099994, 2099084, 2098754, 2098213, 2098422, 2101874, 2098691, 2099999,
                2098586, 2098823, 2102646, 2094672, 2096564, 2097092, 2096203, 2098107, 2094752,
                2095464, 2097683, 2095834, 2098884, 2096998, 2096936, 2097348, 2096883, 2096783,
                2097785, 2096808, 2097842, 2098869, 2098841, 2096840, 2097072, 2100429, 2095648,
                2097941, 2099226, 2095956, 2096074, 2097756, 2096864, 2097721, 2096410, 2095364,
                2096307, 2094309, 2097105, 2098328, 2096969, 2098559, 2094826, 2096550, 2098910,
                2097339, 2100245, 2097275, 2097554, 2098727, 2095983, 2098461, 2098800, 2098886,
                2097666, 2101218, 2096301, 2095780, 2098375, 2097543, 2099311, 2095426, 2098523,
                2101072, 2097053, 2100812, 2096147,
            ],
            [
                2095470, 2093683, 2095006, 2096302, 2096238, 2094357, 2096843, 2094526, 2094720,
                2096284, 2095943, 2096320, 2096425, 2093913, 2093016, 2095713, 2096305, 2094331,
                2097025, 2096548, 2095765, 2095105, 2094519, 2095030, 2098324, 2094154, 2096943,
                2097084, 2096591, 2097534, 2091256, 2095432, 2105752, 2096090, 2093605, 2094660,
                2096764, 2096024, 2095754, 2098321, 2095378, 2109198, 2094429, 2094736, 2095203,
                2092998, 2094003, 2096110, 2098306, 2095155, 2096383, 2096200, 2094157, 2094685,
                2095611, 2094247, 2095212, 2094848, 2095960, 2094615, 2096702, 2096356, 2095063,
                2095627, 2095171, 2095735, 2094909, 2098352, 2095850, 2095510, 2095181, 2095188,
                2097456, 2097289, 2097496, 2096182, 2095730, 2095689, 2095373, 2096315, 2097649,
                2097886, 2094237, 2096550, 2097637, 2097302, 2095246, 2099054, 2096895, 2095413,
                2096611, 2097636, 2097335, 2098795, 2097346, 2097786, 2097689, 2095182, 2096584,
                2096300, 2096454, 2094771, 2094547, 2094790, 2095691, 2096595, 2095671, 2097054,
                2096297, 2097511, 2097218, 2095990, 2097703, 2096329, 2093854, 2095710, 2095638,
                2092360, 2094489, 2096524, 2094802, 2096152, 2096352, 2097308, 2094685, 2093331,
                2094940, 2096231, 2097548, 2094785, 2097791, 2096611, 2098055, 2097764, 2098274,
                2096888, 2096946, 2099204, 2095932, 2097693, 2095942, 2096678, 2096498, 2099538,
                2098870, 2096866, 2097762, 2097746, 2097084, 2097387, 2098607, 2099490, 2097288,
                2096950, 2097655, 2097557, 2098617, 2095740, 2098440, 2098997, 2094819, 2097519,
                2095126, 2096195, 2097196, 2097331, 2096234, 2095843, 2096924, 2097786, 2098566,
                2098811, 2097158, 2095694, 2099898, 2095253, 2098430, 2094227, 2096416, 2096012,
                2096818, 2100509, 2096084, 2096774, 2093588, 2099726, 2095842, 2095769, 2097883,
                2097976, 2096294, 2098479, 2100305, 2098631, 2096069, 2100644, 2099045, 2101935,
                2100071, 2100133, 2099542, 2099143, 2101337, 2100089, 2099600, 2102106, 2101846,
                2099561, 2100023, 2097261, 2100672, 2099728, 2101211, 2101060, 2099795, 2099449,
                2098593, 2101493, 2098651, 2100051, 2099714, 2101421, 2100303, 2099986, 2098374,
                2098232, 2098380, 2098832, 2098173, 2098743, 2097693, 2100752, 2100641, 2099292,
                2099122, 2097639, 2095765, 2100132, 2098196, 2095524, 2099267, 2100572, 2099154,
                2096786, 2099792, 2098465, 2100271, 2100499, 2099011, 2100570, 2100485, 2097921,
                2098234, 2096912, 2097655, 2097564,
            ],
            [
                2094111, 2095357, 2092057, 2097348, 2094030, 2094479, 2097985, 2094531, 2097656,
                2095256, 2096997, 2095891, 2096889, 2098209, 2094613, 2094332, 2095526, 2095339,
                2097469, 2095758, 2098828, 2095375, 2093856, 2093746, 2093674, 2095263, 2096930,
                2095965, 2093392, 2095848, 2096174, 2098018, 2098059, 2097878, 2095113, 2096729,
                2096506, 2097382, 2096940, 2097213, 2097953, 2095102, 2096076, 2096524, 2097306,
                2097233, 2095490, 2095118, 2098074, 2093705, 2094321, 2096467, 2096619, 2095352,
                2097346, 2097133, 2097795, 2095031, 2095972, 2097621, 2095280, 2097147, 2099346,
                2096335, 2098040, 2095136, 2096332, 2096423, 2094544, 2093811, 2093446, 2096089,
                2094600, 2092697, 2094971, 2094718, 2095811, 2095540, 2092369, 2097998, 2097612,
                2096395, 2094908, 2098572, 2108038, 2096983, 2097000, 2094081, 2096170, 2095818,
                2093549, 2094763, 2097482, 2097845, 2110962, 2094360, 2095761, 2096411, 2094279,
                2094693, 2098511, 2093730, 2093727, 2093030, 2098711, 2096776, 2096780, 2095893,
                2097384, 2096922, 2094518, 2095292, 2096156, 2095960, 2092025, 2096274, 2095183,
                2095388, 2094410, 2095969, 2094964, 2097211, 2095728, 2095311, 2094003, 2096118,
                2095609, 2094100, 2097146, 2100800, 2099082, 2099073, 2099386, 2098417, 2096693,
                2099927, 2097260, 2097469, 2097413, 2100771, 2099439, 2097433, 2099542, 2097032,
                2098326, 2100832, 2097228, 2100011, 2099870, 2098782, 2100268, 2099000, 2098375,
                2099027, 2097622, 2100018, 2096808, 2101255, 2100375, 2096619, 2098618, 2101028,
                2099011, 2101574, 2099378, 2098952, 2102551, 2100231, 2098583, 2099767, 2096873,
                2102147, 2101335, 2099197, 2100031, 2098557, 2098456, 2098566, 2098585, 2099893,
                2099705, 2099960, 2099002, 2099601, 2101246, 2099325, 2100729, 2099846, 2096888,
                2099861, 2099335, 2098943, 2096935, 2098763, 2097666, 2097483, 2097955, 2096969,
                2098128, 2098674, 2094993, 2095928, 2097085, 2097514, 2096962, 2096126, 2096360,
                2096300, 2099103, 2096516, 2095153, 2098016, 2096619, 2098537, 2096178, 2098055,
                2095243, 2096776, 2097125, 2095267, 2095813, 2099234, 2096870, 2097380, 2097479,
                2096007, 2098317, 2096240, 2095310, 2096794, 2096222, 2097211, 2097524, 2098923,
                2098405, 2097519, 2096432, 2097530, 2098122, 2097679, 2098085, 2096934, 2096931,
                2101893, 2099489, 2098247, 2098525, 2099439, 2098193, 2097093, 2096625, 2094667,
                2097532, 2096190, 2097809, 2097789,
            ],
            [
                2094492, 2098825, 2099669, 2092375, 2095579, 2096424, 2097201, 2092659, 2097087,
                2094414, 2095033, 2097134, 2094483, 2093402, 2093782, 2094560, 2097117, 2096769,
                2094900, 2096275, 2096256, 2096498, 2093992, 2096077, 2095992, 2097187, 2093963,
                2095794, 2098143, 2095765, 2095869, 2094896, 2098081, 2094982, 2096843, 2094402,
                2097318, 2098356, 2094146, 2095642, 2096202, 2096732, 2099597, 2095522, 2094273,
                2095673, 2097059, 2097062, 2098304, 2095926, 2094175, 2096623, 2096415, 2095711,
                2097867, 2096628, 2095410, 2098543, 2095629, 2097173, 2095613, 2094399, 2099160,
                2097502, 2095888, 2095131, 2095525, 2094742, 2110371, 2096284, 2097668, 2097157,
                2095583, 2094899, 2091653, 2096239, 2098045, 2096314, 2096741, 2108629, 2094317,
                2094161, 2093988, 2093153, 2096193, 2093247, 2094067, 2095034, 2096284, 2094220,
                2095388, 2094662, 2094036, 2094097, 2096084, 2094384, 2095703, 2093064, 2096670,
                2095754, 2095519, 2095880, 2093280, 2094534, 2098130, 2095994, 2097100, 2096078,
                2094308, 2095319, 2093184, 2097715, 2098402, 2093945, 2097151, 2095261, 2095233,
                2095197, 2096046, 2096401, 2097695, 2095582, 2093868, 2096626, 2095702, 2093894,
                2097442, 2096319, 2099748, 2098849, 2099398, 2094821, 2097278, 2098618, 2097368,
                2096700, 2099101, 2096985, 2096565, 2095776, 2098491, 2099441, 2101365, 2098416,
                2097901, 2099105, 2100978, 2100443, 2099321, 2100829, 2096948, 2098597, 2099888,
                2100092, 2097179, 2100776, 2099566, 2097547, 2098235, 2096567, 2099332, 2097683,
                2100191, 2100746, 2099637, 2099929, 2097895, 2101944, 2102055, 2100159, 2100879,
                2102131, 2097594, 2100980, 2099826, 2099304, 2097208, 2099740, 2099443, 2099537,
                2101067, 2101713, 2100478, 2097602, 2100439, 2099731, 2101304, 2100815, 2099462,
                2097758, 2098721, 2099805, 2097394, 2094173, 2098319, 2095061, 2096602, 2094940,
                2098495, 2096902, 2096343, 2097067, 2093921, 2096762, 2098724, 2096578, 2096570,
                2095834, 2092903, 2095466, 2097983, 2098229, 2097820, 2094963, 2098128, 2096230,
                2095159, 2098326, 2097156, 2097125, 2097896, 2098072, 2095322, 2099125, 2096744,
                2098574, 2098620, 2100366, 2099692, 2096125, 2095879, 2098031, 2096264, 2099699,
                2097347, 2098465, 2097976, 2097259, 2100491, 2096772, 2098833, 2098176, 2096405,
                2097142, 2101146, 2098933, 2097941, 2098116, 2100774, 2098233, 2101100, 2097784,
                2099936, 2098304, 2096863, 2094574,
            ],
            [
                2095352, 2098730, 2096902, 2096128, 2094628, 2096115, 2097465, 2093652, 2094433,
                2097612, 2096422, 2096191, 2094053, 2094731, 2093453, 2095655, 2094749, 2100799,
                2094722, 2091457, 2094235, 2097179, 2094948, 2096518, 2095242, 2096560, 2093845,
                2095923, 2094950, 2096125, 2096300, 2096686, 2107460, 2095802, 2097899, 2096506,
                2095064, 2096354, 2096571, 2095835, 2094871, 2094859, 2096754, 2095513, 2107998,
                2092218, 2095697, 2093339, 2098589, 2095388, 2093984, 2096144, 2093761, 2095730,
                2093169, 2091284, 2095566, 2094824, 2096354, 2096657, 2094004, 2095417, 2092127,
                2093475, 2098005, 2098560, 2096279, 2097727, 2097386, 2097756, 2096160, 2094279,
                2094603, 2097752, 2095154, 2098080, 2096712, 2096851, 2095926, 2099209, 2096578,
                2095069, 2097462, 2095802, 2096502, 2098471, 2096171, 2096114, 2097047, 2092414,
                2096083, 2094616, 2098374, 2096297, 2096046, 2097782, 2095061, 2095249, 2097294,
                2094093, 2095510, 2095500, 2091893, 2095308, 2095565, 2094913, 2095039, 2093546,
                2095104, 2096472, 2096863, 2094703, 2096616, 2095591, 2094410, 2095284, 2095653,
                2096374, 2096395, 2096383, 2095053, 2094827, 2097343, 2095203, 2094610, 2095451,
                2094450, 2097681, 2097066, 2097214, 2096729, 2094192, 2098016, 2099490, 2095267,
                2097589, 2098814, 2097402, 2096926, 2098922, 2096054, 2099154, 2099108, 2094689,
                2098945, 2098443, 2098513, 2098375, 2098298, 2098529, 2099566, 2097573, 2098028,
                2098238, 2095951, 2100180, 2095418, 2101723, 2101020, 2096722, 2097171, 2096727,
                2097537, 2096486, 2096231, 2095985, 2095763, 2097387, 2095563, 2097076, 2096956,
                2097406, 2097856, 2096595, 2096950, 2099217, 2096625, 2097805, 2095854, 2094609,
                2097260, 2098376, 2098663, 2095461, 2098734, 2099244, 2097218, 2095575, 2097011,
                2096935, 2098506, 2095027, 2099235, 2100171, 2097508, 2097637, 2098826, 2098577,
                2097837, 2098875, 2099951, 2102338, 2099580, 2101233, 2099173, 2099847, 2100940,
                2098187, 2096527, 2099878, 2101325, 2100151, 2101335, 2100067, 2099096, 2099977,
                2101560, 2100493, 2097365, 2102928, 2104725, 2101004, 2102710, 2099887, 2096042,
                2096427, 2098488, 2098900, 2097794, 2099955, 2099830, 2098092, 2101150, 2097611,
                2100029, 2097532, 2096629, 2095941, 2097453, 2100422, 2099968, 2099207, 2099604,
                2101741, 2099938, 2098594, 2099097, 2097643, 2099234, 2100106, 2100598, 2099168,
                2097642, 2098791, 2098031, 2098672,
            ],
            [
                2094979, 2094220, 2095052, 2097476, 2096775, 2094425, 2099347, 2097549, 2098026,
                2096673, 2094399, 2093574, 2096783, 2095350, 2095742, 2096892, 2095991, 2094820,
                2098472, 2095557, 2100349, 2096980, 2094729, 2097611, 2093780, 2095257, 2094233,
                2096508, 2098520, 2095390, 2095443, 2098863, 2097523, 2095834, 2096091, 2095556,
                2098582, 2095433, 2096127, 2099863, 2095961, 2096172, 2096295, 2096300, 2094445,
                2095834, 2096183, 2095573, 2097643, 2096302, 2094852, 2096501, 2095232, 2094175,
                2093887, 2094329, 2098845, 2095814, 2095672, 2101713, 2097899, 2097583, 2092630,
                2095603, 2097877, 2097843, 2098940, 2100813, 2109251, 2098617, 2093714, 2096366,
                2094322, 2109105, 2096647, 2094267, 2096618, 2095735, 2095378, 2097039, 2096262,
                2095741, 2094438, 2094306, 2094656, 2093650, 2091787, 2094470, 2095520, 2094305,
                2094074, 2096443, 2094649, 2096448, 2095695, 2095243, 2096264, 2095377, 2096493,
                2095160, 2094964, 2094512, 2095408, 2096767, 2093663, 2096457, 2095639, 2096364,
                2094683, 2094383, 2094492, 2096473, 2097502, 2096574, 2094907, 2096861, 2096648,
                2097825, 2094493, 2094229, 2093909, 2096875, 2095926, 2095129, 2093311, 2095763,
                2094801, 2095890, 2097931, 2099052, 2100897, 2099381, 2098405, 2096405, 2098433,
                2096625, 2099118, 2096923, 2097146, 2099488, 2096142, 2098265, 2096332, 2098372,
                2100785, 2098677, 2095531, 2100339, 2098182, 2099390, 2097669, 2098111, 2098332,
                2100685, 2101009, 2099470, 2100039, 2100825, 2098658, 2098999, 2101023, 2098678,
                2101041, 2098121, 2100550, 2099848, 2096921, 2099572, 2099104, 2099718, 2100289,
                2099779, 2099175, 2098127, 2098686, 2098242, 2098059, 2104230, 2101155, 2100317,
                2100256, 2098956, 2096211, 2102604, 2096843, 2101234, 2096606, 2100943, 2098790,
                2100140, 2099067, 2102048, 2098217, 2097564, 2096650, 2096301, 2097637, 2095472,
                2097310, 2097614, 2098771, 2094305, 2096814, 2097660, 2097289, 2095068, 2096813,
                2098364, 2097124, 2097796, 2099606, 2097901, 2095637, 2095116, 2097037, 2096261,
                2096938, 2098579, 2096700, 2097837, 2095923, 2098351, 2096585, 2095052, 2096441,
                2095366, 2098165, 2095557, 2098212, 2095937, 2097982, 2096454, 2099608, 2096293,
                2097111, 2094863, 2097715, 2097768, 2098845, 2097271, 2097250, 2100666, 2096046,
                2099716, 2098502, 2097175, 2099484, 2097202, 2097464, 2096502, 2095775, 2099139,
                2097870, 2097176, 2096199, 2096739,
            ],
            [
                2094785, 2095884, 2095433, 2094959, 2095473, 2098493, 2096435, 2094958, 2096144,
                2095702, 2094967, 2096642, 2094592, 2096089, 2097290, 2096575, 2096737, 2095958,
                2096836, 2093675, 2095280, 2097498, 2096543, 2094587, 2093568, 2095403, 2096541,
                2094115, 2095638, 2094271, 2095975, 2097801, 2097092, 2095786, 2096287, 2099223,
                2098100, 2096228, 2096354, 2094089, 2098137, 2097384, 2094386, 2096439, 2096120,
                2096755, 2095255, 2095966, 2099018, 2097274, 2092164, 2092957, 2098291, 2095517,
                2095349, 2096102, 2098619, 2095465, 2095875, 2097463, 2097689, 2096370, 2098775,
                2097397, 2097091, 2093775, 2097164, 2095428, 2094862, 2094574, 2091267, 2095244,
                2094040, 2094580, 2096818, 2094108, 2096536, 2096124, 2097506, 2096587, 2093475,
                2099552, 2109223, 2095761, 2099690, 2096925, 2095832, 2096271, 2095281, 2094475,
                2094742, 2099601, 2109306, 2093005, 2095724, 2092564, 2095411, 2094307, 2095530,
                2097342, 2097261, 2093775, 2095297, 2095855, 2097141, 2095625, 2095806, 2095731,
                2095976, 2094978, 2097928, 2096560, 2094148, 2095120, 2095779, 2094220, 2092854,
                2095309, 2097882, 2096959, 2097401, 2095338, 2098371, 2095410, 2097966, 2095220,
                2095849, 2096799, 2099802, 2099140, 2098136, 2096444, 2096872, 2099467, 2097464,
                2098204, 2097527, 2098741, 2101744, 2097810, 2097788, 2098680, 2095956, 2100917,
                2098134, 2097958, 2098058, 2096802, 2099979, 2100490, 2097232, 2096367, 2097802,
                2100502, 2097745, 2098360, 2098009, 2101143, 2096888, 2098871, 2099169, 2100249,
                2097791, 2100946, 2100729, 2098982, 2100995, 2099817, 2100965, 2099144, 2099734,
                2099236, 2099205, 2099729, 2100032, 2097983, 2097885, 2099131, 2100228, 2097420,
                2097566, 2099647, 2102853, 2101092, 2099295, 2101999, 2098320, 2099679, 2101311,
                2099190, 2099756, 2098584, 2096893, 2098913, 2096173, 2097335, 2099071, 2095519,
                2095677, 2096934, 2095705, 2098237, 2098204, 2096338, 2098515, 2095691, 2094188,
                2098808, 2099865, 2095335, 2095880, 2097316, 2096931, 2095622, 2095258, 2099975,
                2096272, 2093207, 2095360, 2097949, 2095341, 2098984, 2096309, 2096821, 2099240,
                2096108, 2098445, 2098299, 2097667, 2095775, 2097896, 2098875, 2101162, 2095807,
                2098450, 2094635, 2096212, 2098934, 2100709, 2099049, 2095210, 2097992, 2098479,
                2097530, 2096359, 2096404, 2096248, 2096279, 2095530, 2095930, 2099537, 2096407,
                2098555, 2099426, 2098721, 2099670,
            ],
            [
                2098326, 2093293, 2092595, 2095545, 2095293, 2096053, 2095381, 2096513, 2095647,
                2093119, 2095407, 2094657, 2097131, 2096367, 2096831, 2097844, 2096005, 2096189,
                2095160, 2096837, 2094435, 2097662, 2097303, 2097351, 2094690, 2095506, 2097238,
                2097273, 2095704, 2096029, 2098081, 2097692, 2097461, 2098618, 2095659, 2097320,
                2094921, 2096580, 2094943, 2094251, 2095244, 2093701, 2092141, 2097393, 2098024,
                2096438, 2094768, 2097082, 2095301, 2094281, 2095637, 2096257, 2096651, 2097001,
                2097521, 2096579, 2099844, 2094731, 2097993, 2096919, 2097241, 2096280, 2095058,
                2096106, 2096092, 2096466, 2095254, 2094751, 2097852, 2095235, 2107190, 2095197,
                2096585, 2104340, 2096350, 2096277, 2093071, 2097485, 2094748, 2096517, 2096243,
                2096798, 2094411, 2095548, 2093261, 2096415, 2096418, 2095017, 2092989, 2094679,
                2094632, 2096374, 2093830, 2095731, 2095974, 2093847, 2091975, 2092931, 2094672,
                2097851, 2094771, 2096234, 2094565, 2093366, 2094676, 2095137, 2095283, 2095059,
                2095120, 2097223, 2093500, 2093020, 2096416, 2093936, 2095664, 2095064, 2098176,
                2094505, 2093820, 2096522, 2095517, 2096528, 2094989, 2095346, 2097463, 2093911,
                2095509, 2094934, 2099633, 2098651, 2098661, 2099257, 2098753, 2098586, 2099077,
                2100399, 2098176, 2098920, 2098786, 2100226, 2099804, 2097883, 2099811, 2099638,
                2098613, 2100170, 2099065, 2098065, 2098470, 2097680, 2099158, 2098159, 2099502,
                2099737, 2100871, 2097404, 2100168, 2099896, 2099646, 2098416, 2098628, 2099110,
                2100318, 2097467, 2101618, 2100038, 2098236, 2100545, 2098421, 2100788, 2096460,
                2099674, 2100217, 2100733, 2099969, 2101360, 2098984, 2100526, 2099193, 2099537,
                2100544, 2099409, 2101213, 2101566, 2100409, 2098668, 2101704, 2099467, 2101386,
                2102126, 2099130, 2097752, 2096467, 2096492, 2096904, 2097926, 2097040, 2097216,
                2097351, 2097942, 2093151, 2096433, 2096736, 2097088, 2098780, 2097801, 2096901,
                2097305, 2098727, 2098984, 2096009, 2098409, 2095100, 2097012, 2096119, 2099682,
                2096474, 2097936, 2096715, 2097892, 2098479, 2098068, 2097461, 2095706, 2097715,
                2097226, 2098005, 2099578, 2095002, 2097476, 2098820, 2097499, 2096851, 2096952,
                2099739, 2097772, 2097893, 2097675, 2096420, 2096491, 2098401, 2100530, 2096922,
                2098510, 2096236, 2096381, 2097068, 2099024, 2098732, 2098708, 2096687, 2095491,
                2098163, 2095356, 2098716, 2097729,
            ],
            [
                2095126, 2095049, 2095464, 2095585, 2094081, 2095092, 2094495, 2097540, 2096704,
                2095239, 2092357, 2096079, 2095408, 2097419, 2093449, 2096000, 2093990, 2096708,
                2095148, 2099069, 2095382, 2099010, 2095297, 2094367, 2095129, 2095440, 2096086,
                2093350, 2097969, 2094287, 2094629, 2095830, 2095499, 2094623, 2098132, 2097034,
                2096767, 2094138, 2095485, 2097060, 2093995, 2095306, 2094603, 2095365, 2095368,
                2094372, 2094800, 2093553, 2098243, 2094604, 2097903, 2094747, 2098159, 2094980,
                2095053, 2095370, 2097048, 2095313, 2097412, 2096890, 2093265, 2099943, 2098842,
                2094988, 2095822, 2095337, 2094551, 2096970, 2096857, 2098094, 2098107, 2099879,
                2094808, 2096071, 2095141, 2097931, 2095202, 2094851, 2107864, 2099359, 2095353,
                2094844, 2092546, 2098096, 2093764, 2094441, 2094073, 2095721, 2095438, 2095337,
                2094759, 2094788, 2091992, 2093967, 2105119, 2092683, 2096244, 2094925, 2096217,
                2093240, 2094379, 2095643, 2096807, 2096264, 2095738, 2094043, 2094379, 2096562,
                2095641, 2095923, 2096271, 2094100, 2094341, 2098440, 2098481, 2093705, 2095835,
                2095758, 2095801, 2094434, 2093813, 2096148, 2095078, 2095795, 2096432, 2094804,
                2092688, 2095032, 2098497, 2100365, 2095437, 2098890, 2100156, 2100382, 2098177,
                2093485, 2096888, 2097395, 2099675, 2100424, 2095581, 2098555, 2097618, 2096334,
                2096226, 2100777, 2100532, 2095334, 2097616, 2100604, 2099237, 2097883, 2098227,
                2101335, 2099120, 2098525, 2099472, 2097193, 2097844, 2094615, 2100385, 2100996,
                2096524, 2100892, 2096644, 2097848, 2100802, 2101524, 2096876, 2099567, 2099115,
                2096554, 2099338, 2098807, 2098032, 2098857, 2099818, 2101034, 2104523, 2100165,
                2101825, 2099961, 2100674, 2100655, 2101570, 2099096, 2098059, 2099763, 2101219,
                2101423, 2173121, 2100718, 2097996, 2094518, 2096095, 2098201, 2096891, 2097761,
                2095721, 2094884, 2094547, 2096392, 2095523, 2097028, 2096072, 2096004, 2096107,
                2094475, 2095690, 2095480, 2096813, 2098035, 2095854, 2097307, 2098216, 2095150,
                2096727, 2097686, 2096697, 2099426, 2097267, 2096345, 2096364, 2097830, 2097169,
                2097305, 2097429, 2096280, 2098839, 2098499, 2098806, 2095715, 2096651, 2099975,
                2096280, 2094932, 2095340, 2097936, 2096809, 2096329, 2096551, 2098452, 2097864,
                2096279, 2095919, 2097783, 2099584, 2097985, 2097419, 2097334, 2096387, 2096868,
                2096017, 2100899, 2096569, 2098458,
            ],
            [
                2096267, 2094709, 2094153, 2095935, 2095152, 2096269, 2096226, 2096220, 2095241,
                2096558, 2095419, 2096158, 2094053, 2095360, 2097045, 2095748, 2096915, 2098096,
                2095272, 2097313, 2095561, 2096753, 2095477, 2094012, 2096847, 2095550, 2096851,
                2097247, 2096272, 2096114, 2097039, 2094781, 2096168, 2095497, 2096010, 2098035,
                2093351, 2094655, 2091496, 2095327, 2096034, 2093764, 2098153, 2095482, 2096204,
                2099194, 2098014, 2095332, 2097428, 2095651, 2095971, 2098796, 2098825, 2097192,
                2094480, 2098324, 2095727, 2095960, 2098497, 2094722, 2095604, 2097879, 2097418,
                2096737, 2096158, 2093925, 2098627, 2095753, 2095972, 2098574, 2095378, 2098186,
                2093367, 2097015, 2096648, 2106088, 2093056, 2096665, 2094134, 2096235, 2096887,
                2095318, 2096860, 2098044, 2097331, 2094006, 2094575, 2093198, 2097566, 2094193,
                2108112, 2095078, 2096354, 2096477, 2094289, 2094998, 2095062, 2096358, 2096162,
                2095210, 2096685, 2095271, 2093854, 2090995, 2096778, 2098176, 2094200, 2095894,
                2093480, 2095541, 2095913, 2094517, 2095824, 2093010, 2095593, 2095358, 2096360,
                2100333, 2095174, 2096656, 2095585, 2096673, 2098447, 2095173, 2095844, 2097697,
                2096188, 2094106, 2098060, 2098545, 2099489, 2097756, 2098886, 2099578, 2097672,
                2100183, 2097564, 2098199, 2097814, 2094826, 2098108, 2096915, 2100596, 2097211,
                2099164, 2097777, 2098239, 2095469, 2098695, 2097257, 2099847, 2099039, 2097597,
                2098632, 2099584, 2098929, 2099136, 2099111, 2098289, 2097599, 2100044, 2098790,
                2098987, 2101027, 2099586, 2099732, 2102663, 2098123, 2099241, 2099813, 2099738,
                2100068, 2099193, 2099341, 2097991, 2101096, 2102230, 2100401, 2101707, 2099779,
                2099799, 2100892, 2100837, 2099598, 2098415, 2100229, 2099710, 2098694, 2099047,
                2099847, 2101278, 2101103, 2097305, 2098731, 2096687, 2095855, 2096662, 2097323,
                2097461, 2096330, 2097334, 2099285, 2095913, 2097215, 2094722, 2095033, 2097131,
                2097397, 2097440, 2099452, 2095601, 2097257, 2098363, 2098456, 2098853, 2099444,
                2094448, 2097534, 2098543, 2095307, 2096197, 2097082, 2097475, 2095010, 2097252,
                2098155, 2097321, 2096634, 2095122, 2099490, 2097373, 2097771, 2098627, 2096795,
                2095956, 2096834, 2096980, 2095542, 2097364, 2095724, 2095782, 2099305, 2097853,
                2097193, 2101610, 2099193, 2098235, 2098756, 2097546, 2094744, 2097538, 2097120,
                2096745, 2098090, 2096482, 2096445,
            ],
            [
                2096664, 2094300, 2098709, 2094882, 2093313, 2095488, 2095151, 2097878, 2096700,
                2096200, 2094208, 2094719, 2093662, 2097146, 2096180, 2093348, 2095304, 2096926,
                2097015, 2092647, 2093153, 2095090, 2096131, 2095654, 2097525, 2094992, 2094916,
                2095913, 2095876, 2093221, 2095106, 2093616, 2107505, 2094987, 2095964, 2096225,
                2096263, 2094369, 2097142, 2100560, 2096011, 2093777, 2093552, 2096583, 2098904,
                2096435, 2094912, 2096386, 2099699, 2095008, 2109223, 2096094, 2095488, 2095583,
                2098252, 2095130, 2097364, 2092885, 2093147, 2095879, 2095610, 2094340, 2096971,
                2095552, 2096159, 2097730, 2097545, 2094416, 2096905, 2094586, 2096658, 2094938,
                2099916, 2097028, 2096911, 2097039, 2097587, 2096595, 2095708, 2092744, 2096740,
                2096015, 2097396, 2094776, 2095535, 2095296, 2095631, 2095433, 2094377, 2096152,
                2097048, 2096110, 2094374, 2096866, 2100148, 2096912, 2096344, 2095058, 2093602,
                2094647, 2097698, 2094154, 2097413, 2096046, 2096976, 2097408, 2094740, 2097011,
                2094040, 2095096, 2097558, 2096265, 2097069, 2096874, 2094770, 2096795, 2097485,
                2093745, 2094646, 2096790, 2097173, 2097551, 2095272, 2096392, 2098623, 2096398,
                2095241, 2095091, 2096152, 2099389, 2097652, 2099005, 2097394, 2096041, 2096191,
                2096035, 2098395, 2096649, 2098217, 2096741, 2098797, 2097599, 2097264, 2096086,
                2096824, 2098221, 2098321, 2097879, 2099185, 2100482, 2098953, 2097117, 2097387,
                2097902, 2096149, 2095832, 2099082, 2098981, 2099514, 2099437, 2095128, 2096085,
                2095608, 2098870, 2096971, 2096350, 2096784, 2096149, 2098619, 2097257, 2098206,
                2096693, 2097500, 2095601, 2096410, 2095083, 2098087, 2096897, 2096597, 2098117,
                2099435, 2094599, 2096556, 2097381, 2095156, 2095870, 2096199, 2098432, 2098942,
                2099456, 2098234, 2097045, 2099147, 2099916, 2099819, 2099087, 2097510, 2099479,
                2096002, 2100620, 2102075, 2098840, 2100903, 2096999, 2099749, 2101194, 2098961,
                2101577, 2100241, 2101417, 2100737, 2101109, 2098426, 2100216, 2100200, 2099217,
                2100900, 2098465, 2100239, 2098526, 2101725, 2100963, 2102604, 2097478, 2098797,
                2098538, 2100814, 2095777, 2098203, 2095141, 2099396, 2097197, 2097538, 2098847,
                2098286, 2098901, 2099729, 2097548, 2098533, 2095730, 2099391, 2095498, 2100530,
                2094532, 2098561, 2100713, 2099236, 2096877, 2098694, 2100546, 2098233, 2097826,
                2097751, 2096162, 2098842, 2098336,
            ],
            [
                2096605, 2096802, 2096166, 2097003, 2095397, 2097868, 2095365, 2095420, 2097956,
                2096528, 2096040, 2096541, 2093146, 2098318, 2092631, 2096705, 2095734, 2094986,
                2093908, 2096902, 2097447, 2093552, 2094198, 2096745, 2093416, 2095653, 2093584,
                2095355, 2095532, 2095112, 2094942, 2095533, 2096521, 2098984, 2096707, 2098069,
                2092751, 2096991, 2094716, 2094708, 2094485, 2096312, 2095894, 2095340, 2097073,
                2097058, 2096507, 2097908, 2095133, 2098209, 2098081, 2096928, 2093848, 2095405,
                2094949, 2096315, 2096806, 2093595, 2098741, 2096603, 2096315, 2096284, 2098150,
                2094491, 2093755, 2098468, 2094958, 2094297, 2095796, 2096230, 2096405, 2096995,
                2099550, 2094522, 2104778, 2096884, 2097273, 2094828, 2093920, 2095792, 2098697,
                2095662, 2094642, 2098191, 2096144, 2094810, 2096221, 2097117, 2096965, 2105141,
                2095400, 2096266, 2097099, 2096564, 2099259, 2094698, 2093380, 2093773, 2094970,
                2094418, 2094831, 2094069, 2096272, 2098076, 2094530, 2096366, 2094527, 2095822,
                2094779, 2095430, 2097145, 2092954, 2095884, 2096219, 2096353, 2092687, 2094586,
                2094629, 2096907, 2096017, 2095963, 2096776, 2096039, 2093504, 2094531, 2095696,
                2096327, 2096302, 2097879, 2097641, 2099146, 2100064, 2099564, 2098643, 2096931,
                2100988, 2096071, 2099980, 2098267, 2096794, 2097258, 2096930, 2100322, 2098991,
                2096937, 2097177, 2099344, 2097769, 2100148, 2101548, 2098727, 2101010, 2098425,
                2099456, 2096768, 2098188, 2101494, 2097667, 2096410, 2098782, 2101130, 2102925,
                2098577, 2100475, 2101544, 2099140, 2102876, 2100772, 2100236, 2100763, 2099694,
                2099432, 2101594, 2101164, 2099401, 2099557, 2101402, 2101021, 2101434, 2100632,
                2100718, 2095650, 2099595, 2100600, 2100070, 2099415, 2101059, 2099427, 2099255,
                2099951, 2099121, 2100933, 2098125, 2097258, 2096294, 2096919, 2096735, 2098132,
                2096071, 2100993, 2097953, 2097657, 2096579, 2096932, 2095253, 2096421, 2096404,
                2098450, 2094545, 2096346, 2099602, 2096751, 2095744, 2094381, 2096768, 2097169,
                2099284, 2098028, 2093694, 2096907, 2094913, 2097569, 2095857, 2099708, 2096608,
                2097638, 2096868, 2096783, 2098817, 2097004, 2099932, 2097243, 2098576, 2096275,
                2095883, 2096167, 2094852, 2097112, 2098125, 2098360, 2096606, 2097457, 2097374,
                2096366, 2095875, 2093246, 2098319, 2099259, 2096812, 2100342, 2096555, 2097319,
                2095907, 2097239, 2098973, 2100640,
            ],
            [
                2094289, 2095219, 2096047, 2095409, 2094719, 2096312, 2096223, 2095832, 2098226,
                2094130, 2095320, 2095282, 2096226, 2093603, 2095479, 2095777, 2096670, 2097439,
                2096888, 2096437, 2096423, 2096399, 2094137, 2095830, 2097331, 2098418, 2097732,
                2096162, 2094600, 2097160, 2096392, 2096559, 2096192, 2097090, 2097979, 2097727,
                2096069, 2095263, 2095996, 2097489, 2098357, 2097712, 2096536, 2095398, 2096465,
                2098023, 2095791, 2099732, 2093237, 2093048, 2096313, 2095443, 2097490, 2099053,
                2095598, 2096012, 2096474, 2097367, 2095488, 2097021, 2096182, 2098030, 2097432,
                2097530, 2096673, 2097211, 2096812, 2096508, 2095521, 2094966, 2095787, 2096399,
                2096151, 2097702, 2095039, 2098321, 2093575, 2096087, 2095578, 2107859, 2095456,
                2096072, 2094290, 2095820, 2091792, 2096093, 2092721, 2094278, 2095453, 2096061,
                2096419, 2106419, 2096963, 2098937, 2098208, 2097202, 2094862, 2094354, 2093947,
                2096631, 2096483, 2093246, 2094689, 2096852, 2095194, 2093536, 2093971, 2096706,
                2093106, 2093871, 2095955, 2095318, 2095335, 2095611, 2096260, 2095779, 2092086,
                2093027, 2094074, 2096114, 2095882, 2098487, 2091624, 2095972, 2092412, 2096913,
                2095522, 2096377, 2097677, 2095742, 2097751, 2097790, 2096820, 2097145, 2097478,
                2098356, 2098158, 2097026, 2098599, 2097725, 2096169, 2097243, 2098830, 2095848,
                2100040, 2098444, 2098810, 2098477, 2097742, 2098760, 2099472, 2096227, 2098226,
                2100061, 2097577, 2097768, 2097479, 2097333, 2099435, 2098654, 2099274, 2101240,
                2099004, 2098257, 2100369, 2101420, 2100459, 2100329, 2100856, 2098715, 2098764,
                2098544, 2098634, 2101377, 2099810, 2098212, 2100303, 2101992, 2101217, 2100039,
                2097215, 2100630, 2101775, 2101958, 2100387, 2099207, 2102402, 2101094, 2098937,
                2100500, 2100517, 2099762, 2096238, 2097216, 2097572, 2098349, 2097136, 2095695,
                2096888, 2098261, 2095001, 2096553, 2096169, 2095175, 2098219, 2098942, 2097162,
                2097701, 2099386, 2093792, 2096494, 2095018, 2095573, 2097983, 2095973, 2097670,
                2097259, 2099443, 2096482, 2098390, 2098954, 2095468, 2097953, 2099046, 2096006,
                2095776, 2099439, 2098916, 2099806, 2097688, 2098657, 2096859, 2096068, 2097910,
                2097469, 2098776, 2097172, 2097388, 2099679, 2097668, 2098860, 2098245, 2097716,
                2098241, 2098206, 2096069, 2097047, 2096499, 2097954, 2098018, 2097869, 2096521,
                2097996, 2097396, 2098416, 2098584,
            ],
            [
                2099122, 2097247, 2093833, 2096862, 2094240, 2099335, 2096824, 2097487, 2094936,
                2096978, 2096587, 2096638, 2094399, 2096014, 2096464, 2095775, 2099426, 2097751,
                2095867, 2095748, 2096024, 2097819, 2095693, 2097180, 2093874, 2099338, 2097555,
                2094758, 2097828, 2095266, 2094947, 2094726, 2094880, 2097214, 2095405, 2095472,
                2097519, 2097752, 2095433, 2096980, 2096002, 2099708, 2095460, 2097494, 2097785,
                2099121, 2093264, 2096038, 2097835, 2095765, 2094667, 2096659, 2094880, 2095086,
                2095420, 2097002, 2097678, 2097259, 2095109, 2094729, 2094886, 2095353, 2096320,
                2095551, 2106704, 2096248, 2095899, 2093076, 2095173, 2097296, 2094758, 2096808,
                2096593, 2095258, 2098114, 2096926, 2096178, 2095063, 2094477, 2095220, 2095822,
                2096781, 2096369, 2097278, 2095304, 2105547, 2095852, 2095307, 2096588, 2097770,
                2095146, 2095403, 2095727, 2095366, 2095360, 2094961, 2095774, 2097903, 2097836,
                2093534, 2096813, 2096271, 2095348, 2093758, 2093722, 2096695, 2094299, 2096295,
                2096305, 2095753, 2095284, 2094879, 2094850, 2095297, 2094975, 2091885, 2093365,
                2093693, 2096536, 2095116, 2093316, 2095145, 2095792, 2094220, 2095708, 2095512,
                2094740, 2094553, 2098223, 2099329, 2097909, 2100407, 2099966, 2100184, 2100337,
                2096934, 2098762, 2097260, 2097882, 2101455, 2098500, 2098847, 2098229, 2099828,
                2096766, 2098043, 2098003, 2098929, 2100773, 2100197, 2096901, 2098753, 2099054,
                2099020, 2099758, 2098519, 2098135, 2098019, 2097489, 2099749, 2099733, 2102206,
                2100212, 2099472, 2098628, 2101325, 2099974, 2098610, 2098578, 2100467, 2099298,
                2098818, 2096846, 2101068, 2098574, 2099989, 2098440, 2100464, 2100064, 2101218,
                2099061, 2100106, 2099266, 2097436, 2098228, 2098649, 2098833, 2098317, 2101579,
                2099872, 2100413, 2100447, 2097390, 2094397, 2096686, 2098103, 2097309, 2095919,
                2097358, 2097121, 2097308, 2099128, 2098485, 2096560, 2096309, 2097247, 2098978,
                2097774, 2093317, 2096697, 2095205, 2097336, 2096885, 2096885, 2096197, 2094300,
                2098862, 2097517, 2095303, 2094956, 2096302, 2094493, 2096110, 2096442, 2098415,
                2097685, 2097711, 2097365, 2098761, 2097950, 2096551, 2094989, 2099491, 2099082,
                2097966, 2097379, 2098709, 2095910, 2098413, 2098105, 2098124, 2096756, 2096887,
                2097965, 2098922, 2099679, 2095915, 2098600, 2098619, 2096867, 2098424, 2097726,
                2099607, 2097376, 2095453, 2098469,
            ],
            [
                2096425, 2094007, 2098276, 2094745, 2095333, 2095969, 2096409, 2096259, 2096152,
                2097438, 2096301, 2096291, 2093693, 2096166, 2096464, 2095383, 2094990, 2099947,
                2094753, 2096254, 2095450, 2096320, 2096386, 2095196, 2096459, 2094514, 2092260,
                2095171, 2096138, 2096963, 2097825, 2094656, 2096441, 2097350, 2096289, 2096988,
                2096322, 2099597, 2096638, 2095151, 2097340, 2098126, 2097349, 2098584, 2095617,
                2098897, 2098003, 2095991, 2093853, 2095871, 2096647, 2096290, 2093920, 2097913,
                2098237, 2098269, 2096023, 2096515, 2095201, 2095913, 2096780, 2095307, 2097877,
                2095886, 2097256, 2096777, 2097112, 2093865, 2110203, 2094591, 2095024, 2096310,
                2093397, 2096873, 2092694, 2094678, 2095623, 2095072, 2095036, 2095186, 2096359,
                2096312, 2105287, 2095321, 2094304, 2094617, 2095043, 2095636, 2094528, 2094947,
                2098013, 2098283, 2096800, 2097055, 2097566, 2097756, 2096671, 2093644, 2094278,
                2094612, 2094554, 2096042, 2096151, 2095813, 2094736, 2094047, 2095243, 2097403,
                2093437, 2096076, 2095522, 2095147, 2096704, 2093091, 2093774, 2095807, 2096456,
                2095943, 2094345, 2093721, 2095164, 2096009, 2095640, 2094455, 2094888, 2097502,
                2096074, 2096751, 2098158, 2098880, 2100852, 2096041, 2100431, 2100000, 2099792,
                2099947, 2099959, 2098813, 2098930, 2097463, 2099410, 2098577, 2098817, 2100939,
                2097468, 2098969, 2097340, 2096494, 2097299, 2096287, 2096823, 2098261, 2100698,
                2098086, 2097167, 2099680, 2100695, 2100775, 2095868, 2097409, 2101182, 2100038,
                2097339, 2099731, 2101934, 2101603, 2099639, 2097319, 2100124, 2099109, 2099784,
                2100618, 2099266, 2103555, 2100069, 2100282, 2100255, 2100196, 2097144, 2099219,
                2098701, 2099638, 2097263, 2097942, 2098455, 2099245, 2099390, 2098304, 2099301,
                2099735, 2102810, 2100684, 2099523, 2097620, 2094809, 2095031, 2098025, 2097043,
                2096841, 2093863, 2095686, 2097534, 2096429, 2095894, 2098594, 2097797, 2096800,
                2095937, 2094897, 2095731, 2097824, 2099181, 2097020, 2098019, 2098255, 2099701,
                2097724, 2097900, 2095937, 2098029, 2095565, 2097941, 2096488, 2094678, 2097105,
                2096676, 2093618, 2097704, 2100026, 2097132, 2098494, 2098120, 2096775, 2100215,
                2097294, 2097570, 2096251, 2096830, 2097051, 2098134, 2095672, 2097220, 2098384,
                2098697, 2096937, 2096505, 2098376, 2097151, 2099522, 2097779, 2096727, 2096971,
                2096112, 2097266, 2098750, 2100328,
            ],
            [
                2097150, 2095395, 2095799, 2093613, 2094374, 2094448, 2091365, 2094799, 2094733,
                2092819, 2095352, 2096398, 2095838, 2095193, 2094086, 2094754, 2097076, 2095616,
                2095851, 2094372, 2095474, 2092943, 2095755, 2096395, 2096047, 2099005, 2096185,
                2093990, 2095569, 2094371, 2094546, 2093329, 2106342, 2097932, 2095862, 2096913,
                2100301, 2098822, 2094856, 2095608, 2093122, 2094522, 2092817, 2098771, 2095952,
                2097260, 2095843, 2096607, 2095249, 2096650, 2096617, 2095744, 2095980, 2096414,
                2098384, 2108198, 2095515, 2097440, 2095986, 2096441, 2093916, 2096521, 2095129,
                2095934, 2096073, 2096698, 2096346, 2095233, 2096498, 2095936, 2096303, 2097142,
                2094257, 2096854, 2096856, 2095543, 2097805, 2094438, 2094554, 2097463, 2096366,
                2096577, 2097466, 2097288, 2094842, 2096679, 2093100, 2097862, 2096440, 2101408,
                2092814, 2095360, 2099372, 2095095, 2096832, 2095157, 2096828, 2095846, 2094722,
                2096807, 2095218, 2095820, 2095603, 2093485, 2093750, 2097842, 2096179, 2095333,
                2094847, 2095526, 2095189, 2095194, 2093955, 2096693, 2096965, 2096918, 2093598,
                2096041, 2095709, 2093791, 2094738, 2095392, 2095804, 2096910, 2097192, 2092887,
                2093308, 2095477, 2098289, 2097179, 2096614, 2097659, 2100344, 2098141, 2099406,
                2095404, 2099096, 2097327, 2098988, 2098229, 2098604, 2097962, 2096120, 2099801,
                2096499, 2100636, 2099975, 2098744, 2095955, 2096498, 2100540, 2097215, 2095352,
                2098514, 2095477, 2098519, 2099478, 2099727, 2100460, 2095803, 2099439, 2097269,
                2096026, 2096155, 2095094, 2097135, 2096572, 2098013, 2098396, 2097756, 2096086,
                2097497, 2097056, 2096692, 2098094, 2097019, 2097294, 2097698, 2099175, 2094510,
                2097869, 2096235, 2098035, 2099466, 2099198, 2098418, 2096184, 2097251, 2097477,
                2097394, 2098931, 2097058, 2095518, 2097015, 2100568, 2099035, 2100078, 2097619,
                2100145, 2097689, 2098686, 2097147, 2098475, 2098940, 2100185, 2100819, 2098341,
                2099896, 2100627, 2100209, 2100278, 2098863, 2101511, 2096884, 2099096, 2100966,
                2101365, 2098570, 2103050, 2100298, 2102517, 2100201, 2098343, 2099663, 2097047,
                2097267, 2098117, 2099793, 2096979, 2096180, 2097531, 2097460, 2100385, 2102122,
                2098241, 2102045, 2098272, 2095824, 2096679, 2096093, 2096930, 2099368, 2098074,
                2098178, 2098900, 2100050, 2100803, 2097106, 2100025, 2100260, 2098560, 2099806,
                2099874, 2099042, 2097536, 2100209,
            ],
            [
                2096622, 2095738, 2096695, 2096844, 2094809, 2096215, 2097198, 2096387, 2095186,
                2096546, 2097166, 2095159, 2097114, 2096629, 2094595, 2097134, 2094627, 2094936,
                2097444, 2095703, 2096328, 2097244, 2096040, 2095906, 2094498, 2097388, 2096722,
                2096685, 2093725, 2095100, 2095669, 2096047, 2097595, 2093983, 2096157, 2095956,
                2099383, 2097153, 2096408, 2095945, 2098749, 2095765, 2094845, 2095054, 2098034,
                2094943, 2096465, 2095497, 2096427, 2096873, 2096239, 2096599, 2096737, 2096851,
                2097108, 2096698, 2095458, 2098433, 2094063, 2092410, 2095432, 2095105, 2098777,
                2098029, 2095574, 2099982, 2094300, 2095812, 2093070, 2095911, 2096663, 2095940,
                2097311, 2097040, 2094861, 2095817, 2094659, 2094522, 2097114, 2109573, 2097028,
                2094845, 2096845, 2093768, 2094985, 2096674, 2091093, 2108784, 2095709, 2096607,
                2096125, 2095579, 2097549, 2097246, 2097008, 2096193, 2092228, 2091878, 2096114,
                2096173, 2095889, 2096202, 2097170, 2096002, 2093033, 2095804, 2097524, 2095480,
                2095386, 2094771, 2096634, 2094983, 2094771, 2094026, 2097135, 2095360, 2098283,
                2093974, 2095005, 2092948, 2095871, 2093772, 2095732, 2094572, 2094374, 2092348,
                2095303, 2095113, 2097915, 2098683, 2097936, 2101586, 2096631, 2099307, 2097547,
                2099447, 2100361, 2098720, 2098706, 2097184, 2098620, 2098846, 2095512, 2097767,
                2101393, 2097608, 2098354, 2098821, 2098417, 2096122, 2098914, 2099700, 2101021,
                2100266, 2098888, 2099932, 2096235, 2100644, 2099503, 2099371, 2102777, 2098063,
                2098857, 2103493, 2099733, 2098087, 2101325, 2098091, 2101083, 2098043, 2099804,
                2098741, 2100017, 2099757, 2097264, 2096539, 2100220, 2100503, 2099986, 2099443,
                2101615, 2101951, 2097914, 2099403, 2098847, 2098385, 2098462, 2099098, 2100040,
                2102197, 2098791, 2097474, 2097186, 2097698, 2099689, 2095196, 2095877, 2095316,
                2097602, 2096130, 2097887, 2097582, 2097614, 2094629, 2094200, 2095665, 2095933,
                2097814, 2096123, 2096116, 2094014, 2095737, 2095616, 2098545, 2098034, 2096617,
                2092905, 2095555, 2097381, 2099894, 2098296, 2095981, 2096573, 2097999, 2096896,
                2097936, 2098438, 2101239, 2097516, 2099938, 2097694, 2096780, 2095506, 2098285,
                2097115, 2097581, 2096939, 2094798, 2097771, 2095263, 2097172, 2097960, 2102554,
                2098936, 2100515, 2096359, 2095162, 2098059, 2100056, 2099634, 2098127, 2097224,
                2100208, 2101321, 2098311, 2096940,
            ],
            [
                2092621, 2097295, 2094053, 2093519, 2096002, 2095618, 2095128, 2096454, 2096881,
                2097226, 2095676, 2092063, 2095697, 2096886, 2098981, 2094814, 2095188, 2094762,
                2095601, 2093313, 2094803, 2096164, 2100283, 2094610, 2096770, 2097134, 2093661,
                2098701, 2095335, 2094407, 2091991, 2095139, 2095968, 2095222, 2096821, 2093902,
                2094301, 2096534, 2095677, 2096679, 2096402, 2096873, 2097196, 2097274, 2099539,
                2096361, 2095995, 2095117, 2096002, 2097482, 2097903, 2093872, 2096902, 2098667,
                2096105, 2094893, 2092947, 2094419, 2097610, 2097496, 2097498, 2096632, 2098286,
                2095850, 2094808, 2097612, 2098933, 2094603, 2097793, 2094235, 2094603, 2097186,
                2095454, 2096147, 2094587, 2096255, 2096650, 2094806, 2097352, 2107694, 2095899,
                2096481, 2095807, 2096666, 2096728, 2098123, 2107068, 2095496, 2098533, 2093568,
                2096633, 2096929, 2093847, 2096528, 2097011, 2097657, 2096534, 2096355, 2093799,
                2095119, 2094281, 2095712, 2096070, 2093700, 2096332, 2094683, 2097220, 2095601,
                2095781, 2093870, 2094886, 2095674, 2096937, 2096263, 2094717, 2095105, 2094334,
                2095347, 2093331, 2095855, 2094487, 2096133, 2094459, 2095029, 2094957, 2096069,
                2095893, 2094797, 2099896, 2098919, 2095951, 2098814, 2098889, 2099272, 2099126,
                2098134, 2100186, 2099604, 2099094, 2098540, 2096781, 2096960, 2098943, 2099370,
                2098748, 2098134, 2100295, 2100111, 2099800, 2097681, 2097958, 2099418, 2097321,
                2098881, 2099166, 2098890, 2098324, 2099127, 2101174, 2098309, 2096730, 2100892,
                2100358, 2101714, 2098419, 2100757, 2099570, 2100026, 2100006, 2097766, 2102407,
                2101676, 2099160, 2098764, 2099265, 2100576, 2098786, 2098910, 2099001, 2100441,
                2097542, 2100112, 2099709, 2096564, 2100885, 2101961, 2101379, 2097861, 2099424,
                2101300, 2098487, 2100738, 2098527, 2096987, 2098383, 2095203, 2097029, 2096795,
                2096680, 2096409, 2094219, 2096686, 2095052, 2101589, 2098458, 2095942, 2097154,
                2097960, 2097519, 2097960, 2097185, 2095336, 2096080, 2096336, 2095028, 2096728,
                2096176, 2095968, 2097945, 2096385, 2094005, 2095723, 2093169, 2096904, 2097366,
                2097871, 2098498, 2098246, 2096718, 2098823, 2098050, 2098623, 2096635, 2100232,
                2099268, 2096284, 2100270, 2099897, 2097302, 2097405, 2097459, 2096783, 2096399,
                2099931, 2096345, 2097431, 2096763, 2098062, 2098752, 2096732, 2097355, 2098787,
                2098813, 2097787, 2098144, 2099136,
            ],
            [
                2096861, 2095893, 2093636, 2097032, 2095240, 2092940, 2094970, 2095612, 2094338,
                2095013, 2095056, 2099354, 2093642, 2095727, 2094937, 2096272, 2095803, 2096105,
                2096377, 2097903, 2096779, 2096723, 2097563, 2095476, 2094988, 2097001, 2092435,
                2095366, 2096983, 2095016, 2095141, 2094231, 2096857, 2095032, 2094418, 2096559,
                2098852, 2092714, 2096180, 2095154, 2095125, 2095434, 2094733, 2097054, 2097582,
                2096713, 2096168, 2097617, 2097644, 2096809, 2095717, 2096868, 2094614, 2096144,
                2097389, 2096176, 2096836, 2094549, 2095735, 2098859, 2096780, 2097431, 2095009,
                2096218, 2095426, 2107024, 2099124, 2096575, 2095513, 2096820, 2096641, 2098278,
                2096135, 2093194, 2095159, 2094323, 2098212, 2095863, 2097301, 2096240, 2096202,
                2096796, 2095133, 2095360, 2095080, 2096565, 2096127, 2096559, 2096785, 2095703,
                2094074, 2107308, 2097433, 2094089, 2092857, 2095319, 2095434, 2095306, 2094527,
                2095954, 2095661, 2096436, 2094374, 2094742, 2097078, 2096289, 2096518, 2097599,
                2094945, 2096202, 2094553, 2095293, 2093197, 2097914, 2096781, 2093575, 2097579,
                2095976, 2098265, 2096591, 2098459, 2097516, 2094918, 2096767, 2095167, 2096263,
                2096212, 2095587, 2099022, 2098235, 2103006, 2096930, 2097751, 2096258, 2101529,
                2096669, 2100971, 2097488, 2098887, 2098781, 2100041, 2099228, 2096926, 2101021,
                2098381, 2101144, 2098616, 2098719, 2098496, 2097737, 2098716, 2100074, 2099010,
                2097413, 2102501, 2096978, 2101168, 2098677, 2102246, 2098987, 2098904, 2098153,
                2098044, 2100304, 2099024, 2098079, 2097805, 2097522, 2101087, 2100649, 2098121,
                2097640, 2096793, 2097755, 2098288, 2101758, 2097235, 2100602, 2101360, 2099798,
                2098891, 2098643, 2101381, 2098590, 2100511, 2099874, 2099615, 2101951, 2098867,
                2100882, 2102372, 2100410, 2095648, 2095677, 2098199, 2096758, 2097180, 2096647,
                2099055, 2095877, 2097921, 2095212, 2096443, 2098369, 2095331, 2094745, 2095813,
                2096719, 2098770, 2100338, 2093289, 2094134, 2098334, 2098592, 2097729, 2095781,
                2095009, 2094215, 2096903, 2096859, 2096484, 2096775, 2094758, 2098357, 2095253,
                2096418, 2096513, 2099002, 2093731, 2097107, 2098893, 2098938, 2095823, 2099000,
                2098020, 2096603, 2095361, 2096920, 2097799, 2094188, 2099812, 2098359, 2098079,
                2099398, 2096923, 2097841, 2100189, 2095972, 2098355, 2100250, 2098328, 2099787,
                2100068, 2097495, 2096099, 2095674,
            ],
            [
                2093233, 2097025, 2094428, 2095680, 2096642, 2095838, 2093888, 2099171, 2092712,
                2097213, 2096479, 2093824, 2093139, 2093945, 2096126, 2095986, 2095728, 2096562,
                2093690, 2097116, 2095391, 2097775, 2097665, 2095326, 2098243, 2096470, 2094613,
                2094549, 2095014, 2095712, 2096285, 2095549, 2095472, 2095232, 2095529, 2096379,
                2099822, 2098581, 2097487, 2095898, 2095480, 2096567, 2094434, 2094458, 2095573,
                2095359, 2096120, 2097488, 2095371, 2095460, 2096182, 2095296, 2095566, 2094622,
                2095176, 2094467, 2098375, 2098110, 2095637, 2098140, 2096107, 2096022, 2097494,
                2098178, 2096111, 2095842, 2096379, 2097554, 2095296, 2093704, 2096605, 2096900,
                2094088, 2097111, 2096382, 2094710, 2104425, 2096128, 2096102, 2097099, 2093008,
                2093210, 2093895, 2097184, 2096631, 2093957, 2096863, 2107209, 2097357, 2097763,
                2096688, 2094717, 2092851, 2095323, 2094464, 2095408, 2093745, 2096752, 2095082,
                2092970, 2094898, 2093594, 2097521, 2096753, 2095686, 2097067, 2098074, 2095726,
                2095233, 2095217, 2094908, 2096049, 2094612, 2096731, 2094343, 2096384, 2097097,
                2097018, 2095250, 2094413, 2095504, 2096864, 2095908, 2094793, 2094241, 2096193,
                2094884, 2094027, 2096316, 2098421, 2097635, 2096446, 2098678, 2099266, 2100382,
                2100336, 2098354, 2099570, 2097338, 2098356, 2098656, 2097366, 2098418, 2097698,
                2097380, 2100394, 2098991, 2099505, 2098551, 2097043, 2099276, 2096879, 2099884,
                2099682, 2099219, 2101439, 2098095, 2098404, 2097691, 2097880, 2098205, 2102678,
                2101462, 2097959, 2100564, 2098496, 2100012, 2099391, 2098302, 2098213, 2096541,
                2097120, 2100262, 2099630, 2098741, 2100202, 2097475, 2101160, 2098092, 2103869,
                2100791, 2100441, 2100940, 2102430, 2101572, 2100351, 2100552, 2099504, 2101788,
                2097964, 2101126, 2100631, 2100691, 2094554, 2097168, 2096512, 2097984, 2096474,
                2097943, 2094994, 2097741, 2098411, 2095085, 2097459, 2096557, 2097982, 2094256,
                2097973, 2098895, 2096983, 2095402, 2096797, 2098705, 2097843, 2098902, 2095825,
                2098693, 2098583, 2097810, 2097670, 2097889, 2099741, 2097345, 2095739, 2100478,
                2100734, 2096921, 2096977, 2096915, 2096862, 2099387, 2096801, 2096710, 2096319,
                2098230, 2096675, 2097386, 2096272, 2097196, 2099226, 2096303, 2099875, 2099241,
                2097295, 2097725, 2097460, 2097692, 2095338, 2097915, 2098243, 2098372, 2102336,
                2096528, 2096819, 2097551, 2094911,
            ],
            [
                2096201, 2098151, 2093548, 2096632, 2092024, 2098105, 2097260, 2095398, 2094823,
                2096728, 2095942, 2096459, 2095765, 2095236, 2095684, 2095432, 2097314, 2095818,
                2093357, 2097821, 2095245, 2095118, 2093568, 2091300, 2096444, 2096292, 2096021,
                2096873, 2096037, 2095728, 2095987, 2095464, 2096298, 2098434, 2092773, 2097541,
                2096476, 2095846, 2095647, 2098427, 2097785, 2096429, 2095603, 2096503, 2096396,
                2097121, 2097955, 2097528, 2095608, 2093723, 2095728, 2095581, 2095748, 2095684,
                2095832, 2094586, 2098438, 2098264, 2097848, 2095891, 2094266, 2096050, 2093790,
                2095826, 2095889, 2096283, 2095340, 2099002, 2096382, 2096139, 2095449, 2097060,
                2109010, 2094002, 2094658, 2095640, 2098034, 2098395, 2097261, 2096372, 2096143,
                2097272, 2094653, 2094513, 2109926, 2095891, 2096413, 2096864, 2097749, 2096881,
                2096668, 2096453, 2095778, 2097714, 2098992, 2098754, 2094363, 2096549, 2094670,
                2095206, 2095901, 2094931, 2092532, 2093023, 2093202, 2095466, 2096470, 2094559,
                2096038, 2095024, 2096407, 2094749, 2094356, 2094461, 2092538, 2095964, 2098481,
                2094274, 2096154, 2093171, 2092769, 2095957, 2094077, 2094140, 2094130, 2095227,
                2094342, 2095224, 2095803, 2098954, 2099619, 2099639, 2100639, 2097407, 2097457,
                2098063, 2099152, 2097906, 2096287, 2097228, 2099598, 2097226, 2100798, 2100772,
                2099059, 2097539, 2100518, 2098192, 2098193, 2096064, 2098700, 2098026, 2098951,
                2099756, 2099442, 2097326, 2098534, 2100181, 2095736, 2097971, 2098632, 2099992,
                2102840, 2099397, 2100817, 2099881, 2098859, 2098617, 2100335, 2099053, 2097619,
                2102544, 2101379, 2101942, 2098958, 2100484, 2099891, 2098182, 2101095, 2099115,
                2099232, 2098500, 2100180, 2099157, 2101059, 2098967, 2099029, 2101092, 2096261,
                2101147, 2098594, 2099314, 2098170, 2097647, 2098124, 2097162, 2095522, 2097288,
                2096817, 2092931, 2096812, 2097553, 2098742, 2096099, 2099274, 2098792, 2097484,
                2097969, 2094825, 2097895, 2096984, 2096276, 2096070, 2098656, 2097599, 2097798,
                2096150, 2096819, 2097531, 2095897, 2097508, 2097094, 2097933, 2096681, 2099151,
                2098564, 2096726, 2097266, 2097534, 2098901, 2096987, 2093989, 2096855, 2097428,
                2096465, 2099652, 2102853, 2100833, 2098974, 2101169, 2096282, 2095064, 2094366,
                2098305, 2097460, 2097344, 2096896, 2099084, 2099080, 2097795, 2100176, 2096590,
                2096243, 2097346, 2097313, 2095884,
            ],
            [
                2095725, 2095224, 2096655, 2093072, 2095009, 2095489, 2094343, 2094678, 2094729,
                2096452, 2095883, 2095661, 2097131, 2096310, 2096108, 2095002, 2097149, 2098136,
                2095983, 2094665, 2097942, 2096502, 2096836, 2096056, 2097880, 2095791, 2096287,
                2097859, 2096975, 2095479, 2095651, 2095825, 2094031, 2096444, 2096099, 2096805,
                2097900, 2096961, 2095972, 2094970, 2098561, 2098865, 2097091, 2092677, 2097055,
                2097197, 2096263, 2092890, 2097436, 2094895, 2099219, 2096472, 2098630, 2096330,
                2093716, 2095306, 2097033, 2094050, 2094536, 2096229, 2093651, 2098802, 2095556,
                2095711, 2096070, 2096312, 2095467, 2096356, 2097119, 2095280, 2098734, 2097030,
                2094060, 2105227, 2097235, 2097131, 2097743, 2097459, 2098055, 2096843, 2096346,
                2096400, 2096181, 2095362, 2104656, 2096441, 2094898, 2096269, 2097269, 2095519,
                2097779, 2094978, 2098387, 2096537, 2095763, 2098010, 2095671, 2096000, 2095980,
                2095282, 2093704, 2095775, 2096478, 2094339, 2096235, 2094820, 2095911, 2093975,
                2092705, 2096237, 2097013, 2095958, 2096011, 2096646, 2096036, 2092457, 2097096,
                2096701, 2094756, 2093554, 2097052, 2093182, 2096141, 2096517, 2095178, 2095179,
                2095376, 2093628, 2098592, 2099062, 2099922, 2098966, 2097690, 2097729, 2096742,
                2095234, 2097937, 2097937, 2096266, 2097235, 2094760, 2098372, 2097809, 2100314,
                2100306, 2098398, 2097110, 2100578, 2099688, 2098896, 2097732, 2100857, 2099358,
                2099435, 2099183, 2101012, 2098416, 2097147, 2096782, 2099454, 2098588, 2095757,
                2099221, 2102422, 2098105, 2100771, 2098696, 2100991, 2098475, 2098006, 2099142,
                2098371, 2099435, 2100749, 2100016, 2098268, 2100432, 2101599, 2099832, 2099297,
                2099530, 2101394, 2101308, 2099881, 2100895, 2101009, 2097253, 2100238, 2100091,
                2097446, 2101592, 2100072, 2096223, 2098358, 2095816, 2097559, 2097519, 2096981,
                2096744, 2095634, 2095722, 2098514, 2093711, 2095990, 2097981, 2097181, 2097637,
                2096435, 2097760, 2100178, 2099038, 2096402, 2095389, 2096024, 2099087, 2097536,
                2097462, 2098024, 2096250, 2097515, 2095953, 2097841, 2095927, 2099126, 2097430,
                2094477, 2097731, 2097188, 2098098, 2098355, 2097952, 2098964, 2097959, 2097739,
                2096832, 2096818, 2094351, 2097047, 2099102, 2096827, 2097074, 2096165, 2095941,
                2099054, 2097104, 2099040, 2097261, 2099129, 2096557, 2096690, 2098166, 2097663,
                2095537, 2098069, 2100473, 2096452,
            ],
            [
                2095444, 2094856, 2093088, 2094820, 2097557, 2092953, 2097183, 2094600, 2094866,
                2094339, 2096968, 2097426, 2094289, 2094688, 2094915, 2092445, 2096540, 2094224,
                2094842, 2095656, 2094495, 2095451, 2094915, 2096858, 2095945, 2097962, 2093906,
                2098558, 2094116, 2096832, 2097135, 2097483, 2096929, 2096930, 2097944, 2095498,
                2093995, 2096109, 2097072, 2097279, 2096418, 2096969, 2095103, 2092690, 2097353,
                2095118, 2097877, 2095168, 2097711, 2095993, 2096732, 2096729, 2095647, 2096263,
                2095807, 2094001, 2095631, 2095071, 2094332, 2098426, 2094062, 2096583, 2098149,
                2095626, 2096040, 2097024, 2093165, 2094420, 2093686, 2095045, 2098051, 2095512,
                2096849, 2096090, 2093613, 2096642, 2094525, 2096210, 2107155, 2095570, 2106390,
                2094746, 2096916, 2096632, 2098499, 2097837, 2096437, 2096514, 2097072, 2093353,
                2094934, 2099564, 2095297, 2097891, 2095634, 2096437, 2096431, 2098998, 2092393,
                2092423, 2093674, 2095780, 2097806, 2096083, 2093713, 2094860, 2096937, 2093503,
                2095037, 2094131, 2095251, 2095982, 2095335, 2097209, 2095773, 2094894, 2095164,
                2096492, 2096341, 2097692, 2096319, 2093015, 2095972, 2097876, 2097193, 2094595,
                2095758, 2095536, 2098479, 2098012, 2097446, 2098445, 2098208, 2097333, 2098789,
                2097954, 2099063, 2096277, 2095614, 2097781, 2095737, 2099267, 2098287, 2096053,
                2097489, 2098157, 2103472, 2100545, 2100057, 2099395, 2100024, 2100153, 2101809,
                2097986, 2097707, 2098500, 2095188, 2099017, 2098488, 2097371, 2100338, 2099646,
                2101491, 2100674, 2099701, 2098196, 2098474, 2100051, 2100521, 2098414, 2095197,
                2098575, 2101104, 2099356, 2100335, 2097935, 2101145, 2099806, 2100334, 2099884,
                2100062, 2101142, 2098941, 2100831, 2103626, 2101193, 2099219, 2099090, 2100806,
                2101145, 2099470, 2100558, 2095042, 2096626, 2098071, 2096763, 2096578, 2096739,
                2097352, 2096250, 2098447, 2094468, 2098981, 2098318, 2097347, 2095881, 2096835,
                2097177, 2094599, 2098280, 2097760, 2097490, 2098515, 2096029, 2098812, 2098774,
                2097437, 2098460, 2096499, 2096938, 2097180, 2098521, 2096256, 2096769, 2095346,
                2096913, 2097531, 2098693, 2096995, 2095301, 2098101, 2099293, 2097242, 2097108,
                2096705, 2095723, 2096426, 2100558, 2096188, 2096733, 2098948, 2098657, 2100127,
                2099693, 2098730, 2096605, 2096921, 2098706, 2099453, 2096850, 2096886, 2101773,
                2098233, 2098340, 2099795, 2099296,
            ],
            [
                2098554, 2094604, 2096750, 2094496, 2097935, 2093155, 2095429, 2092292, 2096931,
                2095723, 2095476, 2095560, 2094288, 2095563, 2098121, 2092777, 2097258, 2097090,
                2097707, 2096689, 2096006, 2094448, 2097683, 2096794, 2095944, 2095211, 2097506,
                2094111, 2096912, 2093654, 2100731, 2093442, 2096343, 2098606, 2095541, 2098345,
                2099646, 2092909, 2097435, 2095163, 2098806, 2094378, 2096413, 2097095, 2096383,
                2097969, 2094247, 2094994, 2100198, 2096487, 2095321, 2096805, 2099440, 2096572,
                2098260, 2096015, 2097862, 2097350, 2095190, 2094301, 2098747, 2094033, 2098794,
                2097095, 2094521, 2097206, 2095908, 2098445, 2094968, 2104911, 2098406, 2096672,
                2095514, 2099155, 2097617, 2094731, 2092710, 2097773, 2097166, 2095018, 2095199,
                2098140, 2096724, 2097467, 2098507, 2096638, 2099130, 2096090, 2097691, 2097016,
                2106762, 2096637, 2095712, 2097685, 2097020, 2096759, 2095870, 2095850, 2096898,
                2092713, 2095394, 2094249, 2091948, 2094778, 2094664, 2096750, 2093483, 2095446,
                2096681, 2095576, 2092109, 2094629, 2096653, 2098141, 2097522, 2093227, 2093843,
                2093592, 2095944, 2095085, 2094339, 2096400, 2096180, 2092514, 2094075, 2093154,
                2096706, 2092827, 2097620, 2097837, 2100717, 2096386, 2100093, 2099013, 2098684,
                2099362, 2101347, 2098455, 2100708, 2098710, 2097440, 2097755, 2098780, 2098131,
                2098784, 2098859, 2100002, 2096677, 2100905, 2097808, 2100169, 2098437, 2097971,
                2099033, 2097926, 2100692, 2097882, 2094577, 2097506, 2099645, 2098646, 2096840,
                2099843, 2097538, 2098691, 2099117, 2100314, 2099095, 2095490, 2099757, 2099719,
                2099317, 2100326, 2097926, 2097412, 2100302, 2099242, 2099747, 2099017, 2098187,
                2098940, 2098796, 2100136, 2098338, 2102445, 2101231, 2101968, 2098619, 2098366,
                2098422, 2102182, 2097393, 2096069, 2096521, 2096091, 2096828, 2097364, 2096640,
                2096395, 2096529, 2096351, 2097422, 2096646, 2098023, 2093431, 2096916, 2096611,
                2097913, 2097831, 2093853, 2096634, 2098244, 2096906, 2099414, 2096547, 2093621,
                2097345, 2097498, 2100685, 2096575, 2096509, 2098568, 2099729, 2099707, 2098544,
                2097684, 2096875, 2098975, 2097336, 2097260, 2097599, 2097376, 2097804, 2096258,
                2095742, 2098197, 2098770, 2095806, 2098479, 2096854, 2095100, 2096909, 2096458,
                2097307, 2100301, 2094321, 2097471, 2097281, 2098402, 2097863, 2096506, 2095105,
                2099303, 2098738, 2096550, 2100328,
            ],
        ];

        let pool_size = 12;
        let trials = 1usize << 32;
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
