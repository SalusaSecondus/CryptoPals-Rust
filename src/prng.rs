use anyhow::{ensure, Result};
use rand_core::{impls, RngCore};

const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;
const R: u32 = 31;
const A: u32 = 0x9908B0DF;
const U: u32 = 11;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;
const F: u64 = 1812433253;
const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

pub struct MT19937 {
    state: Vec<u32>,
    index: usize,
}

impl MT19937 {
    pub fn new(seed: u32) -> MT19937 {
        let index = N;
        let mut state = vec![];
        state.resize(N, 0);
        state[0] = seed;

        let mut prev_value = seed as u64;
        for (i, mt) in state.iter_mut().enumerate().skip(1) {
            prev_value = (F * (prev_value ^ (prev_value >> (W - 2)))) + i as u64;
            prev_value &= 0xFFFFFFFF;
            *mt = prev_value as u32;
        }

        MT19937 { state, index }
    }

    pub fn from_state(state: &[u32], index: usize) -> Result<MT19937> {
        ensure!(state.len() == N);
        ensure!(index <= N);

        Ok(MT19937 {
            state: state.to_owned(),
            index,
        })
    }

    pub fn untemper(val: u32) -> u32 {
        let val = MT19937::undo_18_shift(val);
        let val = MT19937::undo_15_shift(val);
        let val = MT19937::undo_7_shift(val);
        let val = MT19937::undo_11_shift(val);
        val
    }
    fn undo_18_shift(y: u32) -> u32 {
        y ^ (y >> 18)
    }

    fn undo_11_shift(y: u32) -> u32 {
        let high_1: u32 = 0xffe00000;
        let mut y = y;

        y ^= (y & high_1) >> 11;
        y ^= (y & (high_1 >> 11)) >> 11;
        y
    }

    fn undo_15_shift(val: u32) -> u32 {
        let low_15 = 0x7fffu32;
        let mask = 0xefc60000u32;
        let mut val = val;

        // Bottom 15 bits are correct
        val ^= ((val & low_15) << 15) & mask;
        // Bottom 30 bits are correct
        val ^= ((val & (low_15 << 15)) << 15) & mask;
        val
    }

    fn undo_7_shift(val: u32) -> u32 {
        let mut val = val;
        let low_7 = 0x7fu32;
        let mask = 0x9d2c5680u32;

        // There has _got_ to be a way to do this
        // in a single operation, but I just can't
        // think of it right now

        // Bottom 7 bits are correct
        val ^= ((val & low_7) << 7) & mask;
        // Bottom 14 bits are correct
        val ^= ((val & (low_7 << 7)) << 7) & mask;
        // Bottom 21 bits are correct
        val ^= ((val & (low_7 << 14)) << 7) & mask;
        // Bottom 28 bits are correct
        val ^= ((val & (low_7 << 21)) << 7) & mask;
        // Everything is correct
        val
    }
    fn extract_number(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }

        let mut y = self.state[self.index];
        y ^= y >> U;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..N - 1 {
            let x = (self.state[i] & UPPER_MASK) + (self.state[i + 1] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= A;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }
        self.index = 0
    }
}

impl RngCore for MT19937 {
    fn next_u32(&mut self) -> u32 {
        self.extract_number()
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MT19937;

    #[test]
    fn kats() {
        let kats = [
            (
                1u32,
                [
                    1791095845, 4282876139, 3093770124, 4005303368, 491263, 550290313, 1298508491,
                    4290846341, 630311759, 1013994432,
                ],
            ),
            (
                42,
                [
                    1608637542, 3421126067, 4083286876, 787846414, 3143890026, 3348747335,
                    2571218620, 2563451924, 670094950, 1914837113,
                ],
            ),
            (
                2147483647,
                [
                    1689602031, 3831148394, 2820341149, 2744746572, 370616153, 3004629480,
                    4141996784, 3942456616, 2667712047, 1179284407,
                ],
            ),
            (
                0xffffffff,
                [
                    419326371, 479346978, 3918654476, 2416749639, 3388880820, 2260532800,
                    3350089942, 3309765114, 77050329, 1217888032,
                ],
            ),
        ];

        for (seed, results) in kats.iter() {
            let mut rng = MT19937::new(*seed);
            for r in results {
                assert_eq!(*r, rng.extract_number());
            }
        }
    }
}
