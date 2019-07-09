// https://cryptopals.com/sets/1

use super::*;

fn single_byte_xor(bin: &Vec<u8>, twiddle: u8) -> Result<Vec<u8>> {
    let mut result = bin.clone();
    for val in result.iter_mut() {
        *val ^= twiddle;
    }
    Ok(result)
}

#[allow(dead_code)]
fn find_best_twiddle(bin: &Vec<u8>) -> (u8, f32, String) {
    let mut low_twiddle = 0;
    let mut low_score = 1000000.0;
    let mut low_string = String::new();
    for twiddle in 0..255 {
        let raw = single_byte_xor(bin, twiddle).unwrap();
        let guess = bytes_to_string(&raw);
        let score = monograph_score(&guess);
        if score < low_score {
            low_score = score;
            low_twiddle = twiddle;
            low_string = guess;
        }
    }
    (low_twiddle, low_score, low_string)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs;

    #[test]
    pub fn set1_prob3() {
        let ciphertext =
            hex_to_bin("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();

        let (low_twiddle, low_score, guess) = find_best_twiddle(&ciphertext);
        println!("{} {}: {}", low_twiddle, low_score, guess);
    }

    #[test]
    pub fn set1_prob4() {
        let mut low_twiddle = 0;
        let mut low_score = 1000000.0;
        let mut low_string = String::new();
        for line in fs::read_to_string("res/1_4.txt").unwrap().lines() {
            let guess = hex_to_bin(line).unwrap();
            let (guess_twiddle, guess_score, guess_string) = find_best_twiddle(&guess);
            if guess_score < low_score {
                low_score = guess_score;
                low_twiddle = guess_twiddle;
                low_string = guess_string;
            }
        }

        println!("{} {}: {}", low_twiddle, low_score, low_string);

    }
}
