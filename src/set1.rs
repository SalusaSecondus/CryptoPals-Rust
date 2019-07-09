// https://cryptopals.com/sets/1

use super::*;

fn single_byte_xor(bin : &Vec<u8>, twiddle : u8) -> Result<Vec<u8>> {
    let mut result = bin.clone();
    for val in result.iter_mut() {
        *val ^= twiddle;
    }
    Ok(result)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn set1_prob3() {
        let ciphertext = hex_to_bin("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

        let mut low_score = 1000000.0;
        let mut low_twiddle = 0;
        for twiddle in 0..255 {
            let raw = single_byte_xor(&ciphertext, twiddle).unwrap();
            let guess = bytes_to_string(&raw);
            let score = monograph_score(&guess);
            if score < low_score {
                low_score = score;
                low_twiddle = twiddle;
            }
            println!("{} {}: {}", twiddle, monograph_score(&guess), guess);
        }
        let raw = single_byte_xor(&ciphertext, low_twiddle).unwrap();
        let guess = bytes_to_string(&raw);
        println!("{} {}: {}", low_twiddle, monograph_score(&guess), guess);
        
    }
}