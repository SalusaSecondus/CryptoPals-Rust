#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::*;
    use aes::AesKey;
    use anyhow::{bail, Result};
    use hex::decode as hex_decode;
    use hex::encode as hex_encode;

    #[test]
    fn challenge_1() -> Result<()> {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            base64::encode(&hex::decode(hex)?)
        );

        Ok(())
    }

    #[test]
    fn challenge_2() -> Result<()> {
        let val1 = hex_decode("1c0111001f010100061a024b53535009181c")?;
        let val2 = hex_decode("686974207468652062756c6c277320657965")?;

        let result = crate::xor(&val1, &val2);
        assert_eq!("746865206b696420646f6e277420706c6179", hex_encode(result));

        Ok(())
    }

    #[test]
    fn challenge_3() -> Result<()> {
        let input =
            hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
        let (best_guess, _, _) = find_best_single_xor(&input)?;

        println!("1.3: Hex: {}", hex_encode(&best_guess));
        println!("1.3: Answer: {}", String::from_utf8_lossy(&best_guess));
        assert_eq!(
            "436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e",
            hex_encode(&best_guess)
        );
        Ok(())
    }

    #[test]
    fn challenge_4() -> Result<()> {
        let mut best_score = f64::MAX;
        let mut best_guess = Option::None;

        for line in crate::read_file("1_4.txt")? {
            let line = hex_decode(line?)?;
            let (guess, _, score) = find_best_single_xor(&line)?;
            if score < best_score {
                best_score = score;
                best_guess = Option::Some(guess);
            }
        }

        let best_guess = best_guess.unwrap();
        println!("1.4: Hex: {}", hex_encode(&best_guess));
        println!("1.4: Answer: {}", String::from_utf8_lossy(&best_guess));
        assert_eq!(
            "4e6f77207468617420746865207061727479206973206a756d70696e670a",
            hex_encode(&best_guess)
        );

        Ok(())
    }

    #[test]
    fn challenge_5() -> Result<()> {
        let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let plaintext =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        // let plaintext = text.as_bytes();
        let key = b"ICE";
        let ciphertext = crate::xor(plaintext, key);

        println!("Challenge 1.5: {}", hex_encode(&ciphertext));
        assert_eq!(expected_hex, hex_encode(&ciphertext));

        Ok(())
    }

    #[test]
    #[ignore = "large_output"]
    fn challenge_6() -> Result<()> {
        let input = file_to_string("6.txt")?;
        let input = base64::decode(&input)?;
        let pieces = find_best_multi_xor(&input)?;
        println!(
            "Challenge 6: {}\n\n{}",
            hex_encode(&pieces.1),
            String::from_utf8_lossy(&pieces.0)
        );
        Ok(())
    }

    #[test]
    fn challenge_7() -> Result<()> {
        let key: AesKey = AesKey::new(b"YELLOW SUBMARINE")?;
        let input = file_to_string("7.txt")?;
        let input = base64::decode(&input)?;

        let plaintext: Vec<u8> = input
            .chunks_exact(16)
            .flat_map(|block| key.decrypt_block(block))
            .collect();
        let plaintext = String::from_utf8(plaintext)?;
        println!("Challenge 7: {}", plaintext);
        Ok(())
    }

    #[test]
    fn challenge_8() -> Result<()> {
        let mut ciphertexts = vec![];
        for l in crate::read_file("8.txt")? {
            ciphertexts.push(hex_decode(l?)?);
        }

        for (idx, c) in ciphertexts.iter().enumerate() {
            let mut seen = HashSet::new();
            for chunk in c.chunks_exact(16) {
                if !seen.insert(chunk) {
                    println!(
                        "Ciphertext {} has duplicate block {}",
                        idx,
                        hex_encode(chunk)
                    );
                    return Ok(());
                }
            }
        }
        bail!("No duplicates found");
    }
}
