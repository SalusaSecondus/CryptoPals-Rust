


#[cfg(test)]
mod tests {
    use crate::{oracles::Challenge49Oracle, padding::{self, Padding}, xor};
    use anyhow::{Result, Context};

    #[test]
    fn challenge40_1() -> Result<()> {
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
        assert!(oracle.verify1(&iv2 , &tag1, "9", "7", 1000000).is_ok());
        Ok(())
    }

    #[test]
    fn challenge40_2() -> Result<()> {
        let oracle: Challenge49Oracle = Default::default();
        let pkcs7 = Padding::Pkcs7Padding(16);

        let txns1 = vec![
            ("0", 1),
            ("15", 32),
            ("2",45)
        ];
        let good_mac = oracle.sign2("1", &txns1)?;
        println!("Good mac: {}", hex::encode(&good_mac));
        let good_signed = pkcs7.pad(Challenge49Oracle::sts2("1", &txns1).as_bytes())?;

        let txns2 = vec![
            ("99", 1000000),
            ("99", 10),
            ("99", 1000000)
        ];
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
}