use anyhow::{bail, ensure, Result};

pub enum Padding {
    Pkcs1PaddingSigning(u64),
    Pkcs7Padding(usize),
}

impl Padding {
    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Padding::Pkcs1PaddingSigning(bit_length) => pkcs1_sign_pad(data, *bit_length),
            Padding::Pkcs7Padding(width) => pkcs7_pad(data, *width),
        }
    }

    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Padding::Pkcs1PaddingSigning(bit_length) => pkcs1_sign_unpad(data, *bit_length),
            Padding::Pkcs7Padding(width) => pkcs7_unpad(data, *width),
        }
    }
}

fn pkcs1_sign_pad(data: &[u8], bit_length: u64) -> Result<Vec<u8>> {
    let em_len: usize = ((bit_length + 7) / 8) as usize;
    let t_len = data.len();
    ensure!(
        em_len - 11 >= t_len,
        format!(
            "intended encoded message length too short. em_len = {}, t_len = {}",
            em_len, t_len
        )
    );

    let pad_len = em_len - t_len - 3;
    let mut result = vec![];
    result.reserve_exact(em_len);
    result.push(0x00);
    result.push(0x01);
    result.extend(std::iter::repeat(0xFF).take(pad_len));
    result.push(0x00);
    result.extend_from_slice(data);
    Ok(result)
}

fn pkcs1_sign_unpad(data: &[u8], bit_length: u64) -> Result<Vec<u8>> {
    let em_len: usize = ((bit_length + 7) / 8) as usize;
    let base_index = if data.len() == em_len {
        ensure!(data[0] == 0, "Invalid first byte");
        1
    } else if data.len() == em_len - 1 {
        0
    } else {
        bail!("Invalid input length");
    };

    ensure!(data[base_index] == 1, "Invalid second byte");

    // Find the start of the data
    for (idx, b) in data.iter().enumerate().skip(base_index + 1) {
        if *b == 0 {
            ensure!(idx > 9, "Insufficient padding");
            return Ok(data[idx + 1..].to_owned());
        }
    }
    bail!("No zero byte found");
}

fn pkcs7_pad(data: &[u8], width: usize) -> Result<Vec<u8>> {
    ensure!(width < 256, "Invalid width");

    let pad_needed = width - (data.len() % width);

    let padding = std::iter::repeat(pad_needed as u8).take(pad_needed);
    let mut result = Vec::from(data);
    result.extend(padding);

    Ok(result)
}

fn pkcs7_unpad(data: &[u8], width: usize) -> Result<Vec<u8>> {
    ensure!(width < 256, "Invalid width");
    ensure!(
        data.len() % width == 0 && !data.is_empty(),
        "Bad input length"
    );

    let pad_length = *data.last().unwrap();
    ensure!(
        pad_length > 0 && pad_length <= width as u8,
        "Invalid pad length"
    );

    let (result, padding) = data.split_at(data.len() - pad_length as usize);

    // Ensure all padding bytes are valid
    ensure!(
        padding.iter().filter(|b| **b != pad_length).count() == 0,
        "Bad padding byte"
    );

    let result = Vec::from(result);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::Padding;
    use anyhow::Result;
    use rand::RngCore;
    use rand_core::OsRng;

    #[test]
    fn challenge_9() -> Result<()> {
        let input = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";

        let padded = Padding::Pkcs7Padding(20).pad(input)?;

        assert_eq!(expected, padded.as_slice());

        let unpadded = Padding::Pkcs7Padding(20).unpad(&padded)?;

        assert_eq!(input, unpadded.as_slice());
        Ok(())
    }

    #[test]
    fn pkcs7() -> Result<()> {
        let sizes = [512, 1024, 2048];
        for size in sizes.iter() {
            let padding = Padding::Pkcs1PaddingSigning(*size);
            for data_len in 0..50 {
                let mut data = vec![0u8; data_len];
                OsRng.fill_bytes(&mut data);
                let padded = padding.pad(&data)?;
                let unpadded = padding.unpad(&padded)?;
                assert_eq!(data, unpadded);
            }

            // TODO: Add limit checks
        }
        Ok(())
    }
}
