use anyhow::{ensure, Result};

pub enum Padding {
    Pkcs7Padding(usize)
}

impl Padding {
    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Padding::Pkcs7Padding(width) => pkcs7_pad(data, *width),
        }
    }

    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Padding::Pkcs7Padding(width) => pkcs7_unpad(data, *width),
        }
    }
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
    ensure!(data.len() % width == 0 && !data.is_empty(), "Bad input length");

    let pad_length = *data.last().unwrap();
    ensure!(pad_length > 0 && pad_length <= width as u8, "Invalid pad length");

    let (result, padding) = data.split_at(data.len() - pad_length as usize);

    // Ensure all padding bytes are valid
    ensure!(padding.iter().filter(|b| **b != pad_length).count() == 0, "Bad padding byte");

    let result = Vec::from(result);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use super::Padding;

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
}