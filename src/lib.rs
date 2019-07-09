pub use failure::Error;
use failure::err_msg;

pub type Result<T>  = std::result::Result<T, Error>;

pub fn hex_to_bin(hex : &str) -> Result<Vec<u8>> {
    let mut result : Vec<u8> = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)?;
        result.push(byte);
    }

    Ok(result)
}

pub fn bin_to_hex(bin : &Vec<u8>) -> Result<String> {
    let mut result = String::new();
    for byte in bin {
        result += &format!("{:x}", byte);
    }
    Ok(result)
}

pub fn b64_to_bin(b64 : &str) -> Result<Vec<u8>> {
    Ok(base64::decode(b64)?)
}

pub fn bin_to_b64(bin : &Vec<u8>) -> Result<String> {
    Ok(base64::encode(bin))
}

pub fn xor(v1 : &Vec<u8>, v2 : &Vec<u8>) -> Result<Vec<u8>> {
    if v1.len() != v2.len() {
        Err(err_msg("Lengths are not compatible"))
    } else {
        let mut result = v1.clone();
        for i in 0..v1.len() {
            result[i] ^= v2[i];
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn set1_prob1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";


        assert_eq!(b64, bin_to_b64(&hex_to_bin(hex).unwrap()).unwrap());      
        assert_eq!(hex, bin_to_hex(&b64_to_bin(b64).unwrap()).unwrap());
    }

    #[test]
    fn set1_prob2() {
        let val1 = hex_to_bin("1c0111001f010100061a024b53535009181c").unwrap();
        let val2 = hex_to_bin("686974207468652062756c6c277320657965").unwrap();
        let result = "746865206b696420646f6e277420706c6179";

        assert_eq!(result, bin_to_hex(&xor(&val1, &val2).unwrap()).unwrap());

    }
}
