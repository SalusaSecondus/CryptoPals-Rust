mod set1;

#[macro_use]
extern crate lazy_static;

pub use failure::Error;
use failure::err_msg;
use std::collections::HashMap;

pub type Result<T>  = std::result::Result<T, Error>;

lazy_static! {
    static ref MONOGRAM_FREQUENCIES : HashMap<&'static str, f32> = {
        let mut m = HashMap::new();
        m.insert(" ", 0.1217);
        m.insert("a", 0.0609);
        m.insert("b", 0.0105);
        m.insert("c", 0.0284);
        m.insert("d", 0.0292);
        m.insert("e", 0.1136);
        m.insert("f", 0.0179);
        m.insert("g", 0.0138);
        m.insert("h", 0.0341);
        m.insert("i", 0.0544);
        m.insert("j", 0.0024);
        m.insert("k", 0.0041);
        m.insert("l", 0.0292);
        m.insert("m", 0.0276);
        m.insert("n", 0.0544);
        m.insert("o", 0.0600);
        m.insert("p", 0.0195);
        m.insert("q", 0.0024);
        m.insert("r", 0.0495);
        m.insert("s", 0.0568);
        m.insert("t", 0.0803);
        m.insert("u", 0.0243);
        m.insert("v", 0.0097);
        m.insert("w", 0.0138);
        m.insert("x", 0.0024);
        m.insert("y", 0.0130);
        m.insert("z", 0.0003);
        m
    };
}


pub fn hex_to_bin(hex : &str) -> Result<Vec<u8>> {
    let mut result : Vec<u8> = Vec::new();
    for hex_byte in string_chunk(hex, 2) {
        let byte = u8::from_str_radix(hex_byte, 16)?;
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

pub fn string_chunk(string : &str, size : usize) -> Vec<&str> {
    let mut result : Vec<&str> = Vec::new();
    let mut indices = string.char_indices();

    let mut start = indices.next().unwrap().0;
    loop {
        let mut end = Option::None;
        for _x in 0..size {
            end = indices.next();
        }
        if end.is_some() {
            let idx_end = end.unwrap().0;
            let tmp = &string[start..idx_end];
            result.push(tmp);
            start = idx_end;
        } else {
            let tmp = &string[start..];
            result.push(tmp);
            break;
        }
    }
    result
}

pub fn monograph_score(string : &str) -> f32 {
    let mut total : f32 = 0.0;
    let mut cnts : HashMap<&str, f32> = HashMap::new();
    let mut result = 0.0;

    let lowercase = string.to_lowercase();
    for mono in string_chunk(&lowercase, 1) {
        let mono_cnt = cnts.entry(mono).or_insert(0.0);
        *mono_cnt += 1.0;
        total += 1.0;
    }

    for (key, val) in MONOGRAM_FREQUENCIES.iter() {
        let freq = cnts.get(key).unwrap_or(&0.0) / total;
        let diff = freq - val;
        let sq_diff = diff * diff;
        result += sq_diff;
    }
    
    result
}

pub fn bytes_to_string(bytes : &Vec<u8>) -> String {
    String::from_utf8_lossy(bytes).to_string()
    // let mut result = String::new();
    // for b in bytes {
    //     // if *b < 128 {
    //         result.push(*b as char)
    //     // } else {
    //     //     result.push('\u{FFFD}');
    //     // }
    // }
    // result
}

#[cfg(test)]
mod tests {
    use super::*;

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
