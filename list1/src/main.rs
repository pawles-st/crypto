mod md5;

use md5::{BlockNumber, Md5Collider};
use md5::generation::gen_message;

//const PADDING: [u8; 64] = [
    //0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//];

// first test pair

//const M0_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9887b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a417125e82551089fc9cdf7f2bd1dd95b3c3780";
//const M1_HEX : &str = "d11d0b969c7b41dcf497d8e4d555655ac79a73350cfdebf066f129308fb109d1797f2775eb5cd530baade8225c15cc79ddcb74ed6dd3c55fd80a9bb1e3a7cc35";
//const M0_PRIME_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9807b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a41f125e82551089fc9cdf772bd1dd95b3c3780";
//const M1_PRIME_HEX : &str = "d11d0b969c7b41dcf497d8e4d555655a479a73350cfdebf066f129308fb109d1797f2775eb5cd530baade8225c154c79ddcb74ed6dd3c55f580a9bb1e3a7cc35";

const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
const M1_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739ac7f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba79cc155ced74cbdd5fc5d36db19b0ad835cca7e3";
const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
const M1_PRIME_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739a47f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba794c155ced74cbdd5fc5d36db19b0a5835cca7e3";

// second test pair
        
//const M0_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9887b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a417125e82551089fc9cdf7f2bd1dd95b3c3780";
//const M1_HEX : &str = "313e82d85b8f3456d4ac6daec619c936b4e253ddfd03da8706633902a0cd48d242339fe9e87e570f70b654ce1e0da880bc2198c69383a8b62b65f996702af76f";
//const M0_PRIME_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9807b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a41f125e82551089fc9cdf772bd1dd95b3c3780";
//const M1_PRIME_HEX : &str = "313e82d85b8f3456d4ac6daec619c93634e253ddfd03da8706633902a0cd48d242339fe9e87e570f70b654ce1e0d2880bc2198c69383a8b6ab65f996702af76f";

//const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
//const M1_HEX : &str = "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70";
//const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
//const M1_PRIME_HEX : &str = "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70";

fn decode_hex_block(hex_str: &str) -> [u8; 64] {
    let mut buf = [0u8; 64];
    hex::decode_to_slice(hex_str, &mut buf).expect("Hex decoding failed");
    buf
}

pub fn modify_word_le(msg: &mut [u8], k: usize, delta: u32, add: bool) {
    // extract word
    let offset = k * 4;
    let mut word_bytes = [0u8; 4];
    word_bytes.copy_from_slice(&msg[offset..offset + 4]);
    let mut word = u32::from_le_bytes(word_bytes);

    // modify
    if add {
        word = word.wrapping_add(delta);
    } else {
        word = word.wrapping_sub(delta);
    }

    // write back
    msg[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
}

fn main() {
    let m0 = decode_hex_block(M0_HEX);
    //let m1 = decode_hex_block(M1_HEX);
    //let m0_prime_test = decode_hex_block(M0_PRIME_HEX);
    //let m1_prime_test = decode_hex_block(M1_PRIME_HEX);

    let mut block: BlockNumber;

    // first round (TODO)

    block = BlockNumber::First;

    let mut hasher = Md5Collider::new();
    hasher.compress_block(&m0);

    let mut m0_prime = m0.clone();
    modify_word_le(&mut m0_prime, 4, 1 << 31, true);
    modify_word_le(&mut m0_prime, 11, 1 << 15, true);
    modify_word_le(&mut m0_prime, 14, 1 << 31, true);

    // second round

    block = BlockNumber::Second;
    let state = hasher.get_state();

    let mut i: usize = 1;
    let mut next_stage = 1;

    loop {
        if i == next_stage {
            next_stage <<= 1;
            println!("computed hashes: {i}");
        }

        let m1 = gen_message(block.clone(), state);

        let mut round_hasher = hasher.clone();
        let result = round_hasher.verify(&m1, block.clone());

        match result {
            Some(k) => {
                //if k < 16 { panic!("Invalid differential path at operation {k}"); }
            },
            None => {
                let mut m1_prime = m1.clone();
                modify_word_le(&mut m1_prime, 4, 2 << 31, true);
                modify_word_le(&mut m1_prime, 11, 2 << 15, false);
                modify_word_le(&mut m1_prime, 14, 2 << 31, true);
                
                let digest = round_hasher.finalize_hex();
                let digest_prime = Md5Collider::new().hash_blocks(&m0_prime, &m1_prime);
                
                let m0_hex = hex::encode(m0);
                let m1_hex = hex::encode(m1);

                if digest == digest_prime {
                    println!("collision found!\nm0 = {}\nm1 = {}", m0_hex, m1_hex);
                    break;
                } else {
                    println!("met conditions, but NO collision\nm0 = {}\nm1 = {}", m0_hex, m1_hex);
                }
            },
        }

        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_equality_1() {
        const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
        const M1_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739ac7f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba79cc155ced74cbdd5fc5d36db19b0ad835cca7e3";
        const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
        const M1_PRIME_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739a47f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba794c155ced74cbdd5fc5d36db19b0a5835cca7e3";
        const H_HEX: &str = "1f160396bf9d0fa3bcff659fefc71ff4";

        let m0 = decode_hex_block(M0_HEX);
        let m1 = decode_hex_block(M1_HEX);
        let mut hasher = Md5Collider::new();
        assert_eq!(hasher.hash_blocks(&m0, &m1), H_HEX);
        
        let m0_prime = decode_hex_block(M0_PRIME_HEX);
        let m1_prime = decode_hex_block(M1_PRIME_HEX);
        let mut hasher = Md5Collider::new();
        assert_eq!(hasher.hash_blocks(&m0_prime, &m1_prime), H_HEX);
    }

    #[test]
    fn test_hash_equality_2() {
        const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
        const M1_HEX : &str = "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70";
        const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
        const M1_PRIME_HEX : &str = "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70";
        const H_HEX: &str = "19705e8d084e8061586b5d7115c02463";

        let m0 = decode_hex_block(M0_HEX);
        let m1 = decode_hex_block(M1_HEX);
        let mut hasher = Md5Collider::new();
        assert_eq!(hasher.hash_blocks(&m0, &m1), H_HEX);
        
        let m0_prime = decode_hex_block(M0_PRIME_HEX);
        let m1_prime = decode_hex_block(M1_PRIME_HEX);
        let mut hasher = Md5Collider::new();
        assert_eq!(hasher.hash_blocks(&m0_prime, &m1_prime), H_HEX);
    }

    #[test]
    fn test_collision() {
        const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
        const M1_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739ac7f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba79cc155ced74cbdd5fc5d36db19b0ad835cca7e3";
        const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
        const M1_PRIME_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739a47f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba794c155ced74cbdd5fc5d36db19b0a5835cca7e3";

        let m0 = decode_hex_block(M0_HEX);
        let m0_prime_test = decode_hex_block(M0_PRIME_HEX);
        let mut m0_prime = m0.clone();

        modify_word_le(&mut m0_prime, 4, 1 << 31, true);
        modify_word_le(&mut m0_prime, 11, 1 << 15, true);
        modify_word_le(&mut m0_prime, 14, 1 << 31, true);
        assert_eq!(m0_prime, m0_prime_test);
        
        let m1 = decode_hex_block(M1_HEX);
        let m1_prime_test = decode_hex_block(M1_PRIME_HEX);
        let mut m1_prime = m1.clone();

        modify_word_le(&mut m1_prime, 4, 1 << 31, true);
        modify_word_le(&mut m1_prime, 11, 1 << 15, false);
        modify_word_le(&mut m1_prime, 14, 1 << 31, true);
        assert_eq!(m1_prime, m1_prime_test);

        let mut hasher = Md5Collider::new();
        hasher.compress_block(&m0);
        let result = hasher.verify(&m1, BlockNumber::Second);
        assert_eq!(result, None);

        let digest = hasher.finalize_hex();
        let digest_prime = Md5Collider::new().hash_blocks(&m0_prime, &m1_prime);
        assert_eq!(digest, digest_prime)
    }
}
