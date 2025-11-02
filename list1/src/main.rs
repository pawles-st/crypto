use md5::{Md5, Digest};
use rand::RngCore;

const M0_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9887b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a417125e82551089fc9cdf7f2bd1dd95b3c3780";
const M1_HEX : &str = "d11d0b969c7b41dcf497d8e4d555655ac79a73350cfdebf066f129308fb109d1797f2775eb5cd530baade8225c15cc79ddcb74ed6dd3c55fd80a9bb1e3a7cc35";
const M0_PRIME_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9807b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a41f125e82551089fc9cdf772bd1dd95b3c3780";
const M1_PRIME_HEX : &str = "d11d0b969c7b41dcf497d8e4d555655a479a73350cfdebf066f129308fb109d1797f2775eb5cd530baade8225c154c79ddcb74ed6dd3c55f580a9bb1e3a7cc35";

//const H_STAR_HEX: &str = "a4c0d35c95a63a805915367dcfe6b751";

//const M0_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9887b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a417125e82551089fc9cdf7f2bd1dd95b3c3780";
//const M1_HEX : &str = "313e82d85b8f3456d4ac6daec619c936b4e253ddfd03da8706633902a0cd48d242339fe9e87e570f70b654ce1e0da880bc2198c69383a8b62b65f996702af76f";
//const M0_PRIME_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9807b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a41f125e82551089fc9cdf772bd1dd95b3c3780";
//const M1_PRIME_HEX : &str = "313e82d85b8f3456d4ac6daec619c93634e253ddfd03da8706633902a0cd48d242339fe9e87e570f70b654ce1e0d2880bc2198c69383a8b6ab65f996702af76f";

//const H_HEX: &str = "8d5e701961804e08715d6b586324c015";
//const H_STAR_HEX: &str = "79054025255fb1a26e4bc422aef54eb4";

struct HexSlice<'a>(&'a [u8]);

impl std::fmt::LowerHex for HexSlice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

fn check_collision(m0: &[u8], m1: &[u8], m0_prime: &[u8], m1_prime: &[u8]) -> bool {
    let digest = hash(m0, m1);
    let digest_prime = hash(m0_prime, m1_prime);

    digest == digest_prime
}

fn hash(m0: &[u8], m1: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(m0);
    hasher.update(m1);
    let digest = hasher.finalize();
    format!("{:x}", HexSlice(&digest))
}

fn main() {
    let m0 = hex::decode(M0_HEX).unwrap();
    let m1 = hex::decode(M1_HEX).unwrap();
    let m0_prime = hex::decode(M0_PRIME_HEX).unwrap();
    let m1_prime = hex::decode(M1_PRIME_HEX).unwrap();

    match check_collision(&m0, &m1, &m0_prime, &m1_prime) {
        true => println!("collision found!"),
        false => println!(":("),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_equality_1() {
        const M0_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9887b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a417125e82551089fc9cdf7f2bd1dd95b3c3780";
        const M1_HEX : &str = "d11d0b969c7b41dcf497d8e4d555655ac79a73350cfdebf066f129308fb109d1797f2775eb5cd530baade8225c15cc79ddcb74ed6dd3c55fd80a9bb1e3a7cc35";
        const M0_PRIME_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9807b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a41f125e82551089fc9cdf772bd1dd95b3c3780";
        const M1_PRIME_HEX : &str = "d11d0b969c7b41dcf497d8e4d555655a479a73350cfdebf066f129308fb109d1797f2775eb5cd530baade8225c154c79ddcb74ed6dd3c55f580a9bb1e3a7cc35";
        const H_HEX: &str = "9603161fa30f9dbf9f65ffbcf41fc7ef";

        let m0 = hex::decode(M0_HEX).unwrap();
        let m1 = hex::decode(M1_HEX).unwrap();
        assert_eq!(hash(&m0, &m1), H_HEX);
        
        let m0_prime = hex::decode(M0_PRIME_HEX).unwrap();
        let m1_prime = hex::decode(M1_PRIME_HEX).unwrap();
        assert_eq!(hash(&m0_prime, &m1_prime), H_HEX);
    }

    #[test]
    fn test_hash_equality_2() {
        const M0_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9887b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a417125e82551089fc9cdf7f2bd1dd95b3c3780";
        const M1_HEX : &str = "313e82d85b8f3456d4ac6daec619c936b4e253ddfd03da8706633902a0cd48d242339fe9e87e570f70b654ce1e0da880bc2198c69383a8b62b65f996702af76f";
        const M0_PRIME_HEX : &str = "02dd31d1c4eee6c5069a3d695cf9af9807b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a41f125e82551089fc9cdf772bd1dd95b3c3780";
        const M1_PRIME_HEX : &str = "313e82d85b8f3456d4ac6daec619c93634e253ddfd03da8706633902a0cd48d242339fe9e87e570f70b654ce1e0d2880bc2198c69383a8b6ab65f996702af76f";
        const H_HEX: &str = "8d5e701961804e08715d6b586324c015";

        let m0 = hex::decode(M0_HEX).unwrap();
        let m1 = hex::decode(M1_HEX).unwrap();
        assert_eq!(hash(&m0, &m1), H_HEX);
        
        let m0_prime = hex::decode(M0_PRIME_HEX).unwrap();
        let m1_prime = hex::decode(M1_PRIME_HEX).unwrap();
        assert_eq!(hash(&m0_prime, &m1_prime), H_HEX);
    }
}
