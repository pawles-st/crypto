pub(crate) const STATE_INIT: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

pub(crate) static RC: [u32; 64] = [
    // round 1
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    // round 2
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    // round 3
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    // round 4
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

pub(crate) const A1_ONE_BITS: u32 = 0x84200000;
pub(crate) const A1_ZERO_BITS: u32 = 0x0A000820;
pub(crate) const D1_ONE_BITS: u32 = 0x8C000800;
pub(crate) const D1_ZERO_BITS: u32 = 0x02208026;
pub(crate) const D1_A1_SAME_BITS: u32 = 0x701F10C0;
pub(crate) const C1_ONE_BITS: u32 = 0xBE1F0966;
pub(crate) const C1_ZERO_BITS: u32 = 0x40201080;
pub(crate) const C1_D1_SAME_BITS: u32 = 0x00000018;
pub(crate) const B1_ONE_BITS: u32 = 0xBA040010;
pub(crate) const B1_ZERO_BITS: u32 = 0x443B19EE;
pub(crate) const B1_C1_SAME_BITS: u32 = 0x00000601;

pub(crate) const A2_ONE_BITS: u32 = 0x482F0E50;
pub(crate) const A2_ZERO_BITS: u32 = 0xB41011AF;
pub(crate) const D2_ONE_BITS: u32 = 0x04220C56;
pub(crate) const D2_ZERO_BITS: u32 = 0x9A1113A9;
pub(crate) const C2_ONE_BITS: u32 = 0x96011E01;
pub(crate) const C2_ZERO_BITS: u32 = 0x083201C0;
pub(crate) const C2_D2_SAME_BITS: u32 = 0x01808000;
pub(crate) const B2_ONE_BITS: u32 = 0x843283C0;
pub(crate) const B2_ZERO_BITS: u32 = 0x1B810001;
pub(crate) const B2_C2_SAME_BITS: u32 = 0x00000002;

pub(crate) const A3_ONE_BITS: u32 = 0x9C0101C1;
pub(crate) const A3_ZERO_BITS: u32 = 0x03828202;
pub(crate) const A3_B2_SAME_BITS: u32 = 0x00001000;
pub(crate) const D3_ONE_BITS: u32 = 0x878383C0;
pub(crate) const D3_ZERO_BITS: u32 = 0x00041003;
pub(crate) const C3_ONE_BITS: u32 = 0x800583C3;
pub(crate) const C3_ZERO_BITS: u32 = 0x00021000;
pub(crate) const C3_D3_SAME_BITS: u32 = 0x00086000;
pub(crate) const B3_ONE_BITS: u32 = 0x80081080;
pub(crate) const B3_ZERO_BITS: u32 = 0x0007E000;
pub(crate) const B3_C3_SAME_BITS: u32 = 0x7F000000;

pub(crate) const A4_ONE_BITS: u32 = 0x3F0FE008;
pub(crate) const A4_ZERO_BITS: u32 = 0xC0000080;
pub(crate) const D4_ONE_BITS: u32 = 0x400BE088;
pub(crate) const D4_ZERO_BITS: u32 = 0xBF040000;
pub(crate) const C4_ONE_BITS: u32 = 0x7D000000;
pub(crate) const C4_ZERO_BITS: u32 = 0x82008008;
pub(crate) const B4_ONE_BITS: u32 = 0x20000000;
pub(crate) const B4_ZERO_BITS: u32 = 0x80000000;

pub(crate) const A5_ZERO_BITS: u32 = 0x80020000;
pub(crate) const A5_B4_SAME_BITS: u32 = 0x00008008;
pub(crate) const D5_ONE_BITS: u32 = 0x00020000;
pub(crate) const D5_ZERO_BITS: u32 = 0x80000000;
pub(crate) const D5_A5_SAME_BITS: u32 = 0x20000000;
pub(crate) const C5_ZERO_BITS: u32 = 0x80020000;
pub(crate) const B5_ZERO_BITS: u32 = 0x80000000;

pub(crate) const A6_ZERO_BITS: u32 = 0x80000000;
pub(crate) const A6_B5_SAME_BITS: u32 = 0x00020000;
pub(crate) const D6_ZERO_BITS: u32 = 0x80000000;
pub(crate) const C6_ZERO_BITS: u32 = 0x80000000;
pub(crate) const B6_C6_DIFFERENT_BITS: u32 = 0x80000000;

pub(crate) const B12_D12_SAME_BITS: u32 = 0x80000000;

pub(crate) const A13_C12_SAME_BITS: u32 = 0x80000000;
pub(crate) const D13_B12_DIFFERENT_BITS: u32 = 0x80000000;
pub(crate) const C13_A13_SAME_BITS: u32 = 0x80000000;
pub(crate) const B13_D13_SAME_BITS: u32 = 0x80000000;

pub(crate) const A14_C13_SAME_BITS: u32 = 0x80000000;
pub(crate) const D14_B13_SAME_BITS: u32 = 0x80000000;
pub(crate) const C14_A14_SAME_BITS: u32 = 0x80000000;
pub(crate) const B14_D14_SAME_BITS: u32 = 0x80000000;

pub(crate) const A15_C14_SAME_BITS: u32 = 0x80000000;
pub(crate) const D15_B14_SAME_BITS: u32 = 0x80000000;
pub(crate) const C15_A15_SAME_BITS: u32 = 0x80000000;
pub(crate) const B15_D15_DIFFERENT_BITS: u32 = 0x80000000;

pub(crate) const A16_ONE_BITS: u32 = 0x02000000;
pub(crate) const A16_C15_SAME_BITS: u32 = 0x80000000;
pub(crate) const D16_ONE_BITS: u32 = 0x02000000;
pub(crate) const D16_B15_SAME_BITS: u32 = 0x80000000;
