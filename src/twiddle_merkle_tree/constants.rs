pub const TWIDDLE_MERKLE_TREE_ROOT_4: [u8; 32] = [
    68, 99, 23, 17, 186, 171, 158, 147, 45, 104, 108, 83, 97, 171, 105, 211, 223, 48, 221, 55, 91,
    63, 43, 54, 127, 66, 190, 60, 72, 127, 6, 185,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_12: [u8; 32] = [
    60, 155, 212, 134, 236, 182, 124, 57, 217, 239, 198, 204, 156, 60, 81, 164, 196, 218, 205, 85,
    113, 213, 12, 210, 2, 30, 141, 114, 195, 117, 96, 144,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_13: [u8; 32] = [
    225, 92, 250, 80, 60, 170, 150, 237, 134, 131, 175, 243, 31, 79, 48, 103, 248, 136, 130, 11,
    174, 123, 233, 13, 16, 95, 171, 24, 155, 130, 120, 54,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_14: [u8; 32] = [
    115, 138, 131, 120, 145, 148, 106, 16, 172, 153, 230, 69, 246, 42, 111, 105, 212, 44, 73, 110,
    103, 200, 38, 218, 119, 146, 102, 203, 61, 64, 139, 106,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_15: [u8; 32] = [
    70, 237, 26, 143, 164, 107, 99, 177, 251, 89, 26, 22, 205, 131, 167, 7, 240, 2, 208, 97, 45,
    120, 168, 41, 47, 180, 252, 102, 169, 188, 3, 55,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_16: [u8; 32] = [
    199, 112, 28, 163, 253, 246, 103, 220, 134, 243, 98, 16, 50, 146, 159, 245, 203, 3, 226, 1, 44,
    64, 199, 220, 174, 191, 180, 220, 87, 99, 185, 227,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_17: [u8; 32] = [
    122, 58, 37, 234, 82, 65, 223, 174, 22, 162, 19, 8, 92, 253, 79, 199, 121, 27, 224, 20, 179,
    86, 127, 36, 23, 113, 49, 201, 159, 58, 199, 242,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_18: [u8; 32] = [
    13, 85, 144, 6, 6, 69, 159, 5, 51, 160, 15, 202, 131, 174, 198, 66, 98, 92, 38, 65, 160, 66,
    76, 118, 63, 138, 129, 61, 245, 42, 121, 204,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_19: [u8; 32] = [
    180, 134, 96, 23, 76, 99, 98, 241, 223, 48, 182, 51, 251, 176, 100, 222, 159, 187, 8, 221, 161,
    82, 164, 208, 77, 99, 147, 123, 240, 206, 49, 195,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_20: [u8; 32] = [
    3, 187, 70, 20, 172, 65, 242, 17, 15, 138, 177, 65, 69, 95, 30, 210, 8, 16, 154, 231, 155, 30,
    2, 186, 169, 52, 167, 168, 121, 210, 66, 173,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_21: [u8; 32] = [
    89, 127, 110, 4, 20, 141, 92, 21, 104, 126, 147, 60, 250, 215, 229, 17, 236, 51, 106, 76, 33,
    224, 75, 143, 142, 213, 97, 169, 114, 30, 232, 238,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_22: [u8; 32] = [
    80, 14, 160, 19, 61, 82, 31, 134, 128, 34, 253, 35, 103, 216, 4, 66, 0, 68, 122, 84, 1, 79, 15,
    211, 30, 208, 114, 249, 79, 43, 60, 199,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_23: [u8; 32] = [
    169, 236, 100, 111, 47, 181, 193, 18, 37, 218, 83, 71, 19, 178, 91, 56, 88, 167, 86, 250, 192,
    52, 18, 81, 206, 45, 127, 228, 114, 224, 172, 117,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_24: [u8; 32] = [
    46, 195, 230, 26, 99, 167, 71, 110, 148, 8, 193, 210, 66, 54, 120, 179, 115, 96, 123, 142, 7,
    131, 241, 17, 114, 183, 244, 218, 190, 129, 174, 146,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_25: [u8; 32] = [
    79, 28, 164, 162, 150, 139, 139, 219, 54, 72, 168, 165, 131, 233, 235, 183, 217, 243, 126, 251,
    251, 231, 226, 146, 223, 238, 153, 161, 33, 156, 81, 105,
];
#[cfg(test)]
mod test {
    use crate::twiddle_merkle_tree::*;

    #[test]
    fn test_consistency() {
        // for the testing
        assert_eq!(
            TwiddleMerkleTree::new(4).root_hash,
            TWIDDLE_MERKLE_TREE_ROOT_4
        );

        // unit tests are running until 18.

        assert_eq!(
            TwiddleMerkleTree::new(12).root_hash,
            TWIDDLE_MERKLE_TREE_ROOT_12
        );
        assert_eq!(
            TwiddleMerkleTree::new(13).root_hash,
            TWIDDLE_MERKLE_TREE_ROOT_13
        );
        assert_eq!(
            TwiddleMerkleTree::new(14).root_hash,
            TWIDDLE_MERKLE_TREE_ROOT_14
        );
        assert_eq!(
            TwiddleMerkleTree::new(15).root_hash,
            TWIDDLE_MERKLE_TREE_ROOT_15
        );
        assert_eq!(
            TwiddleMerkleTree::new(16).root_hash,
            TWIDDLE_MERKLE_TREE_ROOT_16
        );
        assert_eq!(
            TwiddleMerkleTree::new(17).root_hash,
            TWIDDLE_MERKLE_TREE_ROOT_17
        );
        assert_eq!(
            TwiddleMerkleTree::new(18).root_hash,
            TWIDDLE_MERKLE_TREE_ROOT_18
        );
    }
}
