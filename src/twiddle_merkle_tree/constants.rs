pub const TWIDDLE_MERKLE_TREE_ROOT_12: [u8; 32] = [
    249, 145, 180, 224, 61, 120, 220, 4, 111, 108, 202, 88, 205, 230, 50, 56, 142, 218, 146, 215,
    47, 74, 219, 54, 186, 118, 106, 216, 0, 220, 101, 18,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_13: [u8; 32] = [
    50, 118, 30, 123, 43, 80, 130, 23, 79, 231, 150, 82, 85, 56, 246, 31, 102, 44, 219, 115, 122,
    130, 178, 51, 204, 37, 133, 108, 60, 143, 141, 153,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_14: [u8; 32] = [
    42, 57, 90, 15, 137, 75, 29, 13, 249, 8, 73, 112, 3, 239, 90, 230, 178, 68, 171, 78, 55, 140,
    60, 20, 7, 246, 83, 65, 67, 153, 193, 80,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_15: [u8; 32] = [
    106, 156, 233, 20, 145, 172, 214, 42, 138, 41, 164, 166, 197, 90, 26, 19, 188, 29, 29, 249,
    251, 145, 181, 88, 65, 232, 150, 50, 209, 52, 20, 218,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_16: [u8; 32] = [
    241, 185, 61, 195, 113, 134, 47, 151, 100, 27, 116, 129, 164, 133, 165, 147, 68, 207, 91, 241,
    240, 66, 236, 152, 189, 188, 101, 208, 74, 189, 106, 105,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_17: [u8; 32] = [
    184, 23, 66, 6, 75, 223, 119, 70, 150, 138, 102, 191, 150, 48, 210, 174, 181, 204, 211, 99,
    204, 243, 65, 13, 96, 127, 38, 89, 88, 1, 88, 207,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_18: [u8; 32] = [
    103, 62, 237, 73, 10, 204, 193, 86, 86, 248, 129, 94, 23, 251, 224, 146, 33, 94, 21, 208, 56,
    65, 159, 145, 2, 63, 135, 15, 169, 221, 152, 35,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_19: [u8; 32] = [
    6, 219, 139, 255, 4, 123, 53, 89, 180, 13, 10, 242, 197, 73, 14, 70, 185, 122, 233, 198, 184,
    25, 66, 15, 220, 165, 3, 42, 200, 208, 241, 245,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_20: [u8; 32] = [
    242, 127, 169, 89, 12, 65, 100, 155, 77, 253, 159, 74, 28, 47, 245, 84, 23, 70, 24, 167, 131,
    147, 45, 244, 45, 90, 5, 185, 162, 122, 236, 10,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_21: [u8; 32] = [
    252, 99, 175, 224, 104, 143, 156, 3, 223, 106, 219, 203, 196, 29, 84, 246, 159, 85, 130, 239,
    177, 53, 115, 98, 248, 246, 180, 45, 37, 34, 149, 218,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_22: [u8; 32] = [
    169, 45, 10, 162, 124, 238, 196, 20, 199, 85, 199, 35, 96, 202, 89, 76, 202, 196, 21, 178, 133,
    116, 3, 184, 136, 46, 217, 186, 148, 155, 56, 28,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_23: [u8; 32] = [
    47, 136, 175, 48, 147, 133, 170, 151, 83, 167, 173, 60, 194, 221, 107, 69, 28, 78, 109, 59,
    104, 1, 17, 101, 145, 29, 82, 175, 60, 47, 221, 61,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_24: [u8; 32] = [
    8, 29, 224, 172, 171, 136, 4, 102, 42, 164, 194, 168, 174, 121, 236, 233, 78, 168, 142, 81,
    166, 141, 135, 158, 185, 219, 75, 10, 115, 231, 155, 103,
];
pub const TWIDDLE_MERKLE_TREE_ROOT_25: [u8; 32] = [
    213, 190, 83, 110, 196, 85, 149, 7, 207, 235, 48, 227, 49, 255, 47, 125, 160, 118, 49, 166, 34,
    39, 46, 248, 250, 229, 134, 125, 20, 195, 49, 23,
];
#[cfg(test)]
mod test {
    use crate::twiddle_merkle_tree::*;

    #[test]
    fn test_consistency() {
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
