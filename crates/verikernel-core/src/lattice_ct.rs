//! Fixed-schedule ML-DSA ring arithmetic. Complexity: O(256 log 256) transform work.
//! Inputs are valid nonaliasing 256-coefficient allocations; inverse input is bounded by Q.
/// Prime ring modulus; O(1) storage.
pub const Q: i32 = 8380417;
/// Montgomery inverse modulo 2^32; O(1) storage.
pub const QINV: i32 = 58728449;
/// Montgomery squared factor; O(1) storage.
pub const MONT_R2: i32 = 2365951;
/// Inverse transform scaling factor; O(1) storage.
pub const MONT_F: i32 = 41978;
/// Bit-reversed powers of 1753, centered Montgomery representation; O(256) storage.
pub const ZETAS: [i32; 256] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

macro_rules! reduce {
    ($value:expr) => {{
        let a = $value;
        let t = (a as i32).wrapping_mul(QINV) as i64;
        (a.wrapping_sub(t * Q as i64) >> 32) as i32
    }};
}
/// Montgomery reduction for FIPS-bounded products; O(1) time and space.
#[no_mangle]
#[inline(never)]
pub extern "C" fn vk_montgomery_reduce_ct(a: i64) -> i32 {
    reduce!(a)
}
/// Conditional addition for inputs in [-Q,Q); O(1) time and space.
#[no_mangle]
#[inline(never)]
pub extern "C" fn vk_caddq_ct(a: i32) -> i32 {
    a.wrapping_add((a >> 31) & Q)
}
macro_rules! norm_coefficient {
    ($poly:expr, $index:expr, $bound:expr, $acc:ident) => {{
        let value = unsafe { core::ptr::read_volatile($poly.add($index)) };
        let mask = value >> 31;
        let magnitude = value.wrapping_sub(mask & value.wrapping_mul(2));
        $acc |= $bound.wrapping_sub(1).wrapping_sub(magnitude) >> 31;
    }};
}
/// Scan every centered coefficient without early exit; O(256) time, O(1) space.
#[no_mangle]
#[inline(never)]
pub extern "C" fn vk_poly_chknorm_ct(poly: *const i32, bound: i32) -> u32 {
    if poly.is_null() || bound <= 0 || bound > Q / 8 {
        return 1;
    }
    let mut acc: i32 = 0;
    norm_coefficient!(poly, 0, bound, acc);
    norm_coefficient!(poly, 1, bound, acc);
    norm_coefficient!(poly, 2, bound, acc);
    norm_coefficient!(poly, 3, bound, acc);
    norm_coefficient!(poly, 4, bound, acc);
    norm_coefficient!(poly, 5, bound, acc);
    norm_coefficient!(poly, 6, bound, acc);
    norm_coefficient!(poly, 7, bound, acc);
    norm_coefficient!(poly, 8, bound, acc);
    norm_coefficient!(poly, 9, bound, acc);
    norm_coefficient!(poly, 10, bound, acc);
    norm_coefficient!(poly, 11, bound, acc);
    norm_coefficient!(poly, 12, bound, acc);
    norm_coefficient!(poly, 13, bound, acc);
    norm_coefficient!(poly, 14, bound, acc);
    norm_coefficient!(poly, 15, bound, acc);
    norm_coefficient!(poly, 16, bound, acc);
    norm_coefficient!(poly, 17, bound, acc);
    norm_coefficient!(poly, 18, bound, acc);
    norm_coefficient!(poly, 19, bound, acc);
    norm_coefficient!(poly, 20, bound, acc);
    norm_coefficient!(poly, 21, bound, acc);
    norm_coefficient!(poly, 22, bound, acc);
    norm_coefficient!(poly, 23, bound, acc);
    norm_coefficient!(poly, 24, bound, acc);
    norm_coefficient!(poly, 25, bound, acc);
    norm_coefficient!(poly, 26, bound, acc);
    norm_coefficient!(poly, 27, bound, acc);
    norm_coefficient!(poly, 28, bound, acc);
    norm_coefficient!(poly, 29, bound, acc);
    norm_coefficient!(poly, 30, bound, acc);
    norm_coefficient!(poly, 31, bound, acc);
    norm_coefficient!(poly, 32, bound, acc);
    norm_coefficient!(poly, 33, bound, acc);
    norm_coefficient!(poly, 34, bound, acc);
    norm_coefficient!(poly, 35, bound, acc);
    norm_coefficient!(poly, 36, bound, acc);
    norm_coefficient!(poly, 37, bound, acc);
    norm_coefficient!(poly, 38, bound, acc);
    norm_coefficient!(poly, 39, bound, acc);
    norm_coefficient!(poly, 40, bound, acc);
    norm_coefficient!(poly, 41, bound, acc);
    norm_coefficient!(poly, 42, bound, acc);
    norm_coefficient!(poly, 43, bound, acc);
    norm_coefficient!(poly, 44, bound, acc);
    norm_coefficient!(poly, 45, bound, acc);
    norm_coefficient!(poly, 46, bound, acc);
    norm_coefficient!(poly, 47, bound, acc);
    norm_coefficient!(poly, 48, bound, acc);
    norm_coefficient!(poly, 49, bound, acc);
    norm_coefficient!(poly, 50, bound, acc);
    norm_coefficient!(poly, 51, bound, acc);
    norm_coefficient!(poly, 52, bound, acc);
    norm_coefficient!(poly, 53, bound, acc);
    norm_coefficient!(poly, 54, bound, acc);
    norm_coefficient!(poly, 55, bound, acc);
    norm_coefficient!(poly, 56, bound, acc);
    norm_coefficient!(poly, 57, bound, acc);
    norm_coefficient!(poly, 58, bound, acc);
    norm_coefficient!(poly, 59, bound, acc);
    norm_coefficient!(poly, 60, bound, acc);
    norm_coefficient!(poly, 61, bound, acc);
    norm_coefficient!(poly, 62, bound, acc);
    norm_coefficient!(poly, 63, bound, acc);
    norm_coefficient!(poly, 64, bound, acc);
    norm_coefficient!(poly, 65, bound, acc);
    norm_coefficient!(poly, 66, bound, acc);
    norm_coefficient!(poly, 67, bound, acc);
    norm_coefficient!(poly, 68, bound, acc);
    norm_coefficient!(poly, 69, bound, acc);
    norm_coefficient!(poly, 70, bound, acc);
    norm_coefficient!(poly, 71, bound, acc);
    norm_coefficient!(poly, 72, bound, acc);
    norm_coefficient!(poly, 73, bound, acc);
    norm_coefficient!(poly, 74, bound, acc);
    norm_coefficient!(poly, 75, bound, acc);
    norm_coefficient!(poly, 76, bound, acc);
    norm_coefficient!(poly, 77, bound, acc);
    norm_coefficient!(poly, 78, bound, acc);
    norm_coefficient!(poly, 79, bound, acc);
    norm_coefficient!(poly, 80, bound, acc);
    norm_coefficient!(poly, 81, bound, acc);
    norm_coefficient!(poly, 82, bound, acc);
    norm_coefficient!(poly, 83, bound, acc);
    norm_coefficient!(poly, 84, bound, acc);
    norm_coefficient!(poly, 85, bound, acc);
    norm_coefficient!(poly, 86, bound, acc);
    norm_coefficient!(poly, 87, bound, acc);
    norm_coefficient!(poly, 88, bound, acc);
    norm_coefficient!(poly, 89, bound, acc);
    norm_coefficient!(poly, 90, bound, acc);
    norm_coefficient!(poly, 91, bound, acc);
    norm_coefficient!(poly, 92, bound, acc);
    norm_coefficient!(poly, 93, bound, acc);
    norm_coefficient!(poly, 94, bound, acc);
    norm_coefficient!(poly, 95, bound, acc);
    norm_coefficient!(poly, 96, bound, acc);
    norm_coefficient!(poly, 97, bound, acc);
    norm_coefficient!(poly, 98, bound, acc);
    norm_coefficient!(poly, 99, bound, acc);
    norm_coefficient!(poly, 100, bound, acc);
    norm_coefficient!(poly, 101, bound, acc);
    norm_coefficient!(poly, 102, bound, acc);
    norm_coefficient!(poly, 103, bound, acc);
    norm_coefficient!(poly, 104, bound, acc);
    norm_coefficient!(poly, 105, bound, acc);
    norm_coefficient!(poly, 106, bound, acc);
    norm_coefficient!(poly, 107, bound, acc);
    norm_coefficient!(poly, 108, bound, acc);
    norm_coefficient!(poly, 109, bound, acc);
    norm_coefficient!(poly, 110, bound, acc);
    norm_coefficient!(poly, 111, bound, acc);
    norm_coefficient!(poly, 112, bound, acc);
    norm_coefficient!(poly, 113, bound, acc);
    norm_coefficient!(poly, 114, bound, acc);
    norm_coefficient!(poly, 115, bound, acc);
    norm_coefficient!(poly, 116, bound, acc);
    norm_coefficient!(poly, 117, bound, acc);
    norm_coefficient!(poly, 118, bound, acc);
    norm_coefficient!(poly, 119, bound, acc);
    norm_coefficient!(poly, 120, bound, acc);
    norm_coefficient!(poly, 121, bound, acc);
    norm_coefficient!(poly, 122, bound, acc);
    norm_coefficient!(poly, 123, bound, acc);
    norm_coefficient!(poly, 124, bound, acc);
    norm_coefficient!(poly, 125, bound, acc);
    norm_coefficient!(poly, 126, bound, acc);
    norm_coefficient!(poly, 127, bound, acc);
    norm_coefficient!(poly, 128, bound, acc);
    norm_coefficient!(poly, 129, bound, acc);
    norm_coefficient!(poly, 130, bound, acc);
    norm_coefficient!(poly, 131, bound, acc);
    norm_coefficient!(poly, 132, bound, acc);
    norm_coefficient!(poly, 133, bound, acc);
    norm_coefficient!(poly, 134, bound, acc);
    norm_coefficient!(poly, 135, bound, acc);
    norm_coefficient!(poly, 136, bound, acc);
    norm_coefficient!(poly, 137, bound, acc);
    norm_coefficient!(poly, 138, bound, acc);
    norm_coefficient!(poly, 139, bound, acc);
    norm_coefficient!(poly, 140, bound, acc);
    norm_coefficient!(poly, 141, bound, acc);
    norm_coefficient!(poly, 142, bound, acc);
    norm_coefficient!(poly, 143, bound, acc);
    norm_coefficient!(poly, 144, bound, acc);
    norm_coefficient!(poly, 145, bound, acc);
    norm_coefficient!(poly, 146, bound, acc);
    norm_coefficient!(poly, 147, bound, acc);
    norm_coefficient!(poly, 148, bound, acc);
    norm_coefficient!(poly, 149, bound, acc);
    norm_coefficient!(poly, 150, bound, acc);
    norm_coefficient!(poly, 151, bound, acc);
    norm_coefficient!(poly, 152, bound, acc);
    norm_coefficient!(poly, 153, bound, acc);
    norm_coefficient!(poly, 154, bound, acc);
    norm_coefficient!(poly, 155, bound, acc);
    norm_coefficient!(poly, 156, bound, acc);
    norm_coefficient!(poly, 157, bound, acc);
    norm_coefficient!(poly, 158, bound, acc);
    norm_coefficient!(poly, 159, bound, acc);
    norm_coefficient!(poly, 160, bound, acc);
    norm_coefficient!(poly, 161, bound, acc);
    norm_coefficient!(poly, 162, bound, acc);
    norm_coefficient!(poly, 163, bound, acc);
    norm_coefficient!(poly, 164, bound, acc);
    norm_coefficient!(poly, 165, bound, acc);
    norm_coefficient!(poly, 166, bound, acc);
    norm_coefficient!(poly, 167, bound, acc);
    norm_coefficient!(poly, 168, bound, acc);
    norm_coefficient!(poly, 169, bound, acc);
    norm_coefficient!(poly, 170, bound, acc);
    norm_coefficient!(poly, 171, bound, acc);
    norm_coefficient!(poly, 172, bound, acc);
    norm_coefficient!(poly, 173, bound, acc);
    norm_coefficient!(poly, 174, bound, acc);
    norm_coefficient!(poly, 175, bound, acc);
    norm_coefficient!(poly, 176, bound, acc);
    norm_coefficient!(poly, 177, bound, acc);
    norm_coefficient!(poly, 178, bound, acc);
    norm_coefficient!(poly, 179, bound, acc);
    norm_coefficient!(poly, 180, bound, acc);
    norm_coefficient!(poly, 181, bound, acc);
    norm_coefficient!(poly, 182, bound, acc);
    norm_coefficient!(poly, 183, bound, acc);
    norm_coefficient!(poly, 184, bound, acc);
    norm_coefficient!(poly, 185, bound, acc);
    norm_coefficient!(poly, 186, bound, acc);
    norm_coefficient!(poly, 187, bound, acc);
    norm_coefficient!(poly, 188, bound, acc);
    norm_coefficient!(poly, 189, bound, acc);
    norm_coefficient!(poly, 190, bound, acc);
    norm_coefficient!(poly, 191, bound, acc);
    norm_coefficient!(poly, 192, bound, acc);
    norm_coefficient!(poly, 193, bound, acc);
    norm_coefficient!(poly, 194, bound, acc);
    norm_coefficient!(poly, 195, bound, acc);
    norm_coefficient!(poly, 196, bound, acc);
    norm_coefficient!(poly, 197, bound, acc);
    norm_coefficient!(poly, 198, bound, acc);
    norm_coefficient!(poly, 199, bound, acc);
    norm_coefficient!(poly, 200, bound, acc);
    norm_coefficient!(poly, 201, bound, acc);
    norm_coefficient!(poly, 202, bound, acc);
    norm_coefficient!(poly, 203, bound, acc);
    norm_coefficient!(poly, 204, bound, acc);
    norm_coefficient!(poly, 205, bound, acc);
    norm_coefficient!(poly, 206, bound, acc);
    norm_coefficient!(poly, 207, bound, acc);
    norm_coefficient!(poly, 208, bound, acc);
    norm_coefficient!(poly, 209, bound, acc);
    norm_coefficient!(poly, 210, bound, acc);
    norm_coefficient!(poly, 211, bound, acc);
    norm_coefficient!(poly, 212, bound, acc);
    norm_coefficient!(poly, 213, bound, acc);
    norm_coefficient!(poly, 214, bound, acc);
    norm_coefficient!(poly, 215, bound, acc);
    norm_coefficient!(poly, 216, bound, acc);
    norm_coefficient!(poly, 217, bound, acc);
    norm_coefficient!(poly, 218, bound, acc);
    norm_coefficient!(poly, 219, bound, acc);
    norm_coefficient!(poly, 220, bound, acc);
    norm_coefficient!(poly, 221, bound, acc);
    norm_coefficient!(poly, 222, bound, acc);
    norm_coefficient!(poly, 223, bound, acc);
    norm_coefficient!(poly, 224, bound, acc);
    norm_coefficient!(poly, 225, bound, acc);
    norm_coefficient!(poly, 226, bound, acc);
    norm_coefficient!(poly, 227, bound, acc);
    norm_coefficient!(poly, 228, bound, acc);
    norm_coefficient!(poly, 229, bound, acc);
    norm_coefficient!(poly, 230, bound, acc);
    norm_coefficient!(poly, 231, bound, acc);
    norm_coefficient!(poly, 232, bound, acc);
    norm_coefficient!(poly, 233, bound, acc);
    norm_coefficient!(poly, 234, bound, acc);
    norm_coefficient!(poly, 235, bound, acc);
    norm_coefficient!(poly, 236, bound, acc);
    norm_coefficient!(poly, 237, bound, acc);
    norm_coefficient!(poly, 238, bound, acc);
    norm_coefficient!(poly, 239, bound, acc);
    norm_coefficient!(poly, 240, bound, acc);
    norm_coefficient!(poly, 241, bound, acc);
    norm_coefficient!(poly, 242, bound, acc);
    norm_coefficient!(poly, 243, bound, acc);
    norm_coefficient!(poly, 244, bound, acc);
    norm_coefficient!(poly, 245, bound, acc);
    norm_coefficient!(poly, 246, bound, acc);
    norm_coefficient!(poly, 247, bound, acc);
    norm_coefficient!(poly, 248, bound, acc);
    norm_coefficient!(poly, 249, bound, acc);
    norm_coefficient!(poly, 250, bound, acc);
    norm_coefficient!(poly, 251, bound, acc);
    norm_coefficient!(poly, 252, bound, acc);
    norm_coefficient!(poly, 253, bound, acc);
    norm_coefficient!(poly, 254, bound, acc);
    norm_coefficient!(poly, 255, bound, acc);
    (acc as u32) & 1
}
macro_rules! forward_butterfly {
    ($p:expr, $j:expr, $other:expr, $z:expr) => {{
        let a = unsafe { core::ptr::read($p.add($j)) };
        let b = unsafe { core::ptr::read($p.add($other)) };
        let t = reduce!(ZETAS[$z] as i64 * b as i64);
        unsafe {
            core::ptr::write($p.add($j), a.wrapping_add(t));
            core::ptr::write($p.add($other), a.wrapping_sub(t));
        }
    }};
}
macro_rules! inverse_butterfly {
    ($p:expr, $j:expr, $other:expr, $z:expr) => {{
        let a = unsafe { core::ptr::read($p.add($j)) };
        let b = unsafe { core::ptr::read($p.add($other)) };
        let t = reduce!(-(ZETAS[$z] as i64) * a.wrapping_sub(b) as i64);
        unsafe {
            core::ptr::write($p.add($j), a.wrapping_add(b));
            core::ptr::write($p.add($other), t);
        }
    }};
}
/// Eight fixed forward levels in bit-reversed order; O(256 log 256) time, O(1) workspace.
#[no_mangle]
#[inline(never)]
pub extern "C" fn vk_ntt_256_ct(poly: *mut i32) -> i32 {
    if poly.is_null() {
        return -1;
    }
    forward_butterfly!(poly, 0, 128, 1);
    forward_butterfly!(poly, 1, 129, 1);
    forward_butterfly!(poly, 2, 130, 1);
    forward_butterfly!(poly, 3, 131, 1);
    forward_butterfly!(poly, 4, 132, 1);
    forward_butterfly!(poly, 5, 133, 1);
    forward_butterfly!(poly, 6, 134, 1);
    forward_butterfly!(poly, 7, 135, 1);
    forward_butterfly!(poly, 8, 136, 1);
    forward_butterfly!(poly, 9, 137, 1);
    forward_butterfly!(poly, 10, 138, 1);
    forward_butterfly!(poly, 11, 139, 1);
    forward_butterfly!(poly, 12, 140, 1);
    forward_butterfly!(poly, 13, 141, 1);
    forward_butterfly!(poly, 14, 142, 1);
    forward_butterfly!(poly, 15, 143, 1);
    forward_butterfly!(poly, 16, 144, 1);
    forward_butterfly!(poly, 17, 145, 1);
    forward_butterfly!(poly, 18, 146, 1);
    forward_butterfly!(poly, 19, 147, 1);
    forward_butterfly!(poly, 20, 148, 1);
    forward_butterfly!(poly, 21, 149, 1);
    forward_butterfly!(poly, 22, 150, 1);
    forward_butterfly!(poly, 23, 151, 1);
    forward_butterfly!(poly, 24, 152, 1);
    forward_butterfly!(poly, 25, 153, 1);
    forward_butterfly!(poly, 26, 154, 1);
    forward_butterfly!(poly, 27, 155, 1);
    forward_butterfly!(poly, 28, 156, 1);
    forward_butterfly!(poly, 29, 157, 1);
    forward_butterfly!(poly, 30, 158, 1);
    forward_butterfly!(poly, 31, 159, 1);
    forward_butterfly!(poly, 32, 160, 1);
    forward_butterfly!(poly, 33, 161, 1);
    forward_butterfly!(poly, 34, 162, 1);
    forward_butterfly!(poly, 35, 163, 1);
    forward_butterfly!(poly, 36, 164, 1);
    forward_butterfly!(poly, 37, 165, 1);
    forward_butterfly!(poly, 38, 166, 1);
    forward_butterfly!(poly, 39, 167, 1);
    forward_butterfly!(poly, 40, 168, 1);
    forward_butterfly!(poly, 41, 169, 1);
    forward_butterfly!(poly, 42, 170, 1);
    forward_butterfly!(poly, 43, 171, 1);
    forward_butterfly!(poly, 44, 172, 1);
    forward_butterfly!(poly, 45, 173, 1);
    forward_butterfly!(poly, 46, 174, 1);
    forward_butterfly!(poly, 47, 175, 1);
    forward_butterfly!(poly, 48, 176, 1);
    forward_butterfly!(poly, 49, 177, 1);
    forward_butterfly!(poly, 50, 178, 1);
    forward_butterfly!(poly, 51, 179, 1);
    forward_butterfly!(poly, 52, 180, 1);
    forward_butterfly!(poly, 53, 181, 1);
    forward_butterfly!(poly, 54, 182, 1);
    forward_butterfly!(poly, 55, 183, 1);
    forward_butterfly!(poly, 56, 184, 1);
    forward_butterfly!(poly, 57, 185, 1);
    forward_butterfly!(poly, 58, 186, 1);
    forward_butterfly!(poly, 59, 187, 1);
    forward_butterfly!(poly, 60, 188, 1);
    forward_butterfly!(poly, 61, 189, 1);
    forward_butterfly!(poly, 62, 190, 1);
    forward_butterfly!(poly, 63, 191, 1);
    forward_butterfly!(poly, 64, 192, 1);
    forward_butterfly!(poly, 65, 193, 1);
    forward_butterfly!(poly, 66, 194, 1);
    forward_butterfly!(poly, 67, 195, 1);
    forward_butterfly!(poly, 68, 196, 1);
    forward_butterfly!(poly, 69, 197, 1);
    forward_butterfly!(poly, 70, 198, 1);
    forward_butterfly!(poly, 71, 199, 1);
    forward_butterfly!(poly, 72, 200, 1);
    forward_butterfly!(poly, 73, 201, 1);
    forward_butterfly!(poly, 74, 202, 1);
    forward_butterfly!(poly, 75, 203, 1);
    forward_butterfly!(poly, 76, 204, 1);
    forward_butterfly!(poly, 77, 205, 1);
    forward_butterfly!(poly, 78, 206, 1);
    forward_butterfly!(poly, 79, 207, 1);
    forward_butterfly!(poly, 80, 208, 1);
    forward_butterfly!(poly, 81, 209, 1);
    forward_butterfly!(poly, 82, 210, 1);
    forward_butterfly!(poly, 83, 211, 1);
    forward_butterfly!(poly, 84, 212, 1);
    forward_butterfly!(poly, 85, 213, 1);
    forward_butterfly!(poly, 86, 214, 1);
    forward_butterfly!(poly, 87, 215, 1);
    forward_butterfly!(poly, 88, 216, 1);
    forward_butterfly!(poly, 89, 217, 1);
    forward_butterfly!(poly, 90, 218, 1);
    forward_butterfly!(poly, 91, 219, 1);
    forward_butterfly!(poly, 92, 220, 1);
    forward_butterfly!(poly, 93, 221, 1);
    forward_butterfly!(poly, 94, 222, 1);
    forward_butterfly!(poly, 95, 223, 1);
    forward_butterfly!(poly, 96, 224, 1);
    forward_butterfly!(poly, 97, 225, 1);
    forward_butterfly!(poly, 98, 226, 1);
    forward_butterfly!(poly, 99, 227, 1);
    forward_butterfly!(poly, 100, 228, 1);
    forward_butterfly!(poly, 101, 229, 1);
    forward_butterfly!(poly, 102, 230, 1);
    forward_butterfly!(poly, 103, 231, 1);
    forward_butterfly!(poly, 104, 232, 1);
    forward_butterfly!(poly, 105, 233, 1);
    forward_butterfly!(poly, 106, 234, 1);
    forward_butterfly!(poly, 107, 235, 1);
    forward_butterfly!(poly, 108, 236, 1);
    forward_butterfly!(poly, 109, 237, 1);
    forward_butterfly!(poly, 110, 238, 1);
    forward_butterfly!(poly, 111, 239, 1);
    forward_butterfly!(poly, 112, 240, 1);
    forward_butterfly!(poly, 113, 241, 1);
    forward_butterfly!(poly, 114, 242, 1);
    forward_butterfly!(poly, 115, 243, 1);
    forward_butterfly!(poly, 116, 244, 1);
    forward_butterfly!(poly, 117, 245, 1);
    forward_butterfly!(poly, 118, 246, 1);
    forward_butterfly!(poly, 119, 247, 1);
    forward_butterfly!(poly, 120, 248, 1);
    forward_butterfly!(poly, 121, 249, 1);
    forward_butterfly!(poly, 122, 250, 1);
    forward_butterfly!(poly, 123, 251, 1);
    forward_butterfly!(poly, 124, 252, 1);
    forward_butterfly!(poly, 125, 253, 1);
    forward_butterfly!(poly, 126, 254, 1);
    forward_butterfly!(poly, 127, 255, 1);
    forward_butterfly!(poly, 0, 64, 2);
    forward_butterfly!(poly, 1, 65, 2);
    forward_butterfly!(poly, 2, 66, 2);
    forward_butterfly!(poly, 3, 67, 2);
    forward_butterfly!(poly, 4, 68, 2);
    forward_butterfly!(poly, 5, 69, 2);
    forward_butterfly!(poly, 6, 70, 2);
    forward_butterfly!(poly, 7, 71, 2);
    forward_butterfly!(poly, 8, 72, 2);
    forward_butterfly!(poly, 9, 73, 2);
    forward_butterfly!(poly, 10, 74, 2);
    forward_butterfly!(poly, 11, 75, 2);
    forward_butterfly!(poly, 12, 76, 2);
    forward_butterfly!(poly, 13, 77, 2);
    forward_butterfly!(poly, 14, 78, 2);
    forward_butterfly!(poly, 15, 79, 2);
    forward_butterfly!(poly, 16, 80, 2);
    forward_butterfly!(poly, 17, 81, 2);
    forward_butterfly!(poly, 18, 82, 2);
    forward_butterfly!(poly, 19, 83, 2);
    forward_butterfly!(poly, 20, 84, 2);
    forward_butterfly!(poly, 21, 85, 2);
    forward_butterfly!(poly, 22, 86, 2);
    forward_butterfly!(poly, 23, 87, 2);
    forward_butterfly!(poly, 24, 88, 2);
    forward_butterfly!(poly, 25, 89, 2);
    forward_butterfly!(poly, 26, 90, 2);
    forward_butterfly!(poly, 27, 91, 2);
    forward_butterfly!(poly, 28, 92, 2);
    forward_butterfly!(poly, 29, 93, 2);
    forward_butterfly!(poly, 30, 94, 2);
    forward_butterfly!(poly, 31, 95, 2);
    forward_butterfly!(poly, 32, 96, 2);
    forward_butterfly!(poly, 33, 97, 2);
    forward_butterfly!(poly, 34, 98, 2);
    forward_butterfly!(poly, 35, 99, 2);
    forward_butterfly!(poly, 36, 100, 2);
    forward_butterfly!(poly, 37, 101, 2);
    forward_butterfly!(poly, 38, 102, 2);
    forward_butterfly!(poly, 39, 103, 2);
    forward_butterfly!(poly, 40, 104, 2);
    forward_butterfly!(poly, 41, 105, 2);
    forward_butterfly!(poly, 42, 106, 2);
    forward_butterfly!(poly, 43, 107, 2);
    forward_butterfly!(poly, 44, 108, 2);
    forward_butterfly!(poly, 45, 109, 2);
    forward_butterfly!(poly, 46, 110, 2);
    forward_butterfly!(poly, 47, 111, 2);
    forward_butterfly!(poly, 48, 112, 2);
    forward_butterfly!(poly, 49, 113, 2);
    forward_butterfly!(poly, 50, 114, 2);
    forward_butterfly!(poly, 51, 115, 2);
    forward_butterfly!(poly, 52, 116, 2);
    forward_butterfly!(poly, 53, 117, 2);
    forward_butterfly!(poly, 54, 118, 2);
    forward_butterfly!(poly, 55, 119, 2);
    forward_butterfly!(poly, 56, 120, 2);
    forward_butterfly!(poly, 57, 121, 2);
    forward_butterfly!(poly, 58, 122, 2);
    forward_butterfly!(poly, 59, 123, 2);
    forward_butterfly!(poly, 60, 124, 2);
    forward_butterfly!(poly, 61, 125, 2);
    forward_butterfly!(poly, 62, 126, 2);
    forward_butterfly!(poly, 63, 127, 2);
    forward_butterfly!(poly, 128, 192, 3);
    forward_butterfly!(poly, 129, 193, 3);
    forward_butterfly!(poly, 130, 194, 3);
    forward_butterfly!(poly, 131, 195, 3);
    forward_butterfly!(poly, 132, 196, 3);
    forward_butterfly!(poly, 133, 197, 3);
    forward_butterfly!(poly, 134, 198, 3);
    forward_butterfly!(poly, 135, 199, 3);
    forward_butterfly!(poly, 136, 200, 3);
    forward_butterfly!(poly, 137, 201, 3);
    forward_butterfly!(poly, 138, 202, 3);
    forward_butterfly!(poly, 139, 203, 3);
    forward_butterfly!(poly, 140, 204, 3);
    forward_butterfly!(poly, 141, 205, 3);
    forward_butterfly!(poly, 142, 206, 3);
    forward_butterfly!(poly, 143, 207, 3);
    forward_butterfly!(poly, 144, 208, 3);
    forward_butterfly!(poly, 145, 209, 3);
    forward_butterfly!(poly, 146, 210, 3);
    forward_butterfly!(poly, 147, 211, 3);
    forward_butterfly!(poly, 148, 212, 3);
    forward_butterfly!(poly, 149, 213, 3);
    forward_butterfly!(poly, 150, 214, 3);
    forward_butterfly!(poly, 151, 215, 3);
    forward_butterfly!(poly, 152, 216, 3);
    forward_butterfly!(poly, 153, 217, 3);
    forward_butterfly!(poly, 154, 218, 3);
    forward_butterfly!(poly, 155, 219, 3);
    forward_butterfly!(poly, 156, 220, 3);
    forward_butterfly!(poly, 157, 221, 3);
    forward_butterfly!(poly, 158, 222, 3);
    forward_butterfly!(poly, 159, 223, 3);
    forward_butterfly!(poly, 160, 224, 3);
    forward_butterfly!(poly, 161, 225, 3);
    forward_butterfly!(poly, 162, 226, 3);
    forward_butterfly!(poly, 163, 227, 3);
    forward_butterfly!(poly, 164, 228, 3);
    forward_butterfly!(poly, 165, 229, 3);
    forward_butterfly!(poly, 166, 230, 3);
    forward_butterfly!(poly, 167, 231, 3);
    forward_butterfly!(poly, 168, 232, 3);
    forward_butterfly!(poly, 169, 233, 3);
    forward_butterfly!(poly, 170, 234, 3);
    forward_butterfly!(poly, 171, 235, 3);
    forward_butterfly!(poly, 172, 236, 3);
    forward_butterfly!(poly, 173, 237, 3);
    forward_butterfly!(poly, 174, 238, 3);
    forward_butterfly!(poly, 175, 239, 3);
    forward_butterfly!(poly, 176, 240, 3);
    forward_butterfly!(poly, 177, 241, 3);
    forward_butterfly!(poly, 178, 242, 3);
    forward_butterfly!(poly, 179, 243, 3);
    forward_butterfly!(poly, 180, 244, 3);
    forward_butterfly!(poly, 181, 245, 3);
    forward_butterfly!(poly, 182, 246, 3);
    forward_butterfly!(poly, 183, 247, 3);
    forward_butterfly!(poly, 184, 248, 3);
    forward_butterfly!(poly, 185, 249, 3);
    forward_butterfly!(poly, 186, 250, 3);
    forward_butterfly!(poly, 187, 251, 3);
    forward_butterfly!(poly, 188, 252, 3);
    forward_butterfly!(poly, 189, 253, 3);
    forward_butterfly!(poly, 190, 254, 3);
    forward_butterfly!(poly, 191, 255, 3);
    forward_butterfly!(poly, 0, 32, 4);
    forward_butterfly!(poly, 1, 33, 4);
    forward_butterfly!(poly, 2, 34, 4);
    forward_butterfly!(poly, 3, 35, 4);
    forward_butterfly!(poly, 4, 36, 4);
    forward_butterfly!(poly, 5, 37, 4);
    forward_butterfly!(poly, 6, 38, 4);
    forward_butterfly!(poly, 7, 39, 4);
    forward_butterfly!(poly, 8, 40, 4);
    forward_butterfly!(poly, 9, 41, 4);
    forward_butterfly!(poly, 10, 42, 4);
    forward_butterfly!(poly, 11, 43, 4);
    forward_butterfly!(poly, 12, 44, 4);
    forward_butterfly!(poly, 13, 45, 4);
    forward_butterfly!(poly, 14, 46, 4);
    forward_butterfly!(poly, 15, 47, 4);
    forward_butterfly!(poly, 16, 48, 4);
    forward_butterfly!(poly, 17, 49, 4);
    forward_butterfly!(poly, 18, 50, 4);
    forward_butterfly!(poly, 19, 51, 4);
    forward_butterfly!(poly, 20, 52, 4);
    forward_butterfly!(poly, 21, 53, 4);
    forward_butterfly!(poly, 22, 54, 4);
    forward_butterfly!(poly, 23, 55, 4);
    forward_butterfly!(poly, 24, 56, 4);
    forward_butterfly!(poly, 25, 57, 4);
    forward_butterfly!(poly, 26, 58, 4);
    forward_butterfly!(poly, 27, 59, 4);
    forward_butterfly!(poly, 28, 60, 4);
    forward_butterfly!(poly, 29, 61, 4);
    forward_butterfly!(poly, 30, 62, 4);
    forward_butterfly!(poly, 31, 63, 4);
    forward_butterfly!(poly, 64, 96, 5);
    forward_butterfly!(poly, 65, 97, 5);
    forward_butterfly!(poly, 66, 98, 5);
    forward_butterfly!(poly, 67, 99, 5);
    forward_butterfly!(poly, 68, 100, 5);
    forward_butterfly!(poly, 69, 101, 5);
    forward_butterfly!(poly, 70, 102, 5);
    forward_butterfly!(poly, 71, 103, 5);
    forward_butterfly!(poly, 72, 104, 5);
    forward_butterfly!(poly, 73, 105, 5);
    forward_butterfly!(poly, 74, 106, 5);
    forward_butterfly!(poly, 75, 107, 5);
    forward_butterfly!(poly, 76, 108, 5);
    forward_butterfly!(poly, 77, 109, 5);
    forward_butterfly!(poly, 78, 110, 5);
    forward_butterfly!(poly, 79, 111, 5);
    forward_butterfly!(poly, 80, 112, 5);
    forward_butterfly!(poly, 81, 113, 5);
    forward_butterfly!(poly, 82, 114, 5);
    forward_butterfly!(poly, 83, 115, 5);
    forward_butterfly!(poly, 84, 116, 5);
    forward_butterfly!(poly, 85, 117, 5);
    forward_butterfly!(poly, 86, 118, 5);
    forward_butterfly!(poly, 87, 119, 5);
    forward_butterfly!(poly, 88, 120, 5);
    forward_butterfly!(poly, 89, 121, 5);
    forward_butterfly!(poly, 90, 122, 5);
    forward_butterfly!(poly, 91, 123, 5);
    forward_butterfly!(poly, 92, 124, 5);
    forward_butterfly!(poly, 93, 125, 5);
    forward_butterfly!(poly, 94, 126, 5);
    forward_butterfly!(poly, 95, 127, 5);
    forward_butterfly!(poly, 128, 160, 6);
    forward_butterfly!(poly, 129, 161, 6);
    forward_butterfly!(poly, 130, 162, 6);
    forward_butterfly!(poly, 131, 163, 6);
    forward_butterfly!(poly, 132, 164, 6);
    forward_butterfly!(poly, 133, 165, 6);
    forward_butterfly!(poly, 134, 166, 6);
    forward_butterfly!(poly, 135, 167, 6);
    forward_butterfly!(poly, 136, 168, 6);
    forward_butterfly!(poly, 137, 169, 6);
    forward_butterfly!(poly, 138, 170, 6);
    forward_butterfly!(poly, 139, 171, 6);
    forward_butterfly!(poly, 140, 172, 6);
    forward_butterfly!(poly, 141, 173, 6);
    forward_butterfly!(poly, 142, 174, 6);
    forward_butterfly!(poly, 143, 175, 6);
    forward_butterfly!(poly, 144, 176, 6);
    forward_butterfly!(poly, 145, 177, 6);
    forward_butterfly!(poly, 146, 178, 6);
    forward_butterfly!(poly, 147, 179, 6);
    forward_butterfly!(poly, 148, 180, 6);
    forward_butterfly!(poly, 149, 181, 6);
    forward_butterfly!(poly, 150, 182, 6);
    forward_butterfly!(poly, 151, 183, 6);
    forward_butterfly!(poly, 152, 184, 6);
    forward_butterfly!(poly, 153, 185, 6);
    forward_butterfly!(poly, 154, 186, 6);
    forward_butterfly!(poly, 155, 187, 6);
    forward_butterfly!(poly, 156, 188, 6);
    forward_butterfly!(poly, 157, 189, 6);
    forward_butterfly!(poly, 158, 190, 6);
    forward_butterfly!(poly, 159, 191, 6);
    forward_butterfly!(poly, 192, 224, 7);
    forward_butterfly!(poly, 193, 225, 7);
    forward_butterfly!(poly, 194, 226, 7);
    forward_butterfly!(poly, 195, 227, 7);
    forward_butterfly!(poly, 196, 228, 7);
    forward_butterfly!(poly, 197, 229, 7);
    forward_butterfly!(poly, 198, 230, 7);
    forward_butterfly!(poly, 199, 231, 7);
    forward_butterfly!(poly, 200, 232, 7);
    forward_butterfly!(poly, 201, 233, 7);
    forward_butterfly!(poly, 202, 234, 7);
    forward_butterfly!(poly, 203, 235, 7);
    forward_butterfly!(poly, 204, 236, 7);
    forward_butterfly!(poly, 205, 237, 7);
    forward_butterfly!(poly, 206, 238, 7);
    forward_butterfly!(poly, 207, 239, 7);
    forward_butterfly!(poly, 208, 240, 7);
    forward_butterfly!(poly, 209, 241, 7);
    forward_butterfly!(poly, 210, 242, 7);
    forward_butterfly!(poly, 211, 243, 7);
    forward_butterfly!(poly, 212, 244, 7);
    forward_butterfly!(poly, 213, 245, 7);
    forward_butterfly!(poly, 214, 246, 7);
    forward_butterfly!(poly, 215, 247, 7);
    forward_butterfly!(poly, 216, 248, 7);
    forward_butterfly!(poly, 217, 249, 7);
    forward_butterfly!(poly, 218, 250, 7);
    forward_butterfly!(poly, 219, 251, 7);
    forward_butterfly!(poly, 220, 252, 7);
    forward_butterfly!(poly, 221, 253, 7);
    forward_butterfly!(poly, 222, 254, 7);
    forward_butterfly!(poly, 223, 255, 7);
    forward_butterfly!(poly, 0, 16, 8);
    forward_butterfly!(poly, 1, 17, 8);
    forward_butterfly!(poly, 2, 18, 8);
    forward_butterfly!(poly, 3, 19, 8);
    forward_butterfly!(poly, 4, 20, 8);
    forward_butterfly!(poly, 5, 21, 8);
    forward_butterfly!(poly, 6, 22, 8);
    forward_butterfly!(poly, 7, 23, 8);
    forward_butterfly!(poly, 8, 24, 8);
    forward_butterfly!(poly, 9, 25, 8);
    forward_butterfly!(poly, 10, 26, 8);
    forward_butterfly!(poly, 11, 27, 8);
    forward_butterfly!(poly, 12, 28, 8);
    forward_butterfly!(poly, 13, 29, 8);
    forward_butterfly!(poly, 14, 30, 8);
    forward_butterfly!(poly, 15, 31, 8);
    forward_butterfly!(poly, 32, 48, 9);
    forward_butterfly!(poly, 33, 49, 9);
    forward_butterfly!(poly, 34, 50, 9);
    forward_butterfly!(poly, 35, 51, 9);
    forward_butterfly!(poly, 36, 52, 9);
    forward_butterfly!(poly, 37, 53, 9);
    forward_butterfly!(poly, 38, 54, 9);
    forward_butterfly!(poly, 39, 55, 9);
    forward_butterfly!(poly, 40, 56, 9);
    forward_butterfly!(poly, 41, 57, 9);
    forward_butterfly!(poly, 42, 58, 9);
    forward_butterfly!(poly, 43, 59, 9);
    forward_butterfly!(poly, 44, 60, 9);
    forward_butterfly!(poly, 45, 61, 9);
    forward_butterfly!(poly, 46, 62, 9);
    forward_butterfly!(poly, 47, 63, 9);
    forward_butterfly!(poly, 64, 80, 10);
    forward_butterfly!(poly, 65, 81, 10);
    forward_butterfly!(poly, 66, 82, 10);
    forward_butterfly!(poly, 67, 83, 10);
    forward_butterfly!(poly, 68, 84, 10);
    forward_butterfly!(poly, 69, 85, 10);
    forward_butterfly!(poly, 70, 86, 10);
    forward_butterfly!(poly, 71, 87, 10);
    forward_butterfly!(poly, 72, 88, 10);
    forward_butterfly!(poly, 73, 89, 10);
    forward_butterfly!(poly, 74, 90, 10);
    forward_butterfly!(poly, 75, 91, 10);
    forward_butterfly!(poly, 76, 92, 10);
    forward_butterfly!(poly, 77, 93, 10);
    forward_butterfly!(poly, 78, 94, 10);
    forward_butterfly!(poly, 79, 95, 10);
    forward_butterfly!(poly, 96, 112, 11);
    forward_butterfly!(poly, 97, 113, 11);
    forward_butterfly!(poly, 98, 114, 11);
    forward_butterfly!(poly, 99, 115, 11);
    forward_butterfly!(poly, 100, 116, 11);
    forward_butterfly!(poly, 101, 117, 11);
    forward_butterfly!(poly, 102, 118, 11);
    forward_butterfly!(poly, 103, 119, 11);
    forward_butterfly!(poly, 104, 120, 11);
    forward_butterfly!(poly, 105, 121, 11);
    forward_butterfly!(poly, 106, 122, 11);
    forward_butterfly!(poly, 107, 123, 11);
    forward_butterfly!(poly, 108, 124, 11);
    forward_butterfly!(poly, 109, 125, 11);
    forward_butterfly!(poly, 110, 126, 11);
    forward_butterfly!(poly, 111, 127, 11);
    forward_butterfly!(poly, 128, 144, 12);
    forward_butterfly!(poly, 129, 145, 12);
    forward_butterfly!(poly, 130, 146, 12);
    forward_butterfly!(poly, 131, 147, 12);
    forward_butterfly!(poly, 132, 148, 12);
    forward_butterfly!(poly, 133, 149, 12);
    forward_butterfly!(poly, 134, 150, 12);
    forward_butterfly!(poly, 135, 151, 12);
    forward_butterfly!(poly, 136, 152, 12);
    forward_butterfly!(poly, 137, 153, 12);
    forward_butterfly!(poly, 138, 154, 12);
    forward_butterfly!(poly, 139, 155, 12);
    forward_butterfly!(poly, 140, 156, 12);
    forward_butterfly!(poly, 141, 157, 12);
    forward_butterfly!(poly, 142, 158, 12);
    forward_butterfly!(poly, 143, 159, 12);
    forward_butterfly!(poly, 160, 176, 13);
    forward_butterfly!(poly, 161, 177, 13);
    forward_butterfly!(poly, 162, 178, 13);
    forward_butterfly!(poly, 163, 179, 13);
    forward_butterfly!(poly, 164, 180, 13);
    forward_butterfly!(poly, 165, 181, 13);
    forward_butterfly!(poly, 166, 182, 13);
    forward_butterfly!(poly, 167, 183, 13);
    forward_butterfly!(poly, 168, 184, 13);
    forward_butterfly!(poly, 169, 185, 13);
    forward_butterfly!(poly, 170, 186, 13);
    forward_butterfly!(poly, 171, 187, 13);
    forward_butterfly!(poly, 172, 188, 13);
    forward_butterfly!(poly, 173, 189, 13);
    forward_butterfly!(poly, 174, 190, 13);
    forward_butterfly!(poly, 175, 191, 13);
    forward_butterfly!(poly, 192, 208, 14);
    forward_butterfly!(poly, 193, 209, 14);
    forward_butterfly!(poly, 194, 210, 14);
    forward_butterfly!(poly, 195, 211, 14);
    forward_butterfly!(poly, 196, 212, 14);
    forward_butterfly!(poly, 197, 213, 14);
    forward_butterfly!(poly, 198, 214, 14);
    forward_butterfly!(poly, 199, 215, 14);
    forward_butterfly!(poly, 200, 216, 14);
    forward_butterfly!(poly, 201, 217, 14);
    forward_butterfly!(poly, 202, 218, 14);
    forward_butterfly!(poly, 203, 219, 14);
    forward_butterfly!(poly, 204, 220, 14);
    forward_butterfly!(poly, 205, 221, 14);
    forward_butterfly!(poly, 206, 222, 14);
    forward_butterfly!(poly, 207, 223, 14);
    forward_butterfly!(poly, 224, 240, 15);
    forward_butterfly!(poly, 225, 241, 15);
    forward_butterfly!(poly, 226, 242, 15);
    forward_butterfly!(poly, 227, 243, 15);
    forward_butterfly!(poly, 228, 244, 15);
    forward_butterfly!(poly, 229, 245, 15);
    forward_butterfly!(poly, 230, 246, 15);
    forward_butterfly!(poly, 231, 247, 15);
    forward_butterfly!(poly, 232, 248, 15);
    forward_butterfly!(poly, 233, 249, 15);
    forward_butterfly!(poly, 234, 250, 15);
    forward_butterfly!(poly, 235, 251, 15);
    forward_butterfly!(poly, 236, 252, 15);
    forward_butterfly!(poly, 237, 253, 15);
    forward_butterfly!(poly, 238, 254, 15);
    forward_butterfly!(poly, 239, 255, 15);
    forward_butterfly!(poly, 0, 8, 16);
    forward_butterfly!(poly, 1, 9, 16);
    forward_butterfly!(poly, 2, 10, 16);
    forward_butterfly!(poly, 3, 11, 16);
    forward_butterfly!(poly, 4, 12, 16);
    forward_butterfly!(poly, 5, 13, 16);
    forward_butterfly!(poly, 6, 14, 16);
    forward_butterfly!(poly, 7, 15, 16);
    forward_butterfly!(poly, 16, 24, 17);
    forward_butterfly!(poly, 17, 25, 17);
    forward_butterfly!(poly, 18, 26, 17);
    forward_butterfly!(poly, 19, 27, 17);
    forward_butterfly!(poly, 20, 28, 17);
    forward_butterfly!(poly, 21, 29, 17);
    forward_butterfly!(poly, 22, 30, 17);
    forward_butterfly!(poly, 23, 31, 17);
    forward_butterfly!(poly, 32, 40, 18);
    forward_butterfly!(poly, 33, 41, 18);
    forward_butterfly!(poly, 34, 42, 18);
    forward_butterfly!(poly, 35, 43, 18);
    forward_butterfly!(poly, 36, 44, 18);
    forward_butterfly!(poly, 37, 45, 18);
    forward_butterfly!(poly, 38, 46, 18);
    forward_butterfly!(poly, 39, 47, 18);
    forward_butterfly!(poly, 48, 56, 19);
    forward_butterfly!(poly, 49, 57, 19);
    forward_butterfly!(poly, 50, 58, 19);
    forward_butterfly!(poly, 51, 59, 19);
    forward_butterfly!(poly, 52, 60, 19);
    forward_butterfly!(poly, 53, 61, 19);
    forward_butterfly!(poly, 54, 62, 19);
    forward_butterfly!(poly, 55, 63, 19);
    forward_butterfly!(poly, 64, 72, 20);
    forward_butterfly!(poly, 65, 73, 20);
    forward_butterfly!(poly, 66, 74, 20);
    forward_butterfly!(poly, 67, 75, 20);
    forward_butterfly!(poly, 68, 76, 20);
    forward_butterfly!(poly, 69, 77, 20);
    forward_butterfly!(poly, 70, 78, 20);
    forward_butterfly!(poly, 71, 79, 20);
    forward_butterfly!(poly, 80, 88, 21);
    forward_butterfly!(poly, 81, 89, 21);
    forward_butterfly!(poly, 82, 90, 21);
    forward_butterfly!(poly, 83, 91, 21);
    forward_butterfly!(poly, 84, 92, 21);
    forward_butterfly!(poly, 85, 93, 21);
    forward_butterfly!(poly, 86, 94, 21);
    forward_butterfly!(poly, 87, 95, 21);
    forward_butterfly!(poly, 96, 104, 22);
    forward_butterfly!(poly, 97, 105, 22);
    forward_butterfly!(poly, 98, 106, 22);
    forward_butterfly!(poly, 99, 107, 22);
    forward_butterfly!(poly, 100, 108, 22);
    forward_butterfly!(poly, 101, 109, 22);
    forward_butterfly!(poly, 102, 110, 22);
    forward_butterfly!(poly, 103, 111, 22);
    forward_butterfly!(poly, 112, 120, 23);
    forward_butterfly!(poly, 113, 121, 23);
    forward_butterfly!(poly, 114, 122, 23);
    forward_butterfly!(poly, 115, 123, 23);
    forward_butterfly!(poly, 116, 124, 23);
    forward_butterfly!(poly, 117, 125, 23);
    forward_butterfly!(poly, 118, 126, 23);
    forward_butterfly!(poly, 119, 127, 23);
    forward_butterfly!(poly, 128, 136, 24);
    forward_butterfly!(poly, 129, 137, 24);
    forward_butterfly!(poly, 130, 138, 24);
    forward_butterfly!(poly, 131, 139, 24);
    forward_butterfly!(poly, 132, 140, 24);
    forward_butterfly!(poly, 133, 141, 24);
    forward_butterfly!(poly, 134, 142, 24);
    forward_butterfly!(poly, 135, 143, 24);
    forward_butterfly!(poly, 144, 152, 25);
    forward_butterfly!(poly, 145, 153, 25);
    forward_butterfly!(poly, 146, 154, 25);
    forward_butterfly!(poly, 147, 155, 25);
    forward_butterfly!(poly, 148, 156, 25);
    forward_butterfly!(poly, 149, 157, 25);
    forward_butterfly!(poly, 150, 158, 25);
    forward_butterfly!(poly, 151, 159, 25);
    forward_butterfly!(poly, 160, 168, 26);
    forward_butterfly!(poly, 161, 169, 26);
    forward_butterfly!(poly, 162, 170, 26);
    forward_butterfly!(poly, 163, 171, 26);
    forward_butterfly!(poly, 164, 172, 26);
    forward_butterfly!(poly, 165, 173, 26);
    forward_butterfly!(poly, 166, 174, 26);
    forward_butterfly!(poly, 167, 175, 26);
    forward_butterfly!(poly, 176, 184, 27);
    forward_butterfly!(poly, 177, 185, 27);
    forward_butterfly!(poly, 178, 186, 27);
    forward_butterfly!(poly, 179, 187, 27);
    forward_butterfly!(poly, 180, 188, 27);
    forward_butterfly!(poly, 181, 189, 27);
    forward_butterfly!(poly, 182, 190, 27);
    forward_butterfly!(poly, 183, 191, 27);
    forward_butterfly!(poly, 192, 200, 28);
    forward_butterfly!(poly, 193, 201, 28);
    forward_butterfly!(poly, 194, 202, 28);
    forward_butterfly!(poly, 195, 203, 28);
    forward_butterfly!(poly, 196, 204, 28);
    forward_butterfly!(poly, 197, 205, 28);
    forward_butterfly!(poly, 198, 206, 28);
    forward_butterfly!(poly, 199, 207, 28);
    forward_butterfly!(poly, 208, 216, 29);
    forward_butterfly!(poly, 209, 217, 29);
    forward_butterfly!(poly, 210, 218, 29);
    forward_butterfly!(poly, 211, 219, 29);
    forward_butterfly!(poly, 212, 220, 29);
    forward_butterfly!(poly, 213, 221, 29);
    forward_butterfly!(poly, 214, 222, 29);
    forward_butterfly!(poly, 215, 223, 29);
    forward_butterfly!(poly, 224, 232, 30);
    forward_butterfly!(poly, 225, 233, 30);
    forward_butterfly!(poly, 226, 234, 30);
    forward_butterfly!(poly, 227, 235, 30);
    forward_butterfly!(poly, 228, 236, 30);
    forward_butterfly!(poly, 229, 237, 30);
    forward_butterfly!(poly, 230, 238, 30);
    forward_butterfly!(poly, 231, 239, 30);
    forward_butterfly!(poly, 240, 248, 31);
    forward_butterfly!(poly, 241, 249, 31);
    forward_butterfly!(poly, 242, 250, 31);
    forward_butterfly!(poly, 243, 251, 31);
    forward_butterfly!(poly, 244, 252, 31);
    forward_butterfly!(poly, 245, 253, 31);
    forward_butterfly!(poly, 246, 254, 31);
    forward_butterfly!(poly, 247, 255, 31);
    forward_butterfly!(poly, 0, 4, 32);
    forward_butterfly!(poly, 1, 5, 32);
    forward_butterfly!(poly, 2, 6, 32);
    forward_butterfly!(poly, 3, 7, 32);
    forward_butterfly!(poly, 8, 12, 33);
    forward_butterfly!(poly, 9, 13, 33);
    forward_butterfly!(poly, 10, 14, 33);
    forward_butterfly!(poly, 11, 15, 33);
    forward_butterfly!(poly, 16, 20, 34);
    forward_butterfly!(poly, 17, 21, 34);
    forward_butterfly!(poly, 18, 22, 34);
    forward_butterfly!(poly, 19, 23, 34);
    forward_butterfly!(poly, 24, 28, 35);
    forward_butterfly!(poly, 25, 29, 35);
    forward_butterfly!(poly, 26, 30, 35);
    forward_butterfly!(poly, 27, 31, 35);
    forward_butterfly!(poly, 32, 36, 36);
    forward_butterfly!(poly, 33, 37, 36);
    forward_butterfly!(poly, 34, 38, 36);
    forward_butterfly!(poly, 35, 39, 36);
    forward_butterfly!(poly, 40, 44, 37);
    forward_butterfly!(poly, 41, 45, 37);
    forward_butterfly!(poly, 42, 46, 37);
    forward_butterfly!(poly, 43, 47, 37);
    forward_butterfly!(poly, 48, 52, 38);
    forward_butterfly!(poly, 49, 53, 38);
    forward_butterfly!(poly, 50, 54, 38);
    forward_butterfly!(poly, 51, 55, 38);
    forward_butterfly!(poly, 56, 60, 39);
    forward_butterfly!(poly, 57, 61, 39);
    forward_butterfly!(poly, 58, 62, 39);
    forward_butterfly!(poly, 59, 63, 39);
    forward_butterfly!(poly, 64, 68, 40);
    forward_butterfly!(poly, 65, 69, 40);
    forward_butterfly!(poly, 66, 70, 40);
    forward_butterfly!(poly, 67, 71, 40);
    forward_butterfly!(poly, 72, 76, 41);
    forward_butterfly!(poly, 73, 77, 41);
    forward_butterfly!(poly, 74, 78, 41);
    forward_butterfly!(poly, 75, 79, 41);
    forward_butterfly!(poly, 80, 84, 42);
    forward_butterfly!(poly, 81, 85, 42);
    forward_butterfly!(poly, 82, 86, 42);
    forward_butterfly!(poly, 83, 87, 42);
    forward_butterfly!(poly, 88, 92, 43);
    forward_butterfly!(poly, 89, 93, 43);
    forward_butterfly!(poly, 90, 94, 43);
    forward_butterfly!(poly, 91, 95, 43);
    forward_butterfly!(poly, 96, 100, 44);
    forward_butterfly!(poly, 97, 101, 44);
    forward_butterfly!(poly, 98, 102, 44);
    forward_butterfly!(poly, 99, 103, 44);
    forward_butterfly!(poly, 104, 108, 45);
    forward_butterfly!(poly, 105, 109, 45);
    forward_butterfly!(poly, 106, 110, 45);
    forward_butterfly!(poly, 107, 111, 45);
    forward_butterfly!(poly, 112, 116, 46);
    forward_butterfly!(poly, 113, 117, 46);
    forward_butterfly!(poly, 114, 118, 46);
    forward_butterfly!(poly, 115, 119, 46);
    forward_butterfly!(poly, 120, 124, 47);
    forward_butterfly!(poly, 121, 125, 47);
    forward_butterfly!(poly, 122, 126, 47);
    forward_butterfly!(poly, 123, 127, 47);
    forward_butterfly!(poly, 128, 132, 48);
    forward_butterfly!(poly, 129, 133, 48);
    forward_butterfly!(poly, 130, 134, 48);
    forward_butterfly!(poly, 131, 135, 48);
    forward_butterfly!(poly, 136, 140, 49);
    forward_butterfly!(poly, 137, 141, 49);
    forward_butterfly!(poly, 138, 142, 49);
    forward_butterfly!(poly, 139, 143, 49);
    forward_butterfly!(poly, 144, 148, 50);
    forward_butterfly!(poly, 145, 149, 50);
    forward_butterfly!(poly, 146, 150, 50);
    forward_butterfly!(poly, 147, 151, 50);
    forward_butterfly!(poly, 152, 156, 51);
    forward_butterfly!(poly, 153, 157, 51);
    forward_butterfly!(poly, 154, 158, 51);
    forward_butterfly!(poly, 155, 159, 51);
    forward_butterfly!(poly, 160, 164, 52);
    forward_butterfly!(poly, 161, 165, 52);
    forward_butterfly!(poly, 162, 166, 52);
    forward_butterfly!(poly, 163, 167, 52);
    forward_butterfly!(poly, 168, 172, 53);
    forward_butterfly!(poly, 169, 173, 53);
    forward_butterfly!(poly, 170, 174, 53);
    forward_butterfly!(poly, 171, 175, 53);
    forward_butterfly!(poly, 176, 180, 54);
    forward_butterfly!(poly, 177, 181, 54);
    forward_butterfly!(poly, 178, 182, 54);
    forward_butterfly!(poly, 179, 183, 54);
    forward_butterfly!(poly, 184, 188, 55);
    forward_butterfly!(poly, 185, 189, 55);
    forward_butterfly!(poly, 186, 190, 55);
    forward_butterfly!(poly, 187, 191, 55);
    forward_butterfly!(poly, 192, 196, 56);
    forward_butterfly!(poly, 193, 197, 56);
    forward_butterfly!(poly, 194, 198, 56);
    forward_butterfly!(poly, 195, 199, 56);
    forward_butterfly!(poly, 200, 204, 57);
    forward_butterfly!(poly, 201, 205, 57);
    forward_butterfly!(poly, 202, 206, 57);
    forward_butterfly!(poly, 203, 207, 57);
    forward_butterfly!(poly, 208, 212, 58);
    forward_butterfly!(poly, 209, 213, 58);
    forward_butterfly!(poly, 210, 214, 58);
    forward_butterfly!(poly, 211, 215, 58);
    forward_butterfly!(poly, 216, 220, 59);
    forward_butterfly!(poly, 217, 221, 59);
    forward_butterfly!(poly, 218, 222, 59);
    forward_butterfly!(poly, 219, 223, 59);
    forward_butterfly!(poly, 224, 228, 60);
    forward_butterfly!(poly, 225, 229, 60);
    forward_butterfly!(poly, 226, 230, 60);
    forward_butterfly!(poly, 227, 231, 60);
    forward_butterfly!(poly, 232, 236, 61);
    forward_butterfly!(poly, 233, 237, 61);
    forward_butterfly!(poly, 234, 238, 61);
    forward_butterfly!(poly, 235, 239, 61);
    forward_butterfly!(poly, 240, 244, 62);
    forward_butterfly!(poly, 241, 245, 62);
    forward_butterfly!(poly, 242, 246, 62);
    forward_butterfly!(poly, 243, 247, 62);
    forward_butterfly!(poly, 248, 252, 63);
    forward_butterfly!(poly, 249, 253, 63);
    forward_butterfly!(poly, 250, 254, 63);
    forward_butterfly!(poly, 251, 255, 63);
    forward_butterfly!(poly, 0, 2, 64);
    forward_butterfly!(poly, 1, 3, 64);
    forward_butterfly!(poly, 4, 6, 65);
    forward_butterfly!(poly, 5, 7, 65);
    forward_butterfly!(poly, 8, 10, 66);
    forward_butterfly!(poly, 9, 11, 66);
    forward_butterfly!(poly, 12, 14, 67);
    forward_butterfly!(poly, 13, 15, 67);
    forward_butterfly!(poly, 16, 18, 68);
    forward_butterfly!(poly, 17, 19, 68);
    forward_butterfly!(poly, 20, 22, 69);
    forward_butterfly!(poly, 21, 23, 69);
    forward_butterfly!(poly, 24, 26, 70);
    forward_butterfly!(poly, 25, 27, 70);
    forward_butterfly!(poly, 28, 30, 71);
    forward_butterfly!(poly, 29, 31, 71);
    forward_butterfly!(poly, 32, 34, 72);
    forward_butterfly!(poly, 33, 35, 72);
    forward_butterfly!(poly, 36, 38, 73);
    forward_butterfly!(poly, 37, 39, 73);
    forward_butterfly!(poly, 40, 42, 74);
    forward_butterfly!(poly, 41, 43, 74);
    forward_butterfly!(poly, 44, 46, 75);
    forward_butterfly!(poly, 45, 47, 75);
    forward_butterfly!(poly, 48, 50, 76);
    forward_butterfly!(poly, 49, 51, 76);
    forward_butterfly!(poly, 52, 54, 77);
    forward_butterfly!(poly, 53, 55, 77);
    forward_butterfly!(poly, 56, 58, 78);
    forward_butterfly!(poly, 57, 59, 78);
    forward_butterfly!(poly, 60, 62, 79);
    forward_butterfly!(poly, 61, 63, 79);
    forward_butterfly!(poly, 64, 66, 80);
    forward_butterfly!(poly, 65, 67, 80);
    forward_butterfly!(poly, 68, 70, 81);
    forward_butterfly!(poly, 69, 71, 81);
    forward_butterfly!(poly, 72, 74, 82);
    forward_butterfly!(poly, 73, 75, 82);
    forward_butterfly!(poly, 76, 78, 83);
    forward_butterfly!(poly, 77, 79, 83);
    forward_butterfly!(poly, 80, 82, 84);
    forward_butterfly!(poly, 81, 83, 84);
    forward_butterfly!(poly, 84, 86, 85);
    forward_butterfly!(poly, 85, 87, 85);
    forward_butterfly!(poly, 88, 90, 86);
    forward_butterfly!(poly, 89, 91, 86);
    forward_butterfly!(poly, 92, 94, 87);
    forward_butterfly!(poly, 93, 95, 87);
    forward_butterfly!(poly, 96, 98, 88);
    forward_butterfly!(poly, 97, 99, 88);
    forward_butterfly!(poly, 100, 102, 89);
    forward_butterfly!(poly, 101, 103, 89);
    forward_butterfly!(poly, 104, 106, 90);
    forward_butterfly!(poly, 105, 107, 90);
    forward_butterfly!(poly, 108, 110, 91);
    forward_butterfly!(poly, 109, 111, 91);
    forward_butterfly!(poly, 112, 114, 92);
    forward_butterfly!(poly, 113, 115, 92);
    forward_butterfly!(poly, 116, 118, 93);
    forward_butterfly!(poly, 117, 119, 93);
    forward_butterfly!(poly, 120, 122, 94);
    forward_butterfly!(poly, 121, 123, 94);
    forward_butterfly!(poly, 124, 126, 95);
    forward_butterfly!(poly, 125, 127, 95);
    forward_butterfly!(poly, 128, 130, 96);
    forward_butterfly!(poly, 129, 131, 96);
    forward_butterfly!(poly, 132, 134, 97);
    forward_butterfly!(poly, 133, 135, 97);
    forward_butterfly!(poly, 136, 138, 98);
    forward_butterfly!(poly, 137, 139, 98);
    forward_butterfly!(poly, 140, 142, 99);
    forward_butterfly!(poly, 141, 143, 99);
    forward_butterfly!(poly, 144, 146, 100);
    forward_butterfly!(poly, 145, 147, 100);
    forward_butterfly!(poly, 148, 150, 101);
    forward_butterfly!(poly, 149, 151, 101);
    forward_butterfly!(poly, 152, 154, 102);
    forward_butterfly!(poly, 153, 155, 102);
    forward_butterfly!(poly, 156, 158, 103);
    forward_butterfly!(poly, 157, 159, 103);
    forward_butterfly!(poly, 160, 162, 104);
    forward_butterfly!(poly, 161, 163, 104);
    forward_butterfly!(poly, 164, 166, 105);
    forward_butterfly!(poly, 165, 167, 105);
    forward_butterfly!(poly, 168, 170, 106);
    forward_butterfly!(poly, 169, 171, 106);
    forward_butterfly!(poly, 172, 174, 107);
    forward_butterfly!(poly, 173, 175, 107);
    forward_butterfly!(poly, 176, 178, 108);
    forward_butterfly!(poly, 177, 179, 108);
    forward_butterfly!(poly, 180, 182, 109);
    forward_butterfly!(poly, 181, 183, 109);
    forward_butterfly!(poly, 184, 186, 110);
    forward_butterfly!(poly, 185, 187, 110);
    forward_butterfly!(poly, 188, 190, 111);
    forward_butterfly!(poly, 189, 191, 111);
    forward_butterfly!(poly, 192, 194, 112);
    forward_butterfly!(poly, 193, 195, 112);
    forward_butterfly!(poly, 196, 198, 113);
    forward_butterfly!(poly, 197, 199, 113);
    forward_butterfly!(poly, 200, 202, 114);
    forward_butterfly!(poly, 201, 203, 114);
    forward_butterfly!(poly, 204, 206, 115);
    forward_butterfly!(poly, 205, 207, 115);
    forward_butterfly!(poly, 208, 210, 116);
    forward_butterfly!(poly, 209, 211, 116);
    forward_butterfly!(poly, 212, 214, 117);
    forward_butterfly!(poly, 213, 215, 117);
    forward_butterfly!(poly, 216, 218, 118);
    forward_butterfly!(poly, 217, 219, 118);
    forward_butterfly!(poly, 220, 222, 119);
    forward_butterfly!(poly, 221, 223, 119);
    forward_butterfly!(poly, 224, 226, 120);
    forward_butterfly!(poly, 225, 227, 120);
    forward_butterfly!(poly, 228, 230, 121);
    forward_butterfly!(poly, 229, 231, 121);
    forward_butterfly!(poly, 232, 234, 122);
    forward_butterfly!(poly, 233, 235, 122);
    forward_butterfly!(poly, 236, 238, 123);
    forward_butterfly!(poly, 237, 239, 123);
    forward_butterfly!(poly, 240, 242, 124);
    forward_butterfly!(poly, 241, 243, 124);
    forward_butterfly!(poly, 244, 246, 125);
    forward_butterfly!(poly, 245, 247, 125);
    forward_butterfly!(poly, 248, 250, 126);
    forward_butterfly!(poly, 249, 251, 126);
    forward_butterfly!(poly, 252, 254, 127);
    forward_butterfly!(poly, 253, 255, 127);
    forward_butterfly!(poly, 0, 1, 128);
    forward_butterfly!(poly, 2, 3, 129);
    forward_butterfly!(poly, 4, 5, 130);
    forward_butterfly!(poly, 6, 7, 131);
    forward_butterfly!(poly, 8, 9, 132);
    forward_butterfly!(poly, 10, 11, 133);
    forward_butterfly!(poly, 12, 13, 134);
    forward_butterfly!(poly, 14, 15, 135);
    forward_butterfly!(poly, 16, 17, 136);
    forward_butterfly!(poly, 18, 19, 137);
    forward_butterfly!(poly, 20, 21, 138);
    forward_butterfly!(poly, 22, 23, 139);
    forward_butterfly!(poly, 24, 25, 140);
    forward_butterfly!(poly, 26, 27, 141);
    forward_butterfly!(poly, 28, 29, 142);
    forward_butterfly!(poly, 30, 31, 143);
    forward_butterfly!(poly, 32, 33, 144);
    forward_butterfly!(poly, 34, 35, 145);
    forward_butterfly!(poly, 36, 37, 146);
    forward_butterfly!(poly, 38, 39, 147);
    forward_butterfly!(poly, 40, 41, 148);
    forward_butterfly!(poly, 42, 43, 149);
    forward_butterfly!(poly, 44, 45, 150);
    forward_butterfly!(poly, 46, 47, 151);
    forward_butterfly!(poly, 48, 49, 152);
    forward_butterfly!(poly, 50, 51, 153);
    forward_butterfly!(poly, 52, 53, 154);
    forward_butterfly!(poly, 54, 55, 155);
    forward_butterfly!(poly, 56, 57, 156);
    forward_butterfly!(poly, 58, 59, 157);
    forward_butterfly!(poly, 60, 61, 158);
    forward_butterfly!(poly, 62, 63, 159);
    forward_butterfly!(poly, 64, 65, 160);
    forward_butterfly!(poly, 66, 67, 161);
    forward_butterfly!(poly, 68, 69, 162);
    forward_butterfly!(poly, 70, 71, 163);
    forward_butterfly!(poly, 72, 73, 164);
    forward_butterfly!(poly, 74, 75, 165);
    forward_butterfly!(poly, 76, 77, 166);
    forward_butterfly!(poly, 78, 79, 167);
    forward_butterfly!(poly, 80, 81, 168);
    forward_butterfly!(poly, 82, 83, 169);
    forward_butterfly!(poly, 84, 85, 170);
    forward_butterfly!(poly, 86, 87, 171);
    forward_butterfly!(poly, 88, 89, 172);
    forward_butterfly!(poly, 90, 91, 173);
    forward_butterfly!(poly, 92, 93, 174);
    forward_butterfly!(poly, 94, 95, 175);
    forward_butterfly!(poly, 96, 97, 176);
    forward_butterfly!(poly, 98, 99, 177);
    forward_butterfly!(poly, 100, 101, 178);
    forward_butterfly!(poly, 102, 103, 179);
    forward_butterfly!(poly, 104, 105, 180);
    forward_butterfly!(poly, 106, 107, 181);
    forward_butterfly!(poly, 108, 109, 182);
    forward_butterfly!(poly, 110, 111, 183);
    forward_butterfly!(poly, 112, 113, 184);
    forward_butterfly!(poly, 114, 115, 185);
    forward_butterfly!(poly, 116, 117, 186);
    forward_butterfly!(poly, 118, 119, 187);
    forward_butterfly!(poly, 120, 121, 188);
    forward_butterfly!(poly, 122, 123, 189);
    forward_butterfly!(poly, 124, 125, 190);
    forward_butterfly!(poly, 126, 127, 191);
    forward_butterfly!(poly, 128, 129, 192);
    forward_butterfly!(poly, 130, 131, 193);
    forward_butterfly!(poly, 132, 133, 194);
    forward_butterfly!(poly, 134, 135, 195);
    forward_butterfly!(poly, 136, 137, 196);
    forward_butterfly!(poly, 138, 139, 197);
    forward_butterfly!(poly, 140, 141, 198);
    forward_butterfly!(poly, 142, 143, 199);
    forward_butterfly!(poly, 144, 145, 200);
    forward_butterfly!(poly, 146, 147, 201);
    forward_butterfly!(poly, 148, 149, 202);
    forward_butterfly!(poly, 150, 151, 203);
    forward_butterfly!(poly, 152, 153, 204);
    forward_butterfly!(poly, 154, 155, 205);
    forward_butterfly!(poly, 156, 157, 206);
    forward_butterfly!(poly, 158, 159, 207);
    forward_butterfly!(poly, 160, 161, 208);
    forward_butterfly!(poly, 162, 163, 209);
    forward_butterfly!(poly, 164, 165, 210);
    forward_butterfly!(poly, 166, 167, 211);
    forward_butterfly!(poly, 168, 169, 212);
    forward_butterfly!(poly, 170, 171, 213);
    forward_butterfly!(poly, 172, 173, 214);
    forward_butterfly!(poly, 174, 175, 215);
    forward_butterfly!(poly, 176, 177, 216);
    forward_butterfly!(poly, 178, 179, 217);
    forward_butterfly!(poly, 180, 181, 218);
    forward_butterfly!(poly, 182, 183, 219);
    forward_butterfly!(poly, 184, 185, 220);
    forward_butterfly!(poly, 186, 187, 221);
    forward_butterfly!(poly, 188, 189, 222);
    forward_butterfly!(poly, 190, 191, 223);
    forward_butterfly!(poly, 192, 193, 224);
    forward_butterfly!(poly, 194, 195, 225);
    forward_butterfly!(poly, 196, 197, 226);
    forward_butterfly!(poly, 198, 199, 227);
    forward_butterfly!(poly, 200, 201, 228);
    forward_butterfly!(poly, 202, 203, 229);
    forward_butterfly!(poly, 204, 205, 230);
    forward_butterfly!(poly, 206, 207, 231);
    forward_butterfly!(poly, 208, 209, 232);
    forward_butterfly!(poly, 210, 211, 233);
    forward_butterfly!(poly, 212, 213, 234);
    forward_butterfly!(poly, 214, 215, 235);
    forward_butterfly!(poly, 216, 217, 236);
    forward_butterfly!(poly, 218, 219, 237);
    forward_butterfly!(poly, 220, 221, 238);
    forward_butterfly!(poly, 222, 223, 239);
    forward_butterfly!(poly, 224, 225, 240);
    forward_butterfly!(poly, 226, 227, 241);
    forward_butterfly!(poly, 228, 229, 242);
    forward_butterfly!(poly, 230, 231, 243);
    forward_butterfly!(poly, 232, 233, 244);
    forward_butterfly!(poly, 234, 235, 245);
    forward_butterfly!(poly, 236, 237, 246);
    forward_butterfly!(poly, 238, 239, 247);
    forward_butterfly!(poly, 240, 241, 248);
    forward_butterfly!(poly, 242, 243, 249);
    forward_butterfly!(poly, 244, 245, 250);
    forward_butterfly!(poly, 246, 247, 251);
    forward_butterfly!(poly, 248, 249, 252);
    forward_butterfly!(poly, 250, 251, 253);
    forward_butterfly!(poly, 252, 253, 254);
    forward_butterfly!(poly, 254, 255, 255);
    0
}
/// Eight inverse levels with Montgomery scaling; O(256 log 256) time, O(1) workspace.
#[no_mangle]
#[inline(never)]
pub extern "C" fn vk_inv_ntt_256_ct(poly: *mut i32) -> i32 {
    if poly.is_null() {
        return -1;
    }
    inverse_butterfly!(poly, 0, 1, 255);
    inverse_butterfly!(poly, 2, 3, 254);
    inverse_butterfly!(poly, 4, 5, 253);
    inverse_butterfly!(poly, 6, 7, 252);
    inverse_butterfly!(poly, 8, 9, 251);
    inverse_butterfly!(poly, 10, 11, 250);
    inverse_butterfly!(poly, 12, 13, 249);
    inverse_butterfly!(poly, 14, 15, 248);
    inverse_butterfly!(poly, 16, 17, 247);
    inverse_butterfly!(poly, 18, 19, 246);
    inverse_butterfly!(poly, 20, 21, 245);
    inverse_butterfly!(poly, 22, 23, 244);
    inverse_butterfly!(poly, 24, 25, 243);
    inverse_butterfly!(poly, 26, 27, 242);
    inverse_butterfly!(poly, 28, 29, 241);
    inverse_butterfly!(poly, 30, 31, 240);
    inverse_butterfly!(poly, 32, 33, 239);
    inverse_butterfly!(poly, 34, 35, 238);
    inverse_butterfly!(poly, 36, 37, 237);
    inverse_butterfly!(poly, 38, 39, 236);
    inverse_butterfly!(poly, 40, 41, 235);
    inverse_butterfly!(poly, 42, 43, 234);
    inverse_butterfly!(poly, 44, 45, 233);
    inverse_butterfly!(poly, 46, 47, 232);
    inverse_butterfly!(poly, 48, 49, 231);
    inverse_butterfly!(poly, 50, 51, 230);
    inverse_butterfly!(poly, 52, 53, 229);
    inverse_butterfly!(poly, 54, 55, 228);
    inverse_butterfly!(poly, 56, 57, 227);
    inverse_butterfly!(poly, 58, 59, 226);
    inverse_butterfly!(poly, 60, 61, 225);
    inverse_butterfly!(poly, 62, 63, 224);
    inverse_butterfly!(poly, 64, 65, 223);
    inverse_butterfly!(poly, 66, 67, 222);
    inverse_butterfly!(poly, 68, 69, 221);
    inverse_butterfly!(poly, 70, 71, 220);
    inverse_butterfly!(poly, 72, 73, 219);
    inverse_butterfly!(poly, 74, 75, 218);
    inverse_butterfly!(poly, 76, 77, 217);
    inverse_butterfly!(poly, 78, 79, 216);
    inverse_butterfly!(poly, 80, 81, 215);
    inverse_butterfly!(poly, 82, 83, 214);
    inverse_butterfly!(poly, 84, 85, 213);
    inverse_butterfly!(poly, 86, 87, 212);
    inverse_butterfly!(poly, 88, 89, 211);
    inverse_butterfly!(poly, 90, 91, 210);
    inverse_butterfly!(poly, 92, 93, 209);
    inverse_butterfly!(poly, 94, 95, 208);
    inverse_butterfly!(poly, 96, 97, 207);
    inverse_butterfly!(poly, 98, 99, 206);
    inverse_butterfly!(poly, 100, 101, 205);
    inverse_butterfly!(poly, 102, 103, 204);
    inverse_butterfly!(poly, 104, 105, 203);
    inverse_butterfly!(poly, 106, 107, 202);
    inverse_butterfly!(poly, 108, 109, 201);
    inverse_butterfly!(poly, 110, 111, 200);
    inverse_butterfly!(poly, 112, 113, 199);
    inverse_butterfly!(poly, 114, 115, 198);
    inverse_butterfly!(poly, 116, 117, 197);
    inverse_butterfly!(poly, 118, 119, 196);
    inverse_butterfly!(poly, 120, 121, 195);
    inverse_butterfly!(poly, 122, 123, 194);
    inverse_butterfly!(poly, 124, 125, 193);
    inverse_butterfly!(poly, 126, 127, 192);
    inverse_butterfly!(poly, 128, 129, 191);
    inverse_butterfly!(poly, 130, 131, 190);
    inverse_butterfly!(poly, 132, 133, 189);
    inverse_butterfly!(poly, 134, 135, 188);
    inverse_butterfly!(poly, 136, 137, 187);
    inverse_butterfly!(poly, 138, 139, 186);
    inverse_butterfly!(poly, 140, 141, 185);
    inverse_butterfly!(poly, 142, 143, 184);
    inverse_butterfly!(poly, 144, 145, 183);
    inverse_butterfly!(poly, 146, 147, 182);
    inverse_butterfly!(poly, 148, 149, 181);
    inverse_butterfly!(poly, 150, 151, 180);
    inverse_butterfly!(poly, 152, 153, 179);
    inverse_butterfly!(poly, 154, 155, 178);
    inverse_butterfly!(poly, 156, 157, 177);
    inverse_butterfly!(poly, 158, 159, 176);
    inverse_butterfly!(poly, 160, 161, 175);
    inverse_butterfly!(poly, 162, 163, 174);
    inverse_butterfly!(poly, 164, 165, 173);
    inverse_butterfly!(poly, 166, 167, 172);
    inverse_butterfly!(poly, 168, 169, 171);
    inverse_butterfly!(poly, 170, 171, 170);
    inverse_butterfly!(poly, 172, 173, 169);
    inverse_butterfly!(poly, 174, 175, 168);
    inverse_butterfly!(poly, 176, 177, 167);
    inverse_butterfly!(poly, 178, 179, 166);
    inverse_butterfly!(poly, 180, 181, 165);
    inverse_butterfly!(poly, 182, 183, 164);
    inverse_butterfly!(poly, 184, 185, 163);
    inverse_butterfly!(poly, 186, 187, 162);
    inverse_butterfly!(poly, 188, 189, 161);
    inverse_butterfly!(poly, 190, 191, 160);
    inverse_butterfly!(poly, 192, 193, 159);
    inverse_butterfly!(poly, 194, 195, 158);
    inverse_butterfly!(poly, 196, 197, 157);
    inverse_butterfly!(poly, 198, 199, 156);
    inverse_butterfly!(poly, 200, 201, 155);
    inverse_butterfly!(poly, 202, 203, 154);
    inverse_butterfly!(poly, 204, 205, 153);
    inverse_butterfly!(poly, 206, 207, 152);
    inverse_butterfly!(poly, 208, 209, 151);
    inverse_butterfly!(poly, 210, 211, 150);
    inverse_butterfly!(poly, 212, 213, 149);
    inverse_butterfly!(poly, 214, 215, 148);
    inverse_butterfly!(poly, 216, 217, 147);
    inverse_butterfly!(poly, 218, 219, 146);
    inverse_butterfly!(poly, 220, 221, 145);
    inverse_butterfly!(poly, 222, 223, 144);
    inverse_butterfly!(poly, 224, 225, 143);
    inverse_butterfly!(poly, 226, 227, 142);
    inverse_butterfly!(poly, 228, 229, 141);
    inverse_butterfly!(poly, 230, 231, 140);
    inverse_butterfly!(poly, 232, 233, 139);
    inverse_butterfly!(poly, 234, 235, 138);
    inverse_butterfly!(poly, 236, 237, 137);
    inverse_butterfly!(poly, 238, 239, 136);
    inverse_butterfly!(poly, 240, 241, 135);
    inverse_butterfly!(poly, 242, 243, 134);
    inverse_butterfly!(poly, 244, 245, 133);
    inverse_butterfly!(poly, 246, 247, 132);
    inverse_butterfly!(poly, 248, 249, 131);
    inverse_butterfly!(poly, 250, 251, 130);
    inverse_butterfly!(poly, 252, 253, 129);
    inverse_butterfly!(poly, 254, 255, 128);
    inverse_butterfly!(poly, 0, 2, 127);
    inverse_butterfly!(poly, 1, 3, 127);
    inverse_butterfly!(poly, 4, 6, 126);
    inverse_butterfly!(poly, 5, 7, 126);
    inverse_butterfly!(poly, 8, 10, 125);
    inverse_butterfly!(poly, 9, 11, 125);
    inverse_butterfly!(poly, 12, 14, 124);
    inverse_butterfly!(poly, 13, 15, 124);
    inverse_butterfly!(poly, 16, 18, 123);
    inverse_butterfly!(poly, 17, 19, 123);
    inverse_butterfly!(poly, 20, 22, 122);
    inverse_butterfly!(poly, 21, 23, 122);
    inverse_butterfly!(poly, 24, 26, 121);
    inverse_butterfly!(poly, 25, 27, 121);
    inverse_butterfly!(poly, 28, 30, 120);
    inverse_butterfly!(poly, 29, 31, 120);
    inverse_butterfly!(poly, 32, 34, 119);
    inverse_butterfly!(poly, 33, 35, 119);
    inverse_butterfly!(poly, 36, 38, 118);
    inverse_butterfly!(poly, 37, 39, 118);
    inverse_butterfly!(poly, 40, 42, 117);
    inverse_butterfly!(poly, 41, 43, 117);
    inverse_butterfly!(poly, 44, 46, 116);
    inverse_butterfly!(poly, 45, 47, 116);
    inverse_butterfly!(poly, 48, 50, 115);
    inverse_butterfly!(poly, 49, 51, 115);
    inverse_butterfly!(poly, 52, 54, 114);
    inverse_butterfly!(poly, 53, 55, 114);
    inverse_butterfly!(poly, 56, 58, 113);
    inverse_butterfly!(poly, 57, 59, 113);
    inverse_butterfly!(poly, 60, 62, 112);
    inverse_butterfly!(poly, 61, 63, 112);
    inverse_butterfly!(poly, 64, 66, 111);
    inverse_butterfly!(poly, 65, 67, 111);
    inverse_butterfly!(poly, 68, 70, 110);
    inverse_butterfly!(poly, 69, 71, 110);
    inverse_butterfly!(poly, 72, 74, 109);
    inverse_butterfly!(poly, 73, 75, 109);
    inverse_butterfly!(poly, 76, 78, 108);
    inverse_butterfly!(poly, 77, 79, 108);
    inverse_butterfly!(poly, 80, 82, 107);
    inverse_butterfly!(poly, 81, 83, 107);
    inverse_butterfly!(poly, 84, 86, 106);
    inverse_butterfly!(poly, 85, 87, 106);
    inverse_butterfly!(poly, 88, 90, 105);
    inverse_butterfly!(poly, 89, 91, 105);
    inverse_butterfly!(poly, 92, 94, 104);
    inverse_butterfly!(poly, 93, 95, 104);
    inverse_butterfly!(poly, 96, 98, 103);
    inverse_butterfly!(poly, 97, 99, 103);
    inverse_butterfly!(poly, 100, 102, 102);
    inverse_butterfly!(poly, 101, 103, 102);
    inverse_butterfly!(poly, 104, 106, 101);
    inverse_butterfly!(poly, 105, 107, 101);
    inverse_butterfly!(poly, 108, 110, 100);
    inverse_butterfly!(poly, 109, 111, 100);
    inverse_butterfly!(poly, 112, 114, 99);
    inverse_butterfly!(poly, 113, 115, 99);
    inverse_butterfly!(poly, 116, 118, 98);
    inverse_butterfly!(poly, 117, 119, 98);
    inverse_butterfly!(poly, 120, 122, 97);
    inverse_butterfly!(poly, 121, 123, 97);
    inverse_butterfly!(poly, 124, 126, 96);
    inverse_butterfly!(poly, 125, 127, 96);
    inverse_butterfly!(poly, 128, 130, 95);
    inverse_butterfly!(poly, 129, 131, 95);
    inverse_butterfly!(poly, 132, 134, 94);
    inverse_butterfly!(poly, 133, 135, 94);
    inverse_butterfly!(poly, 136, 138, 93);
    inverse_butterfly!(poly, 137, 139, 93);
    inverse_butterfly!(poly, 140, 142, 92);
    inverse_butterfly!(poly, 141, 143, 92);
    inverse_butterfly!(poly, 144, 146, 91);
    inverse_butterfly!(poly, 145, 147, 91);
    inverse_butterfly!(poly, 148, 150, 90);
    inverse_butterfly!(poly, 149, 151, 90);
    inverse_butterfly!(poly, 152, 154, 89);
    inverse_butterfly!(poly, 153, 155, 89);
    inverse_butterfly!(poly, 156, 158, 88);
    inverse_butterfly!(poly, 157, 159, 88);
    inverse_butterfly!(poly, 160, 162, 87);
    inverse_butterfly!(poly, 161, 163, 87);
    inverse_butterfly!(poly, 164, 166, 86);
    inverse_butterfly!(poly, 165, 167, 86);
    inverse_butterfly!(poly, 168, 170, 85);
    inverse_butterfly!(poly, 169, 171, 85);
    inverse_butterfly!(poly, 172, 174, 84);
    inverse_butterfly!(poly, 173, 175, 84);
    inverse_butterfly!(poly, 176, 178, 83);
    inverse_butterfly!(poly, 177, 179, 83);
    inverse_butterfly!(poly, 180, 182, 82);
    inverse_butterfly!(poly, 181, 183, 82);
    inverse_butterfly!(poly, 184, 186, 81);
    inverse_butterfly!(poly, 185, 187, 81);
    inverse_butterfly!(poly, 188, 190, 80);
    inverse_butterfly!(poly, 189, 191, 80);
    inverse_butterfly!(poly, 192, 194, 79);
    inverse_butterfly!(poly, 193, 195, 79);
    inverse_butterfly!(poly, 196, 198, 78);
    inverse_butterfly!(poly, 197, 199, 78);
    inverse_butterfly!(poly, 200, 202, 77);
    inverse_butterfly!(poly, 201, 203, 77);
    inverse_butterfly!(poly, 204, 206, 76);
    inverse_butterfly!(poly, 205, 207, 76);
    inverse_butterfly!(poly, 208, 210, 75);
    inverse_butterfly!(poly, 209, 211, 75);
    inverse_butterfly!(poly, 212, 214, 74);
    inverse_butterfly!(poly, 213, 215, 74);
    inverse_butterfly!(poly, 216, 218, 73);
    inverse_butterfly!(poly, 217, 219, 73);
    inverse_butterfly!(poly, 220, 222, 72);
    inverse_butterfly!(poly, 221, 223, 72);
    inverse_butterfly!(poly, 224, 226, 71);
    inverse_butterfly!(poly, 225, 227, 71);
    inverse_butterfly!(poly, 228, 230, 70);
    inverse_butterfly!(poly, 229, 231, 70);
    inverse_butterfly!(poly, 232, 234, 69);
    inverse_butterfly!(poly, 233, 235, 69);
    inverse_butterfly!(poly, 236, 238, 68);
    inverse_butterfly!(poly, 237, 239, 68);
    inverse_butterfly!(poly, 240, 242, 67);
    inverse_butterfly!(poly, 241, 243, 67);
    inverse_butterfly!(poly, 244, 246, 66);
    inverse_butterfly!(poly, 245, 247, 66);
    inverse_butterfly!(poly, 248, 250, 65);
    inverse_butterfly!(poly, 249, 251, 65);
    inverse_butterfly!(poly, 252, 254, 64);
    inverse_butterfly!(poly, 253, 255, 64);
    inverse_butterfly!(poly, 0, 4, 63);
    inverse_butterfly!(poly, 1, 5, 63);
    inverse_butterfly!(poly, 2, 6, 63);
    inverse_butterfly!(poly, 3, 7, 63);
    inverse_butterfly!(poly, 8, 12, 62);
    inverse_butterfly!(poly, 9, 13, 62);
    inverse_butterfly!(poly, 10, 14, 62);
    inverse_butterfly!(poly, 11, 15, 62);
    inverse_butterfly!(poly, 16, 20, 61);
    inverse_butterfly!(poly, 17, 21, 61);
    inverse_butterfly!(poly, 18, 22, 61);
    inverse_butterfly!(poly, 19, 23, 61);
    inverse_butterfly!(poly, 24, 28, 60);
    inverse_butterfly!(poly, 25, 29, 60);
    inverse_butterfly!(poly, 26, 30, 60);
    inverse_butterfly!(poly, 27, 31, 60);
    inverse_butterfly!(poly, 32, 36, 59);
    inverse_butterfly!(poly, 33, 37, 59);
    inverse_butterfly!(poly, 34, 38, 59);
    inverse_butterfly!(poly, 35, 39, 59);
    inverse_butterfly!(poly, 40, 44, 58);
    inverse_butterfly!(poly, 41, 45, 58);
    inverse_butterfly!(poly, 42, 46, 58);
    inverse_butterfly!(poly, 43, 47, 58);
    inverse_butterfly!(poly, 48, 52, 57);
    inverse_butterfly!(poly, 49, 53, 57);
    inverse_butterfly!(poly, 50, 54, 57);
    inverse_butterfly!(poly, 51, 55, 57);
    inverse_butterfly!(poly, 56, 60, 56);
    inverse_butterfly!(poly, 57, 61, 56);
    inverse_butterfly!(poly, 58, 62, 56);
    inverse_butterfly!(poly, 59, 63, 56);
    inverse_butterfly!(poly, 64, 68, 55);
    inverse_butterfly!(poly, 65, 69, 55);
    inverse_butterfly!(poly, 66, 70, 55);
    inverse_butterfly!(poly, 67, 71, 55);
    inverse_butterfly!(poly, 72, 76, 54);
    inverse_butterfly!(poly, 73, 77, 54);
    inverse_butterfly!(poly, 74, 78, 54);
    inverse_butterfly!(poly, 75, 79, 54);
    inverse_butterfly!(poly, 80, 84, 53);
    inverse_butterfly!(poly, 81, 85, 53);
    inverse_butterfly!(poly, 82, 86, 53);
    inverse_butterfly!(poly, 83, 87, 53);
    inverse_butterfly!(poly, 88, 92, 52);
    inverse_butterfly!(poly, 89, 93, 52);
    inverse_butterfly!(poly, 90, 94, 52);
    inverse_butterfly!(poly, 91, 95, 52);
    inverse_butterfly!(poly, 96, 100, 51);
    inverse_butterfly!(poly, 97, 101, 51);
    inverse_butterfly!(poly, 98, 102, 51);
    inverse_butterfly!(poly, 99, 103, 51);
    inverse_butterfly!(poly, 104, 108, 50);
    inverse_butterfly!(poly, 105, 109, 50);
    inverse_butterfly!(poly, 106, 110, 50);
    inverse_butterfly!(poly, 107, 111, 50);
    inverse_butterfly!(poly, 112, 116, 49);
    inverse_butterfly!(poly, 113, 117, 49);
    inverse_butterfly!(poly, 114, 118, 49);
    inverse_butterfly!(poly, 115, 119, 49);
    inverse_butterfly!(poly, 120, 124, 48);
    inverse_butterfly!(poly, 121, 125, 48);
    inverse_butterfly!(poly, 122, 126, 48);
    inverse_butterfly!(poly, 123, 127, 48);
    inverse_butterfly!(poly, 128, 132, 47);
    inverse_butterfly!(poly, 129, 133, 47);
    inverse_butterfly!(poly, 130, 134, 47);
    inverse_butterfly!(poly, 131, 135, 47);
    inverse_butterfly!(poly, 136, 140, 46);
    inverse_butterfly!(poly, 137, 141, 46);
    inverse_butterfly!(poly, 138, 142, 46);
    inverse_butterfly!(poly, 139, 143, 46);
    inverse_butterfly!(poly, 144, 148, 45);
    inverse_butterfly!(poly, 145, 149, 45);
    inverse_butterfly!(poly, 146, 150, 45);
    inverse_butterfly!(poly, 147, 151, 45);
    inverse_butterfly!(poly, 152, 156, 44);
    inverse_butterfly!(poly, 153, 157, 44);
    inverse_butterfly!(poly, 154, 158, 44);
    inverse_butterfly!(poly, 155, 159, 44);
    inverse_butterfly!(poly, 160, 164, 43);
    inverse_butterfly!(poly, 161, 165, 43);
    inverse_butterfly!(poly, 162, 166, 43);
    inverse_butterfly!(poly, 163, 167, 43);
    inverse_butterfly!(poly, 168, 172, 42);
    inverse_butterfly!(poly, 169, 173, 42);
    inverse_butterfly!(poly, 170, 174, 42);
    inverse_butterfly!(poly, 171, 175, 42);
    inverse_butterfly!(poly, 176, 180, 41);
    inverse_butterfly!(poly, 177, 181, 41);
    inverse_butterfly!(poly, 178, 182, 41);
    inverse_butterfly!(poly, 179, 183, 41);
    inverse_butterfly!(poly, 184, 188, 40);
    inverse_butterfly!(poly, 185, 189, 40);
    inverse_butterfly!(poly, 186, 190, 40);
    inverse_butterfly!(poly, 187, 191, 40);
    inverse_butterfly!(poly, 192, 196, 39);
    inverse_butterfly!(poly, 193, 197, 39);
    inverse_butterfly!(poly, 194, 198, 39);
    inverse_butterfly!(poly, 195, 199, 39);
    inverse_butterfly!(poly, 200, 204, 38);
    inverse_butterfly!(poly, 201, 205, 38);
    inverse_butterfly!(poly, 202, 206, 38);
    inverse_butterfly!(poly, 203, 207, 38);
    inverse_butterfly!(poly, 208, 212, 37);
    inverse_butterfly!(poly, 209, 213, 37);
    inverse_butterfly!(poly, 210, 214, 37);
    inverse_butterfly!(poly, 211, 215, 37);
    inverse_butterfly!(poly, 216, 220, 36);
    inverse_butterfly!(poly, 217, 221, 36);
    inverse_butterfly!(poly, 218, 222, 36);
    inverse_butterfly!(poly, 219, 223, 36);
    inverse_butterfly!(poly, 224, 228, 35);
    inverse_butterfly!(poly, 225, 229, 35);
    inverse_butterfly!(poly, 226, 230, 35);
    inverse_butterfly!(poly, 227, 231, 35);
    inverse_butterfly!(poly, 232, 236, 34);
    inverse_butterfly!(poly, 233, 237, 34);
    inverse_butterfly!(poly, 234, 238, 34);
    inverse_butterfly!(poly, 235, 239, 34);
    inverse_butterfly!(poly, 240, 244, 33);
    inverse_butterfly!(poly, 241, 245, 33);
    inverse_butterfly!(poly, 242, 246, 33);
    inverse_butterfly!(poly, 243, 247, 33);
    inverse_butterfly!(poly, 248, 252, 32);
    inverse_butterfly!(poly, 249, 253, 32);
    inverse_butterfly!(poly, 250, 254, 32);
    inverse_butterfly!(poly, 251, 255, 32);
    inverse_butterfly!(poly, 0, 8, 31);
    inverse_butterfly!(poly, 1, 9, 31);
    inverse_butterfly!(poly, 2, 10, 31);
    inverse_butterfly!(poly, 3, 11, 31);
    inverse_butterfly!(poly, 4, 12, 31);
    inverse_butterfly!(poly, 5, 13, 31);
    inverse_butterfly!(poly, 6, 14, 31);
    inverse_butterfly!(poly, 7, 15, 31);
    inverse_butterfly!(poly, 16, 24, 30);
    inverse_butterfly!(poly, 17, 25, 30);
    inverse_butterfly!(poly, 18, 26, 30);
    inverse_butterfly!(poly, 19, 27, 30);
    inverse_butterfly!(poly, 20, 28, 30);
    inverse_butterfly!(poly, 21, 29, 30);
    inverse_butterfly!(poly, 22, 30, 30);
    inverse_butterfly!(poly, 23, 31, 30);
    inverse_butterfly!(poly, 32, 40, 29);
    inverse_butterfly!(poly, 33, 41, 29);
    inverse_butterfly!(poly, 34, 42, 29);
    inverse_butterfly!(poly, 35, 43, 29);
    inverse_butterfly!(poly, 36, 44, 29);
    inverse_butterfly!(poly, 37, 45, 29);
    inverse_butterfly!(poly, 38, 46, 29);
    inverse_butterfly!(poly, 39, 47, 29);
    inverse_butterfly!(poly, 48, 56, 28);
    inverse_butterfly!(poly, 49, 57, 28);
    inverse_butterfly!(poly, 50, 58, 28);
    inverse_butterfly!(poly, 51, 59, 28);
    inverse_butterfly!(poly, 52, 60, 28);
    inverse_butterfly!(poly, 53, 61, 28);
    inverse_butterfly!(poly, 54, 62, 28);
    inverse_butterfly!(poly, 55, 63, 28);
    inverse_butterfly!(poly, 64, 72, 27);
    inverse_butterfly!(poly, 65, 73, 27);
    inverse_butterfly!(poly, 66, 74, 27);
    inverse_butterfly!(poly, 67, 75, 27);
    inverse_butterfly!(poly, 68, 76, 27);
    inverse_butterfly!(poly, 69, 77, 27);
    inverse_butterfly!(poly, 70, 78, 27);
    inverse_butterfly!(poly, 71, 79, 27);
    inverse_butterfly!(poly, 80, 88, 26);
    inverse_butterfly!(poly, 81, 89, 26);
    inverse_butterfly!(poly, 82, 90, 26);
    inverse_butterfly!(poly, 83, 91, 26);
    inverse_butterfly!(poly, 84, 92, 26);
    inverse_butterfly!(poly, 85, 93, 26);
    inverse_butterfly!(poly, 86, 94, 26);
    inverse_butterfly!(poly, 87, 95, 26);
    inverse_butterfly!(poly, 96, 104, 25);
    inverse_butterfly!(poly, 97, 105, 25);
    inverse_butterfly!(poly, 98, 106, 25);
    inverse_butterfly!(poly, 99, 107, 25);
    inverse_butterfly!(poly, 100, 108, 25);
    inverse_butterfly!(poly, 101, 109, 25);
    inverse_butterfly!(poly, 102, 110, 25);
    inverse_butterfly!(poly, 103, 111, 25);
    inverse_butterfly!(poly, 112, 120, 24);
    inverse_butterfly!(poly, 113, 121, 24);
    inverse_butterfly!(poly, 114, 122, 24);
    inverse_butterfly!(poly, 115, 123, 24);
    inverse_butterfly!(poly, 116, 124, 24);
    inverse_butterfly!(poly, 117, 125, 24);
    inverse_butterfly!(poly, 118, 126, 24);
    inverse_butterfly!(poly, 119, 127, 24);
    inverse_butterfly!(poly, 128, 136, 23);
    inverse_butterfly!(poly, 129, 137, 23);
    inverse_butterfly!(poly, 130, 138, 23);
    inverse_butterfly!(poly, 131, 139, 23);
    inverse_butterfly!(poly, 132, 140, 23);
    inverse_butterfly!(poly, 133, 141, 23);
    inverse_butterfly!(poly, 134, 142, 23);
    inverse_butterfly!(poly, 135, 143, 23);
    inverse_butterfly!(poly, 144, 152, 22);
    inverse_butterfly!(poly, 145, 153, 22);
    inverse_butterfly!(poly, 146, 154, 22);
    inverse_butterfly!(poly, 147, 155, 22);
    inverse_butterfly!(poly, 148, 156, 22);
    inverse_butterfly!(poly, 149, 157, 22);
    inverse_butterfly!(poly, 150, 158, 22);
    inverse_butterfly!(poly, 151, 159, 22);
    inverse_butterfly!(poly, 160, 168, 21);
    inverse_butterfly!(poly, 161, 169, 21);
    inverse_butterfly!(poly, 162, 170, 21);
    inverse_butterfly!(poly, 163, 171, 21);
    inverse_butterfly!(poly, 164, 172, 21);
    inverse_butterfly!(poly, 165, 173, 21);
    inverse_butterfly!(poly, 166, 174, 21);
    inverse_butterfly!(poly, 167, 175, 21);
    inverse_butterfly!(poly, 176, 184, 20);
    inverse_butterfly!(poly, 177, 185, 20);
    inverse_butterfly!(poly, 178, 186, 20);
    inverse_butterfly!(poly, 179, 187, 20);
    inverse_butterfly!(poly, 180, 188, 20);
    inverse_butterfly!(poly, 181, 189, 20);
    inverse_butterfly!(poly, 182, 190, 20);
    inverse_butterfly!(poly, 183, 191, 20);
    inverse_butterfly!(poly, 192, 200, 19);
    inverse_butterfly!(poly, 193, 201, 19);
    inverse_butterfly!(poly, 194, 202, 19);
    inverse_butterfly!(poly, 195, 203, 19);
    inverse_butterfly!(poly, 196, 204, 19);
    inverse_butterfly!(poly, 197, 205, 19);
    inverse_butterfly!(poly, 198, 206, 19);
    inverse_butterfly!(poly, 199, 207, 19);
    inverse_butterfly!(poly, 208, 216, 18);
    inverse_butterfly!(poly, 209, 217, 18);
    inverse_butterfly!(poly, 210, 218, 18);
    inverse_butterfly!(poly, 211, 219, 18);
    inverse_butterfly!(poly, 212, 220, 18);
    inverse_butterfly!(poly, 213, 221, 18);
    inverse_butterfly!(poly, 214, 222, 18);
    inverse_butterfly!(poly, 215, 223, 18);
    inverse_butterfly!(poly, 224, 232, 17);
    inverse_butterfly!(poly, 225, 233, 17);
    inverse_butterfly!(poly, 226, 234, 17);
    inverse_butterfly!(poly, 227, 235, 17);
    inverse_butterfly!(poly, 228, 236, 17);
    inverse_butterfly!(poly, 229, 237, 17);
    inverse_butterfly!(poly, 230, 238, 17);
    inverse_butterfly!(poly, 231, 239, 17);
    inverse_butterfly!(poly, 240, 248, 16);
    inverse_butterfly!(poly, 241, 249, 16);
    inverse_butterfly!(poly, 242, 250, 16);
    inverse_butterfly!(poly, 243, 251, 16);
    inverse_butterfly!(poly, 244, 252, 16);
    inverse_butterfly!(poly, 245, 253, 16);
    inverse_butterfly!(poly, 246, 254, 16);
    inverse_butterfly!(poly, 247, 255, 16);
    inverse_butterfly!(poly, 0, 16, 15);
    inverse_butterfly!(poly, 1, 17, 15);
    inverse_butterfly!(poly, 2, 18, 15);
    inverse_butterfly!(poly, 3, 19, 15);
    inverse_butterfly!(poly, 4, 20, 15);
    inverse_butterfly!(poly, 5, 21, 15);
    inverse_butterfly!(poly, 6, 22, 15);
    inverse_butterfly!(poly, 7, 23, 15);
    inverse_butterfly!(poly, 8, 24, 15);
    inverse_butterfly!(poly, 9, 25, 15);
    inverse_butterfly!(poly, 10, 26, 15);
    inverse_butterfly!(poly, 11, 27, 15);
    inverse_butterfly!(poly, 12, 28, 15);
    inverse_butterfly!(poly, 13, 29, 15);
    inverse_butterfly!(poly, 14, 30, 15);
    inverse_butterfly!(poly, 15, 31, 15);
    inverse_butterfly!(poly, 32, 48, 14);
    inverse_butterfly!(poly, 33, 49, 14);
    inverse_butterfly!(poly, 34, 50, 14);
    inverse_butterfly!(poly, 35, 51, 14);
    inverse_butterfly!(poly, 36, 52, 14);
    inverse_butterfly!(poly, 37, 53, 14);
    inverse_butterfly!(poly, 38, 54, 14);
    inverse_butterfly!(poly, 39, 55, 14);
    inverse_butterfly!(poly, 40, 56, 14);
    inverse_butterfly!(poly, 41, 57, 14);
    inverse_butterfly!(poly, 42, 58, 14);
    inverse_butterfly!(poly, 43, 59, 14);
    inverse_butterfly!(poly, 44, 60, 14);
    inverse_butterfly!(poly, 45, 61, 14);
    inverse_butterfly!(poly, 46, 62, 14);
    inverse_butterfly!(poly, 47, 63, 14);
    inverse_butterfly!(poly, 64, 80, 13);
    inverse_butterfly!(poly, 65, 81, 13);
    inverse_butterfly!(poly, 66, 82, 13);
    inverse_butterfly!(poly, 67, 83, 13);
    inverse_butterfly!(poly, 68, 84, 13);
    inverse_butterfly!(poly, 69, 85, 13);
    inverse_butterfly!(poly, 70, 86, 13);
    inverse_butterfly!(poly, 71, 87, 13);
    inverse_butterfly!(poly, 72, 88, 13);
    inverse_butterfly!(poly, 73, 89, 13);
    inverse_butterfly!(poly, 74, 90, 13);
    inverse_butterfly!(poly, 75, 91, 13);
    inverse_butterfly!(poly, 76, 92, 13);
    inverse_butterfly!(poly, 77, 93, 13);
    inverse_butterfly!(poly, 78, 94, 13);
    inverse_butterfly!(poly, 79, 95, 13);
    inverse_butterfly!(poly, 96, 112, 12);
    inverse_butterfly!(poly, 97, 113, 12);
    inverse_butterfly!(poly, 98, 114, 12);
    inverse_butterfly!(poly, 99, 115, 12);
    inverse_butterfly!(poly, 100, 116, 12);
    inverse_butterfly!(poly, 101, 117, 12);
    inverse_butterfly!(poly, 102, 118, 12);
    inverse_butterfly!(poly, 103, 119, 12);
    inverse_butterfly!(poly, 104, 120, 12);
    inverse_butterfly!(poly, 105, 121, 12);
    inverse_butterfly!(poly, 106, 122, 12);
    inverse_butterfly!(poly, 107, 123, 12);
    inverse_butterfly!(poly, 108, 124, 12);
    inverse_butterfly!(poly, 109, 125, 12);
    inverse_butterfly!(poly, 110, 126, 12);
    inverse_butterfly!(poly, 111, 127, 12);
    inverse_butterfly!(poly, 128, 144, 11);
    inverse_butterfly!(poly, 129, 145, 11);
    inverse_butterfly!(poly, 130, 146, 11);
    inverse_butterfly!(poly, 131, 147, 11);
    inverse_butterfly!(poly, 132, 148, 11);
    inverse_butterfly!(poly, 133, 149, 11);
    inverse_butterfly!(poly, 134, 150, 11);
    inverse_butterfly!(poly, 135, 151, 11);
    inverse_butterfly!(poly, 136, 152, 11);
    inverse_butterfly!(poly, 137, 153, 11);
    inverse_butterfly!(poly, 138, 154, 11);
    inverse_butterfly!(poly, 139, 155, 11);
    inverse_butterfly!(poly, 140, 156, 11);
    inverse_butterfly!(poly, 141, 157, 11);
    inverse_butterfly!(poly, 142, 158, 11);
    inverse_butterfly!(poly, 143, 159, 11);
    inverse_butterfly!(poly, 160, 176, 10);
    inverse_butterfly!(poly, 161, 177, 10);
    inverse_butterfly!(poly, 162, 178, 10);
    inverse_butterfly!(poly, 163, 179, 10);
    inverse_butterfly!(poly, 164, 180, 10);
    inverse_butterfly!(poly, 165, 181, 10);
    inverse_butterfly!(poly, 166, 182, 10);
    inverse_butterfly!(poly, 167, 183, 10);
    inverse_butterfly!(poly, 168, 184, 10);
    inverse_butterfly!(poly, 169, 185, 10);
    inverse_butterfly!(poly, 170, 186, 10);
    inverse_butterfly!(poly, 171, 187, 10);
    inverse_butterfly!(poly, 172, 188, 10);
    inverse_butterfly!(poly, 173, 189, 10);
    inverse_butterfly!(poly, 174, 190, 10);
    inverse_butterfly!(poly, 175, 191, 10);
    inverse_butterfly!(poly, 192, 208, 9);
    inverse_butterfly!(poly, 193, 209, 9);
    inverse_butterfly!(poly, 194, 210, 9);
    inverse_butterfly!(poly, 195, 211, 9);
    inverse_butterfly!(poly, 196, 212, 9);
    inverse_butterfly!(poly, 197, 213, 9);
    inverse_butterfly!(poly, 198, 214, 9);
    inverse_butterfly!(poly, 199, 215, 9);
    inverse_butterfly!(poly, 200, 216, 9);
    inverse_butterfly!(poly, 201, 217, 9);
    inverse_butterfly!(poly, 202, 218, 9);
    inverse_butterfly!(poly, 203, 219, 9);
    inverse_butterfly!(poly, 204, 220, 9);
    inverse_butterfly!(poly, 205, 221, 9);
    inverse_butterfly!(poly, 206, 222, 9);
    inverse_butterfly!(poly, 207, 223, 9);
    inverse_butterfly!(poly, 224, 240, 8);
    inverse_butterfly!(poly, 225, 241, 8);
    inverse_butterfly!(poly, 226, 242, 8);
    inverse_butterfly!(poly, 227, 243, 8);
    inverse_butterfly!(poly, 228, 244, 8);
    inverse_butterfly!(poly, 229, 245, 8);
    inverse_butterfly!(poly, 230, 246, 8);
    inverse_butterfly!(poly, 231, 247, 8);
    inverse_butterfly!(poly, 232, 248, 8);
    inverse_butterfly!(poly, 233, 249, 8);
    inverse_butterfly!(poly, 234, 250, 8);
    inverse_butterfly!(poly, 235, 251, 8);
    inverse_butterfly!(poly, 236, 252, 8);
    inverse_butterfly!(poly, 237, 253, 8);
    inverse_butterfly!(poly, 238, 254, 8);
    inverse_butterfly!(poly, 239, 255, 8);
    inverse_butterfly!(poly, 0, 32, 7);
    inverse_butterfly!(poly, 1, 33, 7);
    inverse_butterfly!(poly, 2, 34, 7);
    inverse_butterfly!(poly, 3, 35, 7);
    inverse_butterfly!(poly, 4, 36, 7);
    inverse_butterfly!(poly, 5, 37, 7);
    inverse_butterfly!(poly, 6, 38, 7);
    inverse_butterfly!(poly, 7, 39, 7);
    inverse_butterfly!(poly, 8, 40, 7);
    inverse_butterfly!(poly, 9, 41, 7);
    inverse_butterfly!(poly, 10, 42, 7);
    inverse_butterfly!(poly, 11, 43, 7);
    inverse_butterfly!(poly, 12, 44, 7);
    inverse_butterfly!(poly, 13, 45, 7);
    inverse_butterfly!(poly, 14, 46, 7);
    inverse_butterfly!(poly, 15, 47, 7);
    inverse_butterfly!(poly, 16, 48, 7);
    inverse_butterfly!(poly, 17, 49, 7);
    inverse_butterfly!(poly, 18, 50, 7);
    inverse_butterfly!(poly, 19, 51, 7);
    inverse_butterfly!(poly, 20, 52, 7);
    inverse_butterfly!(poly, 21, 53, 7);
    inverse_butterfly!(poly, 22, 54, 7);
    inverse_butterfly!(poly, 23, 55, 7);
    inverse_butterfly!(poly, 24, 56, 7);
    inverse_butterfly!(poly, 25, 57, 7);
    inverse_butterfly!(poly, 26, 58, 7);
    inverse_butterfly!(poly, 27, 59, 7);
    inverse_butterfly!(poly, 28, 60, 7);
    inverse_butterfly!(poly, 29, 61, 7);
    inverse_butterfly!(poly, 30, 62, 7);
    inverse_butterfly!(poly, 31, 63, 7);
    inverse_butterfly!(poly, 64, 96, 6);
    inverse_butterfly!(poly, 65, 97, 6);
    inverse_butterfly!(poly, 66, 98, 6);
    inverse_butterfly!(poly, 67, 99, 6);
    inverse_butterfly!(poly, 68, 100, 6);
    inverse_butterfly!(poly, 69, 101, 6);
    inverse_butterfly!(poly, 70, 102, 6);
    inverse_butterfly!(poly, 71, 103, 6);
    inverse_butterfly!(poly, 72, 104, 6);
    inverse_butterfly!(poly, 73, 105, 6);
    inverse_butterfly!(poly, 74, 106, 6);
    inverse_butterfly!(poly, 75, 107, 6);
    inverse_butterfly!(poly, 76, 108, 6);
    inverse_butterfly!(poly, 77, 109, 6);
    inverse_butterfly!(poly, 78, 110, 6);
    inverse_butterfly!(poly, 79, 111, 6);
    inverse_butterfly!(poly, 80, 112, 6);
    inverse_butterfly!(poly, 81, 113, 6);
    inverse_butterfly!(poly, 82, 114, 6);
    inverse_butterfly!(poly, 83, 115, 6);
    inverse_butterfly!(poly, 84, 116, 6);
    inverse_butterfly!(poly, 85, 117, 6);
    inverse_butterfly!(poly, 86, 118, 6);
    inverse_butterfly!(poly, 87, 119, 6);
    inverse_butterfly!(poly, 88, 120, 6);
    inverse_butterfly!(poly, 89, 121, 6);
    inverse_butterfly!(poly, 90, 122, 6);
    inverse_butterfly!(poly, 91, 123, 6);
    inverse_butterfly!(poly, 92, 124, 6);
    inverse_butterfly!(poly, 93, 125, 6);
    inverse_butterfly!(poly, 94, 126, 6);
    inverse_butterfly!(poly, 95, 127, 6);
    inverse_butterfly!(poly, 128, 160, 5);
    inverse_butterfly!(poly, 129, 161, 5);
    inverse_butterfly!(poly, 130, 162, 5);
    inverse_butterfly!(poly, 131, 163, 5);
    inverse_butterfly!(poly, 132, 164, 5);
    inverse_butterfly!(poly, 133, 165, 5);
    inverse_butterfly!(poly, 134, 166, 5);
    inverse_butterfly!(poly, 135, 167, 5);
    inverse_butterfly!(poly, 136, 168, 5);
    inverse_butterfly!(poly, 137, 169, 5);
    inverse_butterfly!(poly, 138, 170, 5);
    inverse_butterfly!(poly, 139, 171, 5);
    inverse_butterfly!(poly, 140, 172, 5);
    inverse_butterfly!(poly, 141, 173, 5);
    inverse_butterfly!(poly, 142, 174, 5);
    inverse_butterfly!(poly, 143, 175, 5);
    inverse_butterfly!(poly, 144, 176, 5);
    inverse_butterfly!(poly, 145, 177, 5);
    inverse_butterfly!(poly, 146, 178, 5);
    inverse_butterfly!(poly, 147, 179, 5);
    inverse_butterfly!(poly, 148, 180, 5);
    inverse_butterfly!(poly, 149, 181, 5);
    inverse_butterfly!(poly, 150, 182, 5);
    inverse_butterfly!(poly, 151, 183, 5);
    inverse_butterfly!(poly, 152, 184, 5);
    inverse_butterfly!(poly, 153, 185, 5);
    inverse_butterfly!(poly, 154, 186, 5);
    inverse_butterfly!(poly, 155, 187, 5);
    inverse_butterfly!(poly, 156, 188, 5);
    inverse_butterfly!(poly, 157, 189, 5);
    inverse_butterfly!(poly, 158, 190, 5);
    inverse_butterfly!(poly, 159, 191, 5);
    inverse_butterfly!(poly, 192, 224, 4);
    inverse_butterfly!(poly, 193, 225, 4);
    inverse_butterfly!(poly, 194, 226, 4);
    inverse_butterfly!(poly, 195, 227, 4);
    inverse_butterfly!(poly, 196, 228, 4);
    inverse_butterfly!(poly, 197, 229, 4);
    inverse_butterfly!(poly, 198, 230, 4);
    inverse_butterfly!(poly, 199, 231, 4);
    inverse_butterfly!(poly, 200, 232, 4);
    inverse_butterfly!(poly, 201, 233, 4);
    inverse_butterfly!(poly, 202, 234, 4);
    inverse_butterfly!(poly, 203, 235, 4);
    inverse_butterfly!(poly, 204, 236, 4);
    inverse_butterfly!(poly, 205, 237, 4);
    inverse_butterfly!(poly, 206, 238, 4);
    inverse_butterfly!(poly, 207, 239, 4);
    inverse_butterfly!(poly, 208, 240, 4);
    inverse_butterfly!(poly, 209, 241, 4);
    inverse_butterfly!(poly, 210, 242, 4);
    inverse_butterfly!(poly, 211, 243, 4);
    inverse_butterfly!(poly, 212, 244, 4);
    inverse_butterfly!(poly, 213, 245, 4);
    inverse_butterfly!(poly, 214, 246, 4);
    inverse_butterfly!(poly, 215, 247, 4);
    inverse_butterfly!(poly, 216, 248, 4);
    inverse_butterfly!(poly, 217, 249, 4);
    inverse_butterfly!(poly, 218, 250, 4);
    inverse_butterfly!(poly, 219, 251, 4);
    inverse_butterfly!(poly, 220, 252, 4);
    inverse_butterfly!(poly, 221, 253, 4);
    inverse_butterfly!(poly, 222, 254, 4);
    inverse_butterfly!(poly, 223, 255, 4);
    inverse_butterfly!(poly, 0, 64, 3);
    inverse_butterfly!(poly, 1, 65, 3);
    inverse_butterfly!(poly, 2, 66, 3);
    inverse_butterfly!(poly, 3, 67, 3);
    inverse_butterfly!(poly, 4, 68, 3);
    inverse_butterfly!(poly, 5, 69, 3);
    inverse_butterfly!(poly, 6, 70, 3);
    inverse_butterfly!(poly, 7, 71, 3);
    inverse_butterfly!(poly, 8, 72, 3);
    inverse_butterfly!(poly, 9, 73, 3);
    inverse_butterfly!(poly, 10, 74, 3);
    inverse_butterfly!(poly, 11, 75, 3);
    inverse_butterfly!(poly, 12, 76, 3);
    inverse_butterfly!(poly, 13, 77, 3);
    inverse_butterfly!(poly, 14, 78, 3);
    inverse_butterfly!(poly, 15, 79, 3);
    inverse_butterfly!(poly, 16, 80, 3);
    inverse_butterfly!(poly, 17, 81, 3);
    inverse_butterfly!(poly, 18, 82, 3);
    inverse_butterfly!(poly, 19, 83, 3);
    inverse_butterfly!(poly, 20, 84, 3);
    inverse_butterfly!(poly, 21, 85, 3);
    inverse_butterfly!(poly, 22, 86, 3);
    inverse_butterfly!(poly, 23, 87, 3);
    inverse_butterfly!(poly, 24, 88, 3);
    inverse_butterfly!(poly, 25, 89, 3);
    inverse_butterfly!(poly, 26, 90, 3);
    inverse_butterfly!(poly, 27, 91, 3);
    inverse_butterfly!(poly, 28, 92, 3);
    inverse_butterfly!(poly, 29, 93, 3);
    inverse_butterfly!(poly, 30, 94, 3);
    inverse_butterfly!(poly, 31, 95, 3);
    inverse_butterfly!(poly, 32, 96, 3);
    inverse_butterfly!(poly, 33, 97, 3);
    inverse_butterfly!(poly, 34, 98, 3);
    inverse_butterfly!(poly, 35, 99, 3);
    inverse_butterfly!(poly, 36, 100, 3);
    inverse_butterfly!(poly, 37, 101, 3);
    inverse_butterfly!(poly, 38, 102, 3);
    inverse_butterfly!(poly, 39, 103, 3);
    inverse_butterfly!(poly, 40, 104, 3);
    inverse_butterfly!(poly, 41, 105, 3);
    inverse_butterfly!(poly, 42, 106, 3);
    inverse_butterfly!(poly, 43, 107, 3);
    inverse_butterfly!(poly, 44, 108, 3);
    inverse_butterfly!(poly, 45, 109, 3);
    inverse_butterfly!(poly, 46, 110, 3);
    inverse_butterfly!(poly, 47, 111, 3);
    inverse_butterfly!(poly, 48, 112, 3);
    inverse_butterfly!(poly, 49, 113, 3);
    inverse_butterfly!(poly, 50, 114, 3);
    inverse_butterfly!(poly, 51, 115, 3);
    inverse_butterfly!(poly, 52, 116, 3);
    inverse_butterfly!(poly, 53, 117, 3);
    inverse_butterfly!(poly, 54, 118, 3);
    inverse_butterfly!(poly, 55, 119, 3);
    inverse_butterfly!(poly, 56, 120, 3);
    inverse_butterfly!(poly, 57, 121, 3);
    inverse_butterfly!(poly, 58, 122, 3);
    inverse_butterfly!(poly, 59, 123, 3);
    inverse_butterfly!(poly, 60, 124, 3);
    inverse_butterfly!(poly, 61, 125, 3);
    inverse_butterfly!(poly, 62, 126, 3);
    inverse_butterfly!(poly, 63, 127, 3);
    inverse_butterfly!(poly, 128, 192, 2);
    inverse_butterfly!(poly, 129, 193, 2);
    inverse_butterfly!(poly, 130, 194, 2);
    inverse_butterfly!(poly, 131, 195, 2);
    inverse_butterfly!(poly, 132, 196, 2);
    inverse_butterfly!(poly, 133, 197, 2);
    inverse_butterfly!(poly, 134, 198, 2);
    inverse_butterfly!(poly, 135, 199, 2);
    inverse_butterfly!(poly, 136, 200, 2);
    inverse_butterfly!(poly, 137, 201, 2);
    inverse_butterfly!(poly, 138, 202, 2);
    inverse_butterfly!(poly, 139, 203, 2);
    inverse_butterfly!(poly, 140, 204, 2);
    inverse_butterfly!(poly, 141, 205, 2);
    inverse_butterfly!(poly, 142, 206, 2);
    inverse_butterfly!(poly, 143, 207, 2);
    inverse_butterfly!(poly, 144, 208, 2);
    inverse_butterfly!(poly, 145, 209, 2);
    inverse_butterfly!(poly, 146, 210, 2);
    inverse_butterfly!(poly, 147, 211, 2);
    inverse_butterfly!(poly, 148, 212, 2);
    inverse_butterfly!(poly, 149, 213, 2);
    inverse_butterfly!(poly, 150, 214, 2);
    inverse_butterfly!(poly, 151, 215, 2);
    inverse_butterfly!(poly, 152, 216, 2);
    inverse_butterfly!(poly, 153, 217, 2);
    inverse_butterfly!(poly, 154, 218, 2);
    inverse_butterfly!(poly, 155, 219, 2);
    inverse_butterfly!(poly, 156, 220, 2);
    inverse_butterfly!(poly, 157, 221, 2);
    inverse_butterfly!(poly, 158, 222, 2);
    inverse_butterfly!(poly, 159, 223, 2);
    inverse_butterfly!(poly, 160, 224, 2);
    inverse_butterfly!(poly, 161, 225, 2);
    inverse_butterfly!(poly, 162, 226, 2);
    inverse_butterfly!(poly, 163, 227, 2);
    inverse_butterfly!(poly, 164, 228, 2);
    inverse_butterfly!(poly, 165, 229, 2);
    inverse_butterfly!(poly, 166, 230, 2);
    inverse_butterfly!(poly, 167, 231, 2);
    inverse_butterfly!(poly, 168, 232, 2);
    inverse_butterfly!(poly, 169, 233, 2);
    inverse_butterfly!(poly, 170, 234, 2);
    inverse_butterfly!(poly, 171, 235, 2);
    inverse_butterfly!(poly, 172, 236, 2);
    inverse_butterfly!(poly, 173, 237, 2);
    inverse_butterfly!(poly, 174, 238, 2);
    inverse_butterfly!(poly, 175, 239, 2);
    inverse_butterfly!(poly, 176, 240, 2);
    inverse_butterfly!(poly, 177, 241, 2);
    inverse_butterfly!(poly, 178, 242, 2);
    inverse_butterfly!(poly, 179, 243, 2);
    inverse_butterfly!(poly, 180, 244, 2);
    inverse_butterfly!(poly, 181, 245, 2);
    inverse_butterfly!(poly, 182, 246, 2);
    inverse_butterfly!(poly, 183, 247, 2);
    inverse_butterfly!(poly, 184, 248, 2);
    inverse_butterfly!(poly, 185, 249, 2);
    inverse_butterfly!(poly, 186, 250, 2);
    inverse_butterfly!(poly, 187, 251, 2);
    inverse_butterfly!(poly, 188, 252, 2);
    inverse_butterfly!(poly, 189, 253, 2);
    inverse_butterfly!(poly, 190, 254, 2);
    inverse_butterfly!(poly, 191, 255, 2);
    inverse_butterfly!(poly, 0, 128, 1);
    inverse_butterfly!(poly, 1, 129, 1);
    inverse_butterfly!(poly, 2, 130, 1);
    inverse_butterfly!(poly, 3, 131, 1);
    inverse_butterfly!(poly, 4, 132, 1);
    inverse_butterfly!(poly, 5, 133, 1);
    inverse_butterfly!(poly, 6, 134, 1);
    inverse_butterfly!(poly, 7, 135, 1);
    inverse_butterfly!(poly, 8, 136, 1);
    inverse_butterfly!(poly, 9, 137, 1);
    inverse_butterfly!(poly, 10, 138, 1);
    inverse_butterfly!(poly, 11, 139, 1);
    inverse_butterfly!(poly, 12, 140, 1);
    inverse_butterfly!(poly, 13, 141, 1);
    inverse_butterfly!(poly, 14, 142, 1);
    inverse_butterfly!(poly, 15, 143, 1);
    inverse_butterfly!(poly, 16, 144, 1);
    inverse_butterfly!(poly, 17, 145, 1);
    inverse_butterfly!(poly, 18, 146, 1);
    inverse_butterfly!(poly, 19, 147, 1);
    inverse_butterfly!(poly, 20, 148, 1);
    inverse_butterfly!(poly, 21, 149, 1);
    inverse_butterfly!(poly, 22, 150, 1);
    inverse_butterfly!(poly, 23, 151, 1);
    inverse_butterfly!(poly, 24, 152, 1);
    inverse_butterfly!(poly, 25, 153, 1);
    inverse_butterfly!(poly, 26, 154, 1);
    inverse_butterfly!(poly, 27, 155, 1);
    inverse_butterfly!(poly, 28, 156, 1);
    inverse_butterfly!(poly, 29, 157, 1);
    inverse_butterfly!(poly, 30, 158, 1);
    inverse_butterfly!(poly, 31, 159, 1);
    inverse_butterfly!(poly, 32, 160, 1);
    inverse_butterfly!(poly, 33, 161, 1);
    inverse_butterfly!(poly, 34, 162, 1);
    inverse_butterfly!(poly, 35, 163, 1);
    inverse_butterfly!(poly, 36, 164, 1);
    inverse_butterfly!(poly, 37, 165, 1);
    inverse_butterfly!(poly, 38, 166, 1);
    inverse_butterfly!(poly, 39, 167, 1);
    inverse_butterfly!(poly, 40, 168, 1);
    inverse_butterfly!(poly, 41, 169, 1);
    inverse_butterfly!(poly, 42, 170, 1);
    inverse_butterfly!(poly, 43, 171, 1);
    inverse_butterfly!(poly, 44, 172, 1);
    inverse_butterfly!(poly, 45, 173, 1);
    inverse_butterfly!(poly, 46, 174, 1);
    inverse_butterfly!(poly, 47, 175, 1);
    inverse_butterfly!(poly, 48, 176, 1);
    inverse_butterfly!(poly, 49, 177, 1);
    inverse_butterfly!(poly, 50, 178, 1);
    inverse_butterfly!(poly, 51, 179, 1);
    inverse_butterfly!(poly, 52, 180, 1);
    inverse_butterfly!(poly, 53, 181, 1);
    inverse_butterfly!(poly, 54, 182, 1);
    inverse_butterfly!(poly, 55, 183, 1);
    inverse_butterfly!(poly, 56, 184, 1);
    inverse_butterfly!(poly, 57, 185, 1);
    inverse_butterfly!(poly, 58, 186, 1);
    inverse_butterfly!(poly, 59, 187, 1);
    inverse_butterfly!(poly, 60, 188, 1);
    inverse_butterfly!(poly, 61, 189, 1);
    inverse_butterfly!(poly, 62, 190, 1);
    inverse_butterfly!(poly, 63, 191, 1);
    inverse_butterfly!(poly, 64, 192, 1);
    inverse_butterfly!(poly, 65, 193, 1);
    inverse_butterfly!(poly, 66, 194, 1);
    inverse_butterfly!(poly, 67, 195, 1);
    inverse_butterfly!(poly, 68, 196, 1);
    inverse_butterfly!(poly, 69, 197, 1);
    inverse_butterfly!(poly, 70, 198, 1);
    inverse_butterfly!(poly, 71, 199, 1);
    inverse_butterfly!(poly, 72, 200, 1);
    inverse_butterfly!(poly, 73, 201, 1);
    inverse_butterfly!(poly, 74, 202, 1);
    inverse_butterfly!(poly, 75, 203, 1);
    inverse_butterfly!(poly, 76, 204, 1);
    inverse_butterfly!(poly, 77, 205, 1);
    inverse_butterfly!(poly, 78, 206, 1);
    inverse_butterfly!(poly, 79, 207, 1);
    inverse_butterfly!(poly, 80, 208, 1);
    inverse_butterfly!(poly, 81, 209, 1);
    inverse_butterfly!(poly, 82, 210, 1);
    inverse_butterfly!(poly, 83, 211, 1);
    inverse_butterfly!(poly, 84, 212, 1);
    inverse_butterfly!(poly, 85, 213, 1);
    inverse_butterfly!(poly, 86, 214, 1);
    inverse_butterfly!(poly, 87, 215, 1);
    inverse_butterfly!(poly, 88, 216, 1);
    inverse_butterfly!(poly, 89, 217, 1);
    inverse_butterfly!(poly, 90, 218, 1);
    inverse_butterfly!(poly, 91, 219, 1);
    inverse_butterfly!(poly, 92, 220, 1);
    inverse_butterfly!(poly, 93, 221, 1);
    inverse_butterfly!(poly, 94, 222, 1);
    inverse_butterfly!(poly, 95, 223, 1);
    inverse_butterfly!(poly, 96, 224, 1);
    inverse_butterfly!(poly, 97, 225, 1);
    inverse_butterfly!(poly, 98, 226, 1);
    inverse_butterfly!(poly, 99, 227, 1);
    inverse_butterfly!(poly, 100, 228, 1);
    inverse_butterfly!(poly, 101, 229, 1);
    inverse_butterfly!(poly, 102, 230, 1);
    inverse_butterfly!(poly, 103, 231, 1);
    inverse_butterfly!(poly, 104, 232, 1);
    inverse_butterfly!(poly, 105, 233, 1);
    inverse_butterfly!(poly, 106, 234, 1);
    inverse_butterfly!(poly, 107, 235, 1);
    inverse_butterfly!(poly, 108, 236, 1);
    inverse_butterfly!(poly, 109, 237, 1);
    inverse_butterfly!(poly, 110, 238, 1);
    inverse_butterfly!(poly, 111, 239, 1);
    inverse_butterfly!(poly, 112, 240, 1);
    inverse_butterfly!(poly, 113, 241, 1);
    inverse_butterfly!(poly, 114, 242, 1);
    inverse_butterfly!(poly, 115, 243, 1);
    inverse_butterfly!(poly, 116, 244, 1);
    inverse_butterfly!(poly, 117, 245, 1);
    inverse_butterfly!(poly, 118, 246, 1);
    inverse_butterfly!(poly, 119, 247, 1);
    inverse_butterfly!(poly, 120, 248, 1);
    inverse_butterfly!(poly, 121, 249, 1);
    inverse_butterfly!(poly, 122, 250, 1);
    inverse_butterfly!(poly, 123, 251, 1);
    inverse_butterfly!(poly, 124, 252, 1);
    inverse_butterfly!(poly, 125, 253, 1);
    inverse_butterfly!(poly, 126, 254, 1);
    inverse_butterfly!(poly, 127, 255, 1);
    unsafe {
        let a = core::ptr::read(poly.add(0));
        core::ptr::write(poly.add(0), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(1));
        core::ptr::write(poly.add(1), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(2));
        core::ptr::write(poly.add(2), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(3));
        core::ptr::write(poly.add(3), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(4));
        core::ptr::write(poly.add(4), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(5));
        core::ptr::write(poly.add(5), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(6));
        core::ptr::write(poly.add(6), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(7));
        core::ptr::write(poly.add(7), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(8));
        core::ptr::write(poly.add(8), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(9));
        core::ptr::write(poly.add(9), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(10));
        core::ptr::write(poly.add(10), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(11));
        core::ptr::write(poly.add(11), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(12));
        core::ptr::write(poly.add(12), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(13));
        core::ptr::write(poly.add(13), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(14));
        core::ptr::write(poly.add(14), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(15));
        core::ptr::write(poly.add(15), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(16));
        core::ptr::write(poly.add(16), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(17));
        core::ptr::write(poly.add(17), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(18));
        core::ptr::write(poly.add(18), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(19));
        core::ptr::write(poly.add(19), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(20));
        core::ptr::write(poly.add(20), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(21));
        core::ptr::write(poly.add(21), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(22));
        core::ptr::write(poly.add(22), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(23));
        core::ptr::write(poly.add(23), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(24));
        core::ptr::write(poly.add(24), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(25));
        core::ptr::write(poly.add(25), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(26));
        core::ptr::write(poly.add(26), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(27));
        core::ptr::write(poly.add(27), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(28));
        core::ptr::write(poly.add(28), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(29));
        core::ptr::write(poly.add(29), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(30));
        core::ptr::write(poly.add(30), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(31));
        core::ptr::write(poly.add(31), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(32));
        core::ptr::write(poly.add(32), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(33));
        core::ptr::write(poly.add(33), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(34));
        core::ptr::write(poly.add(34), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(35));
        core::ptr::write(poly.add(35), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(36));
        core::ptr::write(poly.add(36), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(37));
        core::ptr::write(poly.add(37), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(38));
        core::ptr::write(poly.add(38), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(39));
        core::ptr::write(poly.add(39), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(40));
        core::ptr::write(poly.add(40), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(41));
        core::ptr::write(poly.add(41), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(42));
        core::ptr::write(poly.add(42), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(43));
        core::ptr::write(poly.add(43), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(44));
        core::ptr::write(poly.add(44), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(45));
        core::ptr::write(poly.add(45), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(46));
        core::ptr::write(poly.add(46), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(47));
        core::ptr::write(poly.add(47), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(48));
        core::ptr::write(poly.add(48), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(49));
        core::ptr::write(poly.add(49), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(50));
        core::ptr::write(poly.add(50), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(51));
        core::ptr::write(poly.add(51), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(52));
        core::ptr::write(poly.add(52), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(53));
        core::ptr::write(poly.add(53), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(54));
        core::ptr::write(poly.add(54), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(55));
        core::ptr::write(poly.add(55), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(56));
        core::ptr::write(poly.add(56), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(57));
        core::ptr::write(poly.add(57), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(58));
        core::ptr::write(poly.add(58), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(59));
        core::ptr::write(poly.add(59), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(60));
        core::ptr::write(poly.add(60), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(61));
        core::ptr::write(poly.add(61), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(62));
        core::ptr::write(poly.add(62), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(63));
        core::ptr::write(poly.add(63), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(64));
        core::ptr::write(poly.add(64), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(65));
        core::ptr::write(poly.add(65), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(66));
        core::ptr::write(poly.add(66), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(67));
        core::ptr::write(poly.add(67), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(68));
        core::ptr::write(poly.add(68), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(69));
        core::ptr::write(poly.add(69), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(70));
        core::ptr::write(poly.add(70), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(71));
        core::ptr::write(poly.add(71), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(72));
        core::ptr::write(poly.add(72), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(73));
        core::ptr::write(poly.add(73), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(74));
        core::ptr::write(poly.add(74), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(75));
        core::ptr::write(poly.add(75), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(76));
        core::ptr::write(poly.add(76), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(77));
        core::ptr::write(poly.add(77), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(78));
        core::ptr::write(poly.add(78), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(79));
        core::ptr::write(poly.add(79), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(80));
        core::ptr::write(poly.add(80), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(81));
        core::ptr::write(poly.add(81), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(82));
        core::ptr::write(poly.add(82), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(83));
        core::ptr::write(poly.add(83), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(84));
        core::ptr::write(poly.add(84), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(85));
        core::ptr::write(poly.add(85), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(86));
        core::ptr::write(poly.add(86), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(87));
        core::ptr::write(poly.add(87), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(88));
        core::ptr::write(poly.add(88), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(89));
        core::ptr::write(poly.add(89), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(90));
        core::ptr::write(poly.add(90), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(91));
        core::ptr::write(poly.add(91), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(92));
        core::ptr::write(poly.add(92), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(93));
        core::ptr::write(poly.add(93), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(94));
        core::ptr::write(poly.add(94), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(95));
        core::ptr::write(poly.add(95), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(96));
        core::ptr::write(poly.add(96), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(97));
        core::ptr::write(poly.add(97), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(98));
        core::ptr::write(poly.add(98), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(99));
        core::ptr::write(poly.add(99), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(100));
        core::ptr::write(poly.add(100), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(101));
        core::ptr::write(poly.add(101), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(102));
        core::ptr::write(poly.add(102), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(103));
        core::ptr::write(poly.add(103), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(104));
        core::ptr::write(poly.add(104), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(105));
        core::ptr::write(poly.add(105), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(106));
        core::ptr::write(poly.add(106), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(107));
        core::ptr::write(poly.add(107), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(108));
        core::ptr::write(poly.add(108), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(109));
        core::ptr::write(poly.add(109), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(110));
        core::ptr::write(poly.add(110), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(111));
        core::ptr::write(poly.add(111), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(112));
        core::ptr::write(poly.add(112), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(113));
        core::ptr::write(poly.add(113), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(114));
        core::ptr::write(poly.add(114), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(115));
        core::ptr::write(poly.add(115), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(116));
        core::ptr::write(poly.add(116), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(117));
        core::ptr::write(poly.add(117), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(118));
        core::ptr::write(poly.add(118), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(119));
        core::ptr::write(poly.add(119), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(120));
        core::ptr::write(poly.add(120), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(121));
        core::ptr::write(poly.add(121), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(122));
        core::ptr::write(poly.add(122), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(123));
        core::ptr::write(poly.add(123), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(124));
        core::ptr::write(poly.add(124), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(125));
        core::ptr::write(poly.add(125), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(126));
        core::ptr::write(poly.add(126), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(127));
        core::ptr::write(poly.add(127), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(128));
        core::ptr::write(poly.add(128), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(129));
        core::ptr::write(poly.add(129), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(130));
        core::ptr::write(poly.add(130), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(131));
        core::ptr::write(poly.add(131), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(132));
        core::ptr::write(poly.add(132), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(133));
        core::ptr::write(poly.add(133), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(134));
        core::ptr::write(poly.add(134), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(135));
        core::ptr::write(poly.add(135), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(136));
        core::ptr::write(poly.add(136), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(137));
        core::ptr::write(poly.add(137), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(138));
        core::ptr::write(poly.add(138), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(139));
        core::ptr::write(poly.add(139), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(140));
        core::ptr::write(poly.add(140), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(141));
        core::ptr::write(poly.add(141), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(142));
        core::ptr::write(poly.add(142), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(143));
        core::ptr::write(poly.add(143), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(144));
        core::ptr::write(poly.add(144), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(145));
        core::ptr::write(poly.add(145), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(146));
        core::ptr::write(poly.add(146), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(147));
        core::ptr::write(poly.add(147), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(148));
        core::ptr::write(poly.add(148), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(149));
        core::ptr::write(poly.add(149), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(150));
        core::ptr::write(poly.add(150), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(151));
        core::ptr::write(poly.add(151), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(152));
        core::ptr::write(poly.add(152), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(153));
        core::ptr::write(poly.add(153), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(154));
        core::ptr::write(poly.add(154), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(155));
        core::ptr::write(poly.add(155), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(156));
        core::ptr::write(poly.add(156), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(157));
        core::ptr::write(poly.add(157), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(158));
        core::ptr::write(poly.add(158), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(159));
        core::ptr::write(poly.add(159), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(160));
        core::ptr::write(poly.add(160), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(161));
        core::ptr::write(poly.add(161), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(162));
        core::ptr::write(poly.add(162), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(163));
        core::ptr::write(poly.add(163), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(164));
        core::ptr::write(poly.add(164), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(165));
        core::ptr::write(poly.add(165), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(166));
        core::ptr::write(poly.add(166), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(167));
        core::ptr::write(poly.add(167), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(168));
        core::ptr::write(poly.add(168), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(169));
        core::ptr::write(poly.add(169), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(170));
        core::ptr::write(poly.add(170), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(171));
        core::ptr::write(poly.add(171), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(172));
        core::ptr::write(poly.add(172), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(173));
        core::ptr::write(poly.add(173), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(174));
        core::ptr::write(poly.add(174), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(175));
        core::ptr::write(poly.add(175), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(176));
        core::ptr::write(poly.add(176), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(177));
        core::ptr::write(poly.add(177), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(178));
        core::ptr::write(poly.add(178), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(179));
        core::ptr::write(poly.add(179), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(180));
        core::ptr::write(poly.add(180), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(181));
        core::ptr::write(poly.add(181), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(182));
        core::ptr::write(poly.add(182), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(183));
        core::ptr::write(poly.add(183), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(184));
        core::ptr::write(poly.add(184), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(185));
        core::ptr::write(poly.add(185), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(186));
        core::ptr::write(poly.add(186), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(187));
        core::ptr::write(poly.add(187), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(188));
        core::ptr::write(poly.add(188), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(189));
        core::ptr::write(poly.add(189), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(190));
        core::ptr::write(poly.add(190), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(191));
        core::ptr::write(poly.add(191), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(192));
        core::ptr::write(poly.add(192), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(193));
        core::ptr::write(poly.add(193), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(194));
        core::ptr::write(poly.add(194), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(195));
        core::ptr::write(poly.add(195), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(196));
        core::ptr::write(poly.add(196), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(197));
        core::ptr::write(poly.add(197), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(198));
        core::ptr::write(poly.add(198), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(199));
        core::ptr::write(poly.add(199), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(200));
        core::ptr::write(poly.add(200), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(201));
        core::ptr::write(poly.add(201), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(202));
        core::ptr::write(poly.add(202), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(203));
        core::ptr::write(poly.add(203), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(204));
        core::ptr::write(poly.add(204), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(205));
        core::ptr::write(poly.add(205), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(206));
        core::ptr::write(poly.add(206), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(207));
        core::ptr::write(poly.add(207), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(208));
        core::ptr::write(poly.add(208), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(209));
        core::ptr::write(poly.add(209), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(210));
        core::ptr::write(poly.add(210), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(211));
        core::ptr::write(poly.add(211), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(212));
        core::ptr::write(poly.add(212), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(213));
        core::ptr::write(poly.add(213), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(214));
        core::ptr::write(poly.add(214), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(215));
        core::ptr::write(poly.add(215), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(216));
        core::ptr::write(poly.add(216), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(217));
        core::ptr::write(poly.add(217), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(218));
        core::ptr::write(poly.add(218), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(219));
        core::ptr::write(poly.add(219), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(220));
        core::ptr::write(poly.add(220), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(221));
        core::ptr::write(poly.add(221), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(222));
        core::ptr::write(poly.add(222), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(223));
        core::ptr::write(poly.add(223), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(224));
        core::ptr::write(poly.add(224), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(225));
        core::ptr::write(poly.add(225), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(226));
        core::ptr::write(poly.add(226), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(227));
        core::ptr::write(poly.add(227), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(228));
        core::ptr::write(poly.add(228), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(229));
        core::ptr::write(poly.add(229), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(230));
        core::ptr::write(poly.add(230), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(231));
        core::ptr::write(poly.add(231), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(232));
        core::ptr::write(poly.add(232), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(233));
        core::ptr::write(poly.add(233), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(234));
        core::ptr::write(poly.add(234), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(235));
        core::ptr::write(poly.add(235), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(236));
        core::ptr::write(poly.add(236), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(237));
        core::ptr::write(poly.add(237), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(238));
        core::ptr::write(poly.add(238), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(239));
        core::ptr::write(poly.add(239), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(240));
        core::ptr::write(poly.add(240), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(241));
        core::ptr::write(poly.add(241), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(242));
        core::ptr::write(poly.add(242), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(243));
        core::ptr::write(poly.add(243), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(244));
        core::ptr::write(poly.add(244), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(245));
        core::ptr::write(poly.add(245), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(246));
        core::ptr::write(poly.add(246), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(247));
        core::ptr::write(poly.add(247), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(248));
        core::ptr::write(poly.add(248), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(249));
        core::ptr::write(poly.add(249), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(250));
        core::ptr::write(poly.add(250), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(251));
        core::ptr::write(poly.add(251), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(252));
        core::ptr::write(poly.add(252), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(253));
        core::ptr::write(poly.add(253), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(254));
        core::ptr::write(poly.add(254), reduce!(MONT_F as i64 * a as i64));
    }
    unsafe {
        let a = core::ptr::read(poly.add(255));
        core::ptr::write(poly.add(255), reduce!(MONT_F as i64 * a as i64));
    }
    0
}
/// Fixed-size coefficient multiplication; O(256) time and O(1) workspace.
#[no_mangle]
#[inline(never)]
pub extern "C" fn vk_poly_pointwise_montgomery_ct(
    out: *mut i32,
    a: *const i32,
    b: *const i32,
) -> i32 {
    if out.is_null() || a.is_null() || b.is_null() {
        return -1;
    }
    unsafe {
        core::ptr::write(
            out.add(0),
            reduce!(core::ptr::read(a.add(0)) as i64 * core::ptr::read(b.add(0)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(1),
            reduce!(core::ptr::read(a.add(1)) as i64 * core::ptr::read(b.add(1)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(2),
            reduce!(core::ptr::read(a.add(2)) as i64 * core::ptr::read(b.add(2)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(3),
            reduce!(core::ptr::read(a.add(3)) as i64 * core::ptr::read(b.add(3)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(4),
            reduce!(core::ptr::read(a.add(4)) as i64 * core::ptr::read(b.add(4)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(5),
            reduce!(core::ptr::read(a.add(5)) as i64 * core::ptr::read(b.add(5)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(6),
            reduce!(core::ptr::read(a.add(6)) as i64 * core::ptr::read(b.add(6)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(7),
            reduce!(core::ptr::read(a.add(7)) as i64 * core::ptr::read(b.add(7)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(8),
            reduce!(core::ptr::read(a.add(8)) as i64 * core::ptr::read(b.add(8)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(9),
            reduce!(core::ptr::read(a.add(9)) as i64 * core::ptr::read(b.add(9)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(10),
            reduce!(core::ptr::read(a.add(10)) as i64 * core::ptr::read(b.add(10)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(11),
            reduce!(core::ptr::read(a.add(11)) as i64 * core::ptr::read(b.add(11)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(12),
            reduce!(core::ptr::read(a.add(12)) as i64 * core::ptr::read(b.add(12)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(13),
            reduce!(core::ptr::read(a.add(13)) as i64 * core::ptr::read(b.add(13)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(14),
            reduce!(core::ptr::read(a.add(14)) as i64 * core::ptr::read(b.add(14)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(15),
            reduce!(core::ptr::read(a.add(15)) as i64 * core::ptr::read(b.add(15)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(16),
            reduce!(core::ptr::read(a.add(16)) as i64 * core::ptr::read(b.add(16)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(17),
            reduce!(core::ptr::read(a.add(17)) as i64 * core::ptr::read(b.add(17)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(18),
            reduce!(core::ptr::read(a.add(18)) as i64 * core::ptr::read(b.add(18)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(19),
            reduce!(core::ptr::read(a.add(19)) as i64 * core::ptr::read(b.add(19)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(20),
            reduce!(core::ptr::read(a.add(20)) as i64 * core::ptr::read(b.add(20)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(21),
            reduce!(core::ptr::read(a.add(21)) as i64 * core::ptr::read(b.add(21)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(22),
            reduce!(core::ptr::read(a.add(22)) as i64 * core::ptr::read(b.add(22)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(23),
            reduce!(core::ptr::read(a.add(23)) as i64 * core::ptr::read(b.add(23)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(24),
            reduce!(core::ptr::read(a.add(24)) as i64 * core::ptr::read(b.add(24)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(25),
            reduce!(core::ptr::read(a.add(25)) as i64 * core::ptr::read(b.add(25)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(26),
            reduce!(core::ptr::read(a.add(26)) as i64 * core::ptr::read(b.add(26)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(27),
            reduce!(core::ptr::read(a.add(27)) as i64 * core::ptr::read(b.add(27)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(28),
            reduce!(core::ptr::read(a.add(28)) as i64 * core::ptr::read(b.add(28)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(29),
            reduce!(core::ptr::read(a.add(29)) as i64 * core::ptr::read(b.add(29)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(30),
            reduce!(core::ptr::read(a.add(30)) as i64 * core::ptr::read(b.add(30)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(31),
            reduce!(core::ptr::read(a.add(31)) as i64 * core::ptr::read(b.add(31)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(32),
            reduce!(core::ptr::read(a.add(32)) as i64 * core::ptr::read(b.add(32)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(33),
            reduce!(core::ptr::read(a.add(33)) as i64 * core::ptr::read(b.add(33)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(34),
            reduce!(core::ptr::read(a.add(34)) as i64 * core::ptr::read(b.add(34)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(35),
            reduce!(core::ptr::read(a.add(35)) as i64 * core::ptr::read(b.add(35)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(36),
            reduce!(core::ptr::read(a.add(36)) as i64 * core::ptr::read(b.add(36)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(37),
            reduce!(core::ptr::read(a.add(37)) as i64 * core::ptr::read(b.add(37)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(38),
            reduce!(core::ptr::read(a.add(38)) as i64 * core::ptr::read(b.add(38)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(39),
            reduce!(core::ptr::read(a.add(39)) as i64 * core::ptr::read(b.add(39)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(40),
            reduce!(core::ptr::read(a.add(40)) as i64 * core::ptr::read(b.add(40)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(41),
            reduce!(core::ptr::read(a.add(41)) as i64 * core::ptr::read(b.add(41)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(42),
            reduce!(core::ptr::read(a.add(42)) as i64 * core::ptr::read(b.add(42)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(43),
            reduce!(core::ptr::read(a.add(43)) as i64 * core::ptr::read(b.add(43)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(44),
            reduce!(core::ptr::read(a.add(44)) as i64 * core::ptr::read(b.add(44)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(45),
            reduce!(core::ptr::read(a.add(45)) as i64 * core::ptr::read(b.add(45)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(46),
            reduce!(core::ptr::read(a.add(46)) as i64 * core::ptr::read(b.add(46)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(47),
            reduce!(core::ptr::read(a.add(47)) as i64 * core::ptr::read(b.add(47)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(48),
            reduce!(core::ptr::read(a.add(48)) as i64 * core::ptr::read(b.add(48)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(49),
            reduce!(core::ptr::read(a.add(49)) as i64 * core::ptr::read(b.add(49)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(50),
            reduce!(core::ptr::read(a.add(50)) as i64 * core::ptr::read(b.add(50)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(51),
            reduce!(core::ptr::read(a.add(51)) as i64 * core::ptr::read(b.add(51)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(52),
            reduce!(core::ptr::read(a.add(52)) as i64 * core::ptr::read(b.add(52)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(53),
            reduce!(core::ptr::read(a.add(53)) as i64 * core::ptr::read(b.add(53)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(54),
            reduce!(core::ptr::read(a.add(54)) as i64 * core::ptr::read(b.add(54)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(55),
            reduce!(core::ptr::read(a.add(55)) as i64 * core::ptr::read(b.add(55)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(56),
            reduce!(core::ptr::read(a.add(56)) as i64 * core::ptr::read(b.add(56)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(57),
            reduce!(core::ptr::read(a.add(57)) as i64 * core::ptr::read(b.add(57)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(58),
            reduce!(core::ptr::read(a.add(58)) as i64 * core::ptr::read(b.add(58)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(59),
            reduce!(core::ptr::read(a.add(59)) as i64 * core::ptr::read(b.add(59)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(60),
            reduce!(core::ptr::read(a.add(60)) as i64 * core::ptr::read(b.add(60)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(61),
            reduce!(core::ptr::read(a.add(61)) as i64 * core::ptr::read(b.add(61)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(62),
            reduce!(core::ptr::read(a.add(62)) as i64 * core::ptr::read(b.add(62)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(63),
            reduce!(core::ptr::read(a.add(63)) as i64 * core::ptr::read(b.add(63)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(64),
            reduce!(core::ptr::read(a.add(64)) as i64 * core::ptr::read(b.add(64)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(65),
            reduce!(core::ptr::read(a.add(65)) as i64 * core::ptr::read(b.add(65)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(66),
            reduce!(core::ptr::read(a.add(66)) as i64 * core::ptr::read(b.add(66)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(67),
            reduce!(core::ptr::read(a.add(67)) as i64 * core::ptr::read(b.add(67)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(68),
            reduce!(core::ptr::read(a.add(68)) as i64 * core::ptr::read(b.add(68)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(69),
            reduce!(core::ptr::read(a.add(69)) as i64 * core::ptr::read(b.add(69)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(70),
            reduce!(core::ptr::read(a.add(70)) as i64 * core::ptr::read(b.add(70)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(71),
            reduce!(core::ptr::read(a.add(71)) as i64 * core::ptr::read(b.add(71)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(72),
            reduce!(core::ptr::read(a.add(72)) as i64 * core::ptr::read(b.add(72)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(73),
            reduce!(core::ptr::read(a.add(73)) as i64 * core::ptr::read(b.add(73)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(74),
            reduce!(core::ptr::read(a.add(74)) as i64 * core::ptr::read(b.add(74)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(75),
            reduce!(core::ptr::read(a.add(75)) as i64 * core::ptr::read(b.add(75)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(76),
            reduce!(core::ptr::read(a.add(76)) as i64 * core::ptr::read(b.add(76)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(77),
            reduce!(core::ptr::read(a.add(77)) as i64 * core::ptr::read(b.add(77)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(78),
            reduce!(core::ptr::read(a.add(78)) as i64 * core::ptr::read(b.add(78)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(79),
            reduce!(core::ptr::read(a.add(79)) as i64 * core::ptr::read(b.add(79)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(80),
            reduce!(core::ptr::read(a.add(80)) as i64 * core::ptr::read(b.add(80)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(81),
            reduce!(core::ptr::read(a.add(81)) as i64 * core::ptr::read(b.add(81)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(82),
            reduce!(core::ptr::read(a.add(82)) as i64 * core::ptr::read(b.add(82)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(83),
            reduce!(core::ptr::read(a.add(83)) as i64 * core::ptr::read(b.add(83)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(84),
            reduce!(core::ptr::read(a.add(84)) as i64 * core::ptr::read(b.add(84)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(85),
            reduce!(core::ptr::read(a.add(85)) as i64 * core::ptr::read(b.add(85)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(86),
            reduce!(core::ptr::read(a.add(86)) as i64 * core::ptr::read(b.add(86)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(87),
            reduce!(core::ptr::read(a.add(87)) as i64 * core::ptr::read(b.add(87)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(88),
            reduce!(core::ptr::read(a.add(88)) as i64 * core::ptr::read(b.add(88)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(89),
            reduce!(core::ptr::read(a.add(89)) as i64 * core::ptr::read(b.add(89)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(90),
            reduce!(core::ptr::read(a.add(90)) as i64 * core::ptr::read(b.add(90)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(91),
            reduce!(core::ptr::read(a.add(91)) as i64 * core::ptr::read(b.add(91)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(92),
            reduce!(core::ptr::read(a.add(92)) as i64 * core::ptr::read(b.add(92)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(93),
            reduce!(core::ptr::read(a.add(93)) as i64 * core::ptr::read(b.add(93)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(94),
            reduce!(core::ptr::read(a.add(94)) as i64 * core::ptr::read(b.add(94)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(95),
            reduce!(core::ptr::read(a.add(95)) as i64 * core::ptr::read(b.add(95)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(96),
            reduce!(core::ptr::read(a.add(96)) as i64 * core::ptr::read(b.add(96)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(97),
            reduce!(core::ptr::read(a.add(97)) as i64 * core::ptr::read(b.add(97)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(98),
            reduce!(core::ptr::read(a.add(98)) as i64 * core::ptr::read(b.add(98)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(99),
            reduce!(core::ptr::read(a.add(99)) as i64 * core::ptr::read(b.add(99)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(100),
            reduce!(core::ptr::read(a.add(100)) as i64 * core::ptr::read(b.add(100)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(101),
            reduce!(core::ptr::read(a.add(101)) as i64 * core::ptr::read(b.add(101)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(102),
            reduce!(core::ptr::read(a.add(102)) as i64 * core::ptr::read(b.add(102)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(103),
            reduce!(core::ptr::read(a.add(103)) as i64 * core::ptr::read(b.add(103)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(104),
            reduce!(core::ptr::read(a.add(104)) as i64 * core::ptr::read(b.add(104)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(105),
            reduce!(core::ptr::read(a.add(105)) as i64 * core::ptr::read(b.add(105)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(106),
            reduce!(core::ptr::read(a.add(106)) as i64 * core::ptr::read(b.add(106)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(107),
            reduce!(core::ptr::read(a.add(107)) as i64 * core::ptr::read(b.add(107)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(108),
            reduce!(core::ptr::read(a.add(108)) as i64 * core::ptr::read(b.add(108)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(109),
            reduce!(core::ptr::read(a.add(109)) as i64 * core::ptr::read(b.add(109)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(110),
            reduce!(core::ptr::read(a.add(110)) as i64 * core::ptr::read(b.add(110)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(111),
            reduce!(core::ptr::read(a.add(111)) as i64 * core::ptr::read(b.add(111)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(112),
            reduce!(core::ptr::read(a.add(112)) as i64 * core::ptr::read(b.add(112)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(113),
            reduce!(core::ptr::read(a.add(113)) as i64 * core::ptr::read(b.add(113)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(114),
            reduce!(core::ptr::read(a.add(114)) as i64 * core::ptr::read(b.add(114)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(115),
            reduce!(core::ptr::read(a.add(115)) as i64 * core::ptr::read(b.add(115)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(116),
            reduce!(core::ptr::read(a.add(116)) as i64 * core::ptr::read(b.add(116)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(117),
            reduce!(core::ptr::read(a.add(117)) as i64 * core::ptr::read(b.add(117)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(118),
            reduce!(core::ptr::read(a.add(118)) as i64 * core::ptr::read(b.add(118)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(119),
            reduce!(core::ptr::read(a.add(119)) as i64 * core::ptr::read(b.add(119)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(120),
            reduce!(core::ptr::read(a.add(120)) as i64 * core::ptr::read(b.add(120)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(121),
            reduce!(core::ptr::read(a.add(121)) as i64 * core::ptr::read(b.add(121)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(122),
            reduce!(core::ptr::read(a.add(122)) as i64 * core::ptr::read(b.add(122)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(123),
            reduce!(core::ptr::read(a.add(123)) as i64 * core::ptr::read(b.add(123)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(124),
            reduce!(core::ptr::read(a.add(124)) as i64 * core::ptr::read(b.add(124)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(125),
            reduce!(core::ptr::read(a.add(125)) as i64 * core::ptr::read(b.add(125)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(126),
            reduce!(core::ptr::read(a.add(126)) as i64 * core::ptr::read(b.add(126)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(127),
            reduce!(core::ptr::read(a.add(127)) as i64 * core::ptr::read(b.add(127)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(128),
            reduce!(core::ptr::read(a.add(128)) as i64 * core::ptr::read(b.add(128)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(129),
            reduce!(core::ptr::read(a.add(129)) as i64 * core::ptr::read(b.add(129)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(130),
            reduce!(core::ptr::read(a.add(130)) as i64 * core::ptr::read(b.add(130)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(131),
            reduce!(core::ptr::read(a.add(131)) as i64 * core::ptr::read(b.add(131)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(132),
            reduce!(core::ptr::read(a.add(132)) as i64 * core::ptr::read(b.add(132)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(133),
            reduce!(core::ptr::read(a.add(133)) as i64 * core::ptr::read(b.add(133)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(134),
            reduce!(core::ptr::read(a.add(134)) as i64 * core::ptr::read(b.add(134)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(135),
            reduce!(core::ptr::read(a.add(135)) as i64 * core::ptr::read(b.add(135)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(136),
            reduce!(core::ptr::read(a.add(136)) as i64 * core::ptr::read(b.add(136)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(137),
            reduce!(core::ptr::read(a.add(137)) as i64 * core::ptr::read(b.add(137)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(138),
            reduce!(core::ptr::read(a.add(138)) as i64 * core::ptr::read(b.add(138)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(139),
            reduce!(core::ptr::read(a.add(139)) as i64 * core::ptr::read(b.add(139)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(140),
            reduce!(core::ptr::read(a.add(140)) as i64 * core::ptr::read(b.add(140)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(141),
            reduce!(core::ptr::read(a.add(141)) as i64 * core::ptr::read(b.add(141)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(142),
            reduce!(core::ptr::read(a.add(142)) as i64 * core::ptr::read(b.add(142)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(143),
            reduce!(core::ptr::read(a.add(143)) as i64 * core::ptr::read(b.add(143)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(144),
            reduce!(core::ptr::read(a.add(144)) as i64 * core::ptr::read(b.add(144)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(145),
            reduce!(core::ptr::read(a.add(145)) as i64 * core::ptr::read(b.add(145)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(146),
            reduce!(core::ptr::read(a.add(146)) as i64 * core::ptr::read(b.add(146)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(147),
            reduce!(core::ptr::read(a.add(147)) as i64 * core::ptr::read(b.add(147)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(148),
            reduce!(core::ptr::read(a.add(148)) as i64 * core::ptr::read(b.add(148)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(149),
            reduce!(core::ptr::read(a.add(149)) as i64 * core::ptr::read(b.add(149)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(150),
            reduce!(core::ptr::read(a.add(150)) as i64 * core::ptr::read(b.add(150)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(151),
            reduce!(core::ptr::read(a.add(151)) as i64 * core::ptr::read(b.add(151)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(152),
            reduce!(core::ptr::read(a.add(152)) as i64 * core::ptr::read(b.add(152)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(153),
            reduce!(core::ptr::read(a.add(153)) as i64 * core::ptr::read(b.add(153)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(154),
            reduce!(core::ptr::read(a.add(154)) as i64 * core::ptr::read(b.add(154)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(155),
            reduce!(core::ptr::read(a.add(155)) as i64 * core::ptr::read(b.add(155)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(156),
            reduce!(core::ptr::read(a.add(156)) as i64 * core::ptr::read(b.add(156)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(157),
            reduce!(core::ptr::read(a.add(157)) as i64 * core::ptr::read(b.add(157)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(158),
            reduce!(core::ptr::read(a.add(158)) as i64 * core::ptr::read(b.add(158)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(159),
            reduce!(core::ptr::read(a.add(159)) as i64 * core::ptr::read(b.add(159)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(160),
            reduce!(core::ptr::read(a.add(160)) as i64 * core::ptr::read(b.add(160)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(161),
            reduce!(core::ptr::read(a.add(161)) as i64 * core::ptr::read(b.add(161)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(162),
            reduce!(core::ptr::read(a.add(162)) as i64 * core::ptr::read(b.add(162)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(163),
            reduce!(core::ptr::read(a.add(163)) as i64 * core::ptr::read(b.add(163)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(164),
            reduce!(core::ptr::read(a.add(164)) as i64 * core::ptr::read(b.add(164)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(165),
            reduce!(core::ptr::read(a.add(165)) as i64 * core::ptr::read(b.add(165)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(166),
            reduce!(core::ptr::read(a.add(166)) as i64 * core::ptr::read(b.add(166)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(167),
            reduce!(core::ptr::read(a.add(167)) as i64 * core::ptr::read(b.add(167)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(168),
            reduce!(core::ptr::read(a.add(168)) as i64 * core::ptr::read(b.add(168)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(169),
            reduce!(core::ptr::read(a.add(169)) as i64 * core::ptr::read(b.add(169)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(170),
            reduce!(core::ptr::read(a.add(170)) as i64 * core::ptr::read(b.add(170)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(171),
            reduce!(core::ptr::read(a.add(171)) as i64 * core::ptr::read(b.add(171)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(172),
            reduce!(core::ptr::read(a.add(172)) as i64 * core::ptr::read(b.add(172)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(173),
            reduce!(core::ptr::read(a.add(173)) as i64 * core::ptr::read(b.add(173)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(174),
            reduce!(core::ptr::read(a.add(174)) as i64 * core::ptr::read(b.add(174)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(175),
            reduce!(core::ptr::read(a.add(175)) as i64 * core::ptr::read(b.add(175)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(176),
            reduce!(core::ptr::read(a.add(176)) as i64 * core::ptr::read(b.add(176)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(177),
            reduce!(core::ptr::read(a.add(177)) as i64 * core::ptr::read(b.add(177)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(178),
            reduce!(core::ptr::read(a.add(178)) as i64 * core::ptr::read(b.add(178)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(179),
            reduce!(core::ptr::read(a.add(179)) as i64 * core::ptr::read(b.add(179)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(180),
            reduce!(core::ptr::read(a.add(180)) as i64 * core::ptr::read(b.add(180)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(181),
            reduce!(core::ptr::read(a.add(181)) as i64 * core::ptr::read(b.add(181)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(182),
            reduce!(core::ptr::read(a.add(182)) as i64 * core::ptr::read(b.add(182)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(183),
            reduce!(core::ptr::read(a.add(183)) as i64 * core::ptr::read(b.add(183)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(184),
            reduce!(core::ptr::read(a.add(184)) as i64 * core::ptr::read(b.add(184)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(185),
            reduce!(core::ptr::read(a.add(185)) as i64 * core::ptr::read(b.add(185)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(186),
            reduce!(core::ptr::read(a.add(186)) as i64 * core::ptr::read(b.add(186)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(187),
            reduce!(core::ptr::read(a.add(187)) as i64 * core::ptr::read(b.add(187)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(188),
            reduce!(core::ptr::read(a.add(188)) as i64 * core::ptr::read(b.add(188)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(189),
            reduce!(core::ptr::read(a.add(189)) as i64 * core::ptr::read(b.add(189)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(190),
            reduce!(core::ptr::read(a.add(190)) as i64 * core::ptr::read(b.add(190)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(191),
            reduce!(core::ptr::read(a.add(191)) as i64 * core::ptr::read(b.add(191)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(192),
            reduce!(core::ptr::read(a.add(192)) as i64 * core::ptr::read(b.add(192)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(193),
            reduce!(core::ptr::read(a.add(193)) as i64 * core::ptr::read(b.add(193)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(194),
            reduce!(core::ptr::read(a.add(194)) as i64 * core::ptr::read(b.add(194)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(195),
            reduce!(core::ptr::read(a.add(195)) as i64 * core::ptr::read(b.add(195)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(196),
            reduce!(core::ptr::read(a.add(196)) as i64 * core::ptr::read(b.add(196)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(197),
            reduce!(core::ptr::read(a.add(197)) as i64 * core::ptr::read(b.add(197)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(198),
            reduce!(core::ptr::read(a.add(198)) as i64 * core::ptr::read(b.add(198)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(199),
            reduce!(core::ptr::read(a.add(199)) as i64 * core::ptr::read(b.add(199)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(200),
            reduce!(core::ptr::read(a.add(200)) as i64 * core::ptr::read(b.add(200)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(201),
            reduce!(core::ptr::read(a.add(201)) as i64 * core::ptr::read(b.add(201)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(202),
            reduce!(core::ptr::read(a.add(202)) as i64 * core::ptr::read(b.add(202)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(203),
            reduce!(core::ptr::read(a.add(203)) as i64 * core::ptr::read(b.add(203)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(204),
            reduce!(core::ptr::read(a.add(204)) as i64 * core::ptr::read(b.add(204)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(205),
            reduce!(core::ptr::read(a.add(205)) as i64 * core::ptr::read(b.add(205)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(206),
            reduce!(core::ptr::read(a.add(206)) as i64 * core::ptr::read(b.add(206)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(207),
            reduce!(core::ptr::read(a.add(207)) as i64 * core::ptr::read(b.add(207)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(208),
            reduce!(core::ptr::read(a.add(208)) as i64 * core::ptr::read(b.add(208)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(209),
            reduce!(core::ptr::read(a.add(209)) as i64 * core::ptr::read(b.add(209)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(210),
            reduce!(core::ptr::read(a.add(210)) as i64 * core::ptr::read(b.add(210)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(211),
            reduce!(core::ptr::read(a.add(211)) as i64 * core::ptr::read(b.add(211)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(212),
            reduce!(core::ptr::read(a.add(212)) as i64 * core::ptr::read(b.add(212)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(213),
            reduce!(core::ptr::read(a.add(213)) as i64 * core::ptr::read(b.add(213)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(214),
            reduce!(core::ptr::read(a.add(214)) as i64 * core::ptr::read(b.add(214)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(215),
            reduce!(core::ptr::read(a.add(215)) as i64 * core::ptr::read(b.add(215)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(216),
            reduce!(core::ptr::read(a.add(216)) as i64 * core::ptr::read(b.add(216)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(217),
            reduce!(core::ptr::read(a.add(217)) as i64 * core::ptr::read(b.add(217)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(218),
            reduce!(core::ptr::read(a.add(218)) as i64 * core::ptr::read(b.add(218)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(219),
            reduce!(core::ptr::read(a.add(219)) as i64 * core::ptr::read(b.add(219)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(220),
            reduce!(core::ptr::read(a.add(220)) as i64 * core::ptr::read(b.add(220)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(221),
            reduce!(core::ptr::read(a.add(221)) as i64 * core::ptr::read(b.add(221)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(222),
            reduce!(core::ptr::read(a.add(222)) as i64 * core::ptr::read(b.add(222)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(223),
            reduce!(core::ptr::read(a.add(223)) as i64 * core::ptr::read(b.add(223)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(224),
            reduce!(core::ptr::read(a.add(224)) as i64 * core::ptr::read(b.add(224)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(225),
            reduce!(core::ptr::read(a.add(225)) as i64 * core::ptr::read(b.add(225)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(226),
            reduce!(core::ptr::read(a.add(226)) as i64 * core::ptr::read(b.add(226)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(227),
            reduce!(core::ptr::read(a.add(227)) as i64 * core::ptr::read(b.add(227)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(228),
            reduce!(core::ptr::read(a.add(228)) as i64 * core::ptr::read(b.add(228)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(229),
            reduce!(core::ptr::read(a.add(229)) as i64 * core::ptr::read(b.add(229)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(230),
            reduce!(core::ptr::read(a.add(230)) as i64 * core::ptr::read(b.add(230)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(231),
            reduce!(core::ptr::read(a.add(231)) as i64 * core::ptr::read(b.add(231)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(232),
            reduce!(core::ptr::read(a.add(232)) as i64 * core::ptr::read(b.add(232)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(233),
            reduce!(core::ptr::read(a.add(233)) as i64 * core::ptr::read(b.add(233)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(234),
            reduce!(core::ptr::read(a.add(234)) as i64 * core::ptr::read(b.add(234)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(235),
            reduce!(core::ptr::read(a.add(235)) as i64 * core::ptr::read(b.add(235)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(236),
            reduce!(core::ptr::read(a.add(236)) as i64 * core::ptr::read(b.add(236)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(237),
            reduce!(core::ptr::read(a.add(237)) as i64 * core::ptr::read(b.add(237)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(238),
            reduce!(core::ptr::read(a.add(238)) as i64 * core::ptr::read(b.add(238)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(239),
            reduce!(core::ptr::read(a.add(239)) as i64 * core::ptr::read(b.add(239)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(240),
            reduce!(core::ptr::read(a.add(240)) as i64 * core::ptr::read(b.add(240)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(241),
            reduce!(core::ptr::read(a.add(241)) as i64 * core::ptr::read(b.add(241)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(242),
            reduce!(core::ptr::read(a.add(242)) as i64 * core::ptr::read(b.add(242)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(243),
            reduce!(core::ptr::read(a.add(243)) as i64 * core::ptr::read(b.add(243)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(244),
            reduce!(core::ptr::read(a.add(244)) as i64 * core::ptr::read(b.add(244)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(245),
            reduce!(core::ptr::read(a.add(245)) as i64 * core::ptr::read(b.add(245)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(246),
            reduce!(core::ptr::read(a.add(246)) as i64 * core::ptr::read(b.add(246)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(247),
            reduce!(core::ptr::read(a.add(247)) as i64 * core::ptr::read(b.add(247)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(248),
            reduce!(core::ptr::read(a.add(248)) as i64 * core::ptr::read(b.add(248)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(249),
            reduce!(core::ptr::read(a.add(249)) as i64 * core::ptr::read(b.add(249)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(250),
            reduce!(core::ptr::read(a.add(250)) as i64 * core::ptr::read(b.add(250)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(251),
            reduce!(core::ptr::read(a.add(251)) as i64 * core::ptr::read(b.add(251)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(252),
            reduce!(core::ptr::read(a.add(252)) as i64 * core::ptr::read(b.add(252)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(253),
            reduce!(core::ptr::read(a.add(253)) as i64 * core::ptr::read(b.add(253)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(254),
            reduce!(core::ptr::read(a.add(254)) as i64 * core::ptr::read(b.add(254)) as i64),
        );
    }
    unsafe {
        core::ptr::write(
            out.add(255),
            reduce!(core::ptr::read(a.add(255)) as i64 * core::ptr::read(b.add(255)) as i64),
        );
    }
    0
}
#[cfg(test)]
mod tests {
    /// Exercise scalar and fixed-size bounds; O(256) time and space.
    #[test]
    fn arithmetic_boundaries() -> () {
        assert_eq!(super::ZETAS[1], 25847);
        assert_eq!(super::vk_caddq_ct(-1), super::Q - 1);
        assert_eq!(super::vk_montgomery_reduce_ct(0), 0);
        let mut p = [0i32; 256];
        assert_eq!(super::vk_poly_chknorm_ct(p.as_ptr(), 100), 0);
        p[255] = -100;
        assert_eq!(super::vk_poly_chknorm_ct(p.as_ptr(), 100), 1);
        assert_eq!(super::vk_ntt_256_ct(core::ptr::null_mut()), -1);
    }
}
