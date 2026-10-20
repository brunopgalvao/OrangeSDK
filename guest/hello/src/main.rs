#![no_std]
#![no_main]

static GREETING: &[u8] = b"hello, solo";
static mut COUNTER: u64 = 0;

fn main(a0: u64, a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> (u64, u64) {
    let mut digest = [0u8; 32];
    // SAFETY: GREETING is valid memory of the stated length; digest is 32 bytes.
    unsafe {
        solo_guest::host::__solo_import_hash_keccak256(GREETING.as_ptr(), GREETING.len() as u32, digest.as_mut_ptr());
        COUNTER += 1;
    }
    solo_guest::output(&digest);
    // SAFETY: single-threaded guest.
    let count = unsafe { COUNTER };
    (a0.wrapping_add(a1), count)
}

solo_guest::solo_main!(main);
