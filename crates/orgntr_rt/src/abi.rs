#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FardVal {
    pub tag: u32,
    pub pad: u32,      // Explicit 4-byte padding for 8-byte payload alignment
    pub payload: u64,  // i64 bits or bool 0/1
}

pub const TAG_INT: u32 = 0;
pub const TAG_BOOL: u32 = 1;

impl FardVal {
    #[inline]
    pub fn int(val: i64) -> Self {
        Self { tag: TAG_INT, pad: 0, payload: val as u64 }
    }

    #[inline]
    pub fn bool(val: bool) -> Self {
        Self { tag: TAG_BOOL, pad: 0, payload: if val { 1 } else { 0 } }
    }

    #[inline]
    pub fn as_i64(self) -> i64 {
        self.payload as i64
    }

    #[inline]
    pub fn as_bool(self) -> bool {
        self.payload != 0
    }
}
