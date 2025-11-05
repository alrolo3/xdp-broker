#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Backend {
    pub if_index: u32,
    pub flags: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

// You might need these derives for the BPF map
impl Default for Backend {
    fn default() -> Self {
        Self {
            if_index: 0,
            flags: 0,
        }
    }
}