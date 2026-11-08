#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod crypto;
mod gui;
mod ops;
mod stego;
mod util;

use std::alloc::{GlobalAlloc, Layout, System};
use zeroize::Zeroize;

/// Allocator that wipes every block of memory before returning it to the
/// system: keys, passwords, file buffers and the internal state of the
/// compressor and Argon2 never linger in freed memory.
struct WipingAlloc;

unsafe impl GlobalAlloc for WipingAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe {
            std::slice::from_raw_parts_mut(p, l.size()).zeroize();
            System.dealloc(p, l)
        }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            let new_layout = Layout::from_size_align_unchecked(new_size, l.align());
            let np = System.alloc(new_layout);
            if !np.is_null() {
                std::ptr::copy_nonoverlapping(p, np, l.size().min(new_size));
                self.dealloc(p, l);
            }
            np
        }
    }
}

#[global_allocator]
static ALLOC: WipingAlloc = WipingAlloc;

fn main() -> eframe::Result<()> {
    gui::run()
}
