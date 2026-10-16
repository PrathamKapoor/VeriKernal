//! Bounded PE64 thunk inspection; O(I + T) time, O(T) enumeration output space.

/// One mapped import slot; O(B) symbol-name storage.
#[derive(Debug, PartialEq)]
pub struct ImportThunk {
    pub library: String,
    pub symbol: String,
    pub offset: usize,
    pub address: u64,
}

/// Enumerate named and ordinal imports in a mapped image; O(B + T) time and space.
pub fn enumerate_imports(image: &[u8]) -> Result<Vec<ImportThunk>, &'static str> {
    let parse = || -> Option<Vec<ImportThunk>> {
        if image.get(..2)? != b"MZ" {
            return None;
        }
        let pe = word(image, 60, 4)? as usize;
        if image.get(pe..pe + 4)? != b"PE\0\0" || word(image, pe + 24, 2)? != 0x20b {
            return None;
        }
        let directory = word(image, pe + 24 + 120, 4)? as usize;
        let size = word(image, pe + 24 + 124, 4)? as usize;
        let mut result = Vec::new();
        if directory == 0 && size == 0 {
            return Some(result);
        }
        image.get(directory..directory.checked_add(size)?)?;
        for index in 0..size / 20 {
            let entry = directory + 20 * index;
            let original = word(image, entry, 4)? as usize;
            let dll_name = word(image, entry + 12, 4)? as usize;
            let first = word(image, entry + 16, 4)? as usize;
            if dll_name == 0 && first == 0 {
                return Some(result);
            }
            let library = std::str::from_utf8(name(image, dll_name)?).ok()?.to_owned();
            let lookup = if original == 0 { first } else { original };
            let mut terminated = false;
            for ordinal in 0..image.len() / 8 {
                let value = word(image, lookup.checked_add(ordinal * 8)?, 8)?;
                if value == 0 {
                    terminated = true;
                    break;
                }
                let symbol = if value >> 63 != 0 {
                    format!("#{}", value & 0xffff)
                } else {
                    std::str::from_utf8(name(image, usize::try_from(value).ok()?.checked_add(2)?)?)
                        .ok()?
                        .to_owned()
                };
                let offset = first.checked_add(ordinal * 8)?;
                result.push(ImportThunk {
                    library: library.clone(),
                    symbol,
                    offset,
                    address: word(image, offset, 8)?,
                });
            }
            if !terminated {
                return None;
            }
        }
        None
    };
    parse().ok_or("malformed or unterminated PE64 import directory")
}

/// Read a bounded integer; O(1) time and space.
fn word(data: &[u8], at: usize, width: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(width)?)?;
    Some(bytes.iter().enumerate().fold(0, |sum, (index, value)| {
        sum | ((*value as u64) << (8 * index))
    }))
}

/// Read an image-bounded C string; O(B) time and O(1) borrowed space.
fn name(data: &[u8], at: usize) -> Option<&[u8]> {
    let bytes = data.get(at..)?;
    Some(&bytes[..bytes.iter().position(|byte| *byte == 0)?])
}

/// Find a named import in a mapped image, not raw-file offsets; O(I + T) time.
fn locate(image: &[u8], dll: &[u8], symbol: &[u8]) -> Option<usize> {
    if image.get(..2)? != b"MZ" {
        return None;
    }
    let pe = word(image, 60, 4)? as usize;
    if image.get(pe..pe.checked_add(4)?)? != b"PE\0\0" || word(image, pe + 24, 2)? != 0x20b {
        return None;
    }
    let directory = word(image, pe + 24 + 120, 4)? as usize;
    let size = word(image, pe + 24 + 124, 4)? as usize;
    let descriptors = image.get(directory..directory.checked_add(size)?)?;
    for index in 0..descriptors.len() / 20 {
        let entry = directory + 20 * index;
        let original = word(image, entry, 4)? as usize;
        let dll_name = word(image, entry + 12, 4)? as usize;
        let first = word(image, entry + 16, 4)? as usize;
        if dll_name == 0 && first == 0 {
            break;
        }
        if !name(image, dll_name)?.eq_ignore_ascii_case(dll) {
            continue;
        }
        let lookup = if original == 0 { first } else { original };
        for ordinal in 0..image.len() / 8 {
            let value = word(image, lookup.checked_add(ordinal * 8)?, 8)?;
            if value == 0 {
                break;
            }
            if value >> 63 != 0 {
                continue;
            }
            let at = usize::try_from(value).ok()?.checked_add(2)?;
            if name(image, at)? == symbol {
                let slot = first.checked_add(ordinal * 8)?;
                word(image, slot, 8)?;
                return Some(slot);
            }
        }
    }
    None
}

/// Locate a thunk in a caller-owned mapped PE64 allocation; O(I + T) time, O(1) space.
#[no_mangle]
pub unsafe extern "C" fn vk_pe_iat_find_thunk(
    image: *const u8,
    len: usize,
    dll: *const std::ffi::c_char,
    symbol: *const std::ffi::c_char,
    offset: *mut usize,
) -> i32 {
    if image.is_null()
        || dll.is_null()
        || symbol.is_null()
        || offset.is_null()
        || len > 64 * 1024 * 1024
    {
        return -1;
    }
    let bytes = std::slice::from_raw_parts(image, len);
    match locate(
        bytes,
        std::ffi::CStr::from_ptr(dll).to_bytes(),
        std::ffi::CStr::from_ptr(symbol).to_bytes(),
    ) {
        Some(found) => {
            core::ptr::write(offset, found);
            0
        }
        None => -2,
    }
}

/// Count every named/ordinal import slot in a bounded mapped image; O(B + T) time/space.
#[no_mangle]
pub unsafe extern "C" fn vk_pe_iat_count(image: *const u8, len: usize, count: *mut usize) -> i32 {
    if image.is_null() || count.is_null() || len > 64 * 1024 * 1024 {
        return -1;
    }
    match enumerate_imports(std::slice::from_raw_parts(image, len)) {
        Ok(imports) => {
            core::ptr::write(count, imports.len());
            0
        }
        Err(_) => -2,
    }
}

/// Verify expected bytes before redirecting a writable owned thunk; O(1) time/space.
#[no_mangle]
pub unsafe extern "C" fn vk_pe_iat_redirect(
    image: *mut u8,
    len: usize,
    offset: usize,
    expected: u64,
    replacement: u64,
) -> i32 {
    if image.is_null() || len > 64 * 1024 * 1024 || offset % 8 != 0 {
        return -1;
    }
    let bytes = std::slice::from_raw_parts_mut(image, len);
    if word(bytes, offset, 8) != Some(expected) {
        return -2;
    }
    match bytes.get_mut(offset..offset + 8) {
        Some(slot) => {
            slot.copy_from_slice(&replacement.to_le_bytes());
            0
        }
        None => -1,
    }
}

#[cfg(test)]
mod tests {
    /// Reject absent and truncated directories without writes; O(1) work/space.
    #[test]
    fn malformed_images() -> () {
        assert_eq!(
            super::locate(&[0; 128], b"kernel32.dll", b"WriteFile"),
            None
        );
        let mut data = [0u8; 16];
        unsafe {
            assert_eq!(
                super::vk_pe_iat_redirect(data.as_mut_ptr(), 16, 8, 1, 2),
                -2
            );
            assert_eq!(
                super::vk_pe_iat_redirect(data.as_mut_ptr(), 16, 24, 0, 2),
                -2
            );
        }
        assert_eq!(data, [0; 16]);
    }
}
