use std::ffi::CString;

/// Пытается скомпилировать фильтр WinDivert с помощью оригинального Helper API,
/// чтобы убедиться, что синтаксис корректен.
///
/// WinDivertHelperCompileFilter принимает строку фильтра, уровень слоя (network = 0)
/// и возвращает статус успеха, а также позицию и текст ошибки при провале.
pub fn compile_filter(filter: &str) -> Result<(), String> {
    let c_str = CString::new(filter).map_err(|_| "Filter contains null bytes".to_string())?;
    let mut error_str: *const std::os::raw::c_char = std::ptr::null();
    let mut error_pos: u32 = 0;

    #[link(name = "WinDivert")]
    extern "system" {
        fn WinDivertHelperCompileFilter(
            filter: *const std::os::raw::c_char,
            layer: u32,
            error_str: *mut *const std::os::raw::c_char,
            error_pos: *mut u32,
        ) -> i32;
    }

    // WINDIVERT_LAYER_NETWORK = 0
    let res =
        unsafe { WinDivertHelperCompileFilter(c_str.as_ptr(), 0, &mut error_str, &mut error_pos) };

    if res == 0 {
        let msg = if !error_str.is_null() {
            unsafe {
                std::ffi::CStr::from_ptr(error_str)
                    .to_string_lossy()
                    .into_owned()
            }
        } else {
            "Unknown compile error".to_string()
        };
        Err(format!("Error at pos {}: {}", error_pos, msg))
    } else {
        Ok(())
    }
}
