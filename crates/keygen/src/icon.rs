use std::path::Path;

#[cfg(windows)]
type HMODULE = isize;
#[cfg(windows)]
type HRSRC = isize;
#[cfg(windows)]
type HGLOBAL = isize;
#[cfg(windows)]
type HANDLE = isize;

#[cfg(windows)]
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
#[cfg(windows)]
const RT_ICON: u16 = 3;
#[cfg(windows)]
const RT_GROUP_ICON: u16 = 14;

#[cfg(windows)]
#[allow(non_snake_case)]
extern "system" {
    fn LoadLibraryExA(lpLibFileName: *const u8, hFile: HANDLE, dwFlags: u32) -> HMODULE;
    fn FreeLibrary(hLibModule: HMODULE) -> i32;
    fn FindResourceA(hModule: HMODULE, lpName: *const u8, lpType: *const u8) -> HRSRC;
    fn LoadResource(hModule: HMODULE, hResInfo: HRSRC) -> HGLOBAL;
    fn LockResource(hResData: HGLOBAL) -> *mut std::ffi::c_void;
    fn SizeofResource(hModule: HMODULE, hResInfo: HRSRC) -> u32;
    fn BeginUpdateResourceA(pFileName: *const u8, bDeleteExistingResources: i32) -> HANDLE;
    fn EndUpdateResourceA(hUpdate: HANDLE, fDiscard: i32) -> i32;
    fn UpdateResourceA(
        hUpdate: HANDLE,
        lpType: *const u8,
        lpName: *const u8,
        wLanguage: u16,
        lpData: *const std::ffi::c_void,
        cb: u32,
    ) -> i32;
}

#[cfg(windows)]
fn make_int_resource(id: u16) -> *const u8 {
    id as usize as *const u8
}

#[cfg(windows)]
pub fn copy_icon_from_exe(src: &Path, dst: &Path) -> bool {
    use std::ffi::CString;
    let src_c = match CString::new(src.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let dst_c = match CString::new(dst.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    unsafe {
        let h_src = LoadLibraryExA(
            src_c.as_ptr() as *const u8,
            0,
            LOAD_LIBRARY_AS_DATAFILE,
        );
        if h_src == 0 {
            return false;
        }
        let mut h_res_info = FindResourceA(h_src, make_int_resource(1), make_int_resource(RT_GROUP_ICON));
        if h_res_info == 0 {
            h_res_info = FindResourceA(h_src, make_int_resource(32512), make_int_resource(RT_GROUP_ICON));
        }
        if h_res_info == 0 {
            FreeLibrary(h_src);
            return false;
        }
        let h_res_data = LoadResource(h_src, h_res_info);
        if h_res_data == 0 {
            FreeLibrary(h_src);
            return false;
        }
        let p_group_icon = LockResource(h_res_data);
        let group_size = SizeofResource(h_src, h_res_info);
        if p_group_icon.is_null() || group_size == 0 {
            FreeLibrary(h_src);
            return false;
        }
        let h_update = BeginUpdateResourceA(dst_c.as_ptr() as *const u8, 0);
        if h_update == 0 {
            FreeLibrary(h_src);
            return false;
        }
        UpdateResourceA(
            h_update,
            make_int_resource(RT_GROUP_ICON),
            make_int_resource(1),
            0,
            p_group_icon,
            group_size,
        );
        let p_data = p_group_icon as *const u8;
        let id_count = std::ptr::read_unaligned(p_data.offset(4) as *const u16);
        for i in 0..id_count as isize {
            let id_off = 6 + i * 14 + 12;
            let icon_id = std::ptr::read_unaligned(p_data.offset(id_off) as *const u16);
            let h_icon_info = FindResourceA(h_src, make_int_resource(icon_id), make_int_resource(RT_ICON));
            if h_icon_info != 0 {
                let h_icon_data = LoadResource(h_src, h_icon_info);
                let p_icon = LockResource(h_icon_data);
                let icon_size = SizeofResource(h_src, h_icon_info);
                if !p_icon.is_null() && icon_size > 0 {
                    UpdateResourceA(h_update, make_int_resource(RT_ICON), make_int_resource(icon_id), 0, p_icon, icon_size);
                }
            }
        }
        EndUpdateResourceA(h_update, 0);
        FreeLibrary(h_src);
    }
    true
}

#[cfg(not(windows))]
pub fn copy_icon_from_exe(_src: &Path, _dst: &Path) -> bool {
    false
}
