fn main() {
    #[cfg(windows)]
    {
        let icon = std::path::Path::new("../../res/icon.ico");
        if icon.exists() {
            embed_resource::compile("../../res/icon.rc", embed_resource::NONE);
        }
    }
}
