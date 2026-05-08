fn main() {
    #[cfg(windows)]
    {
        if std::env::var_os("CARGO_FEATURE_UAC").is_some() {
            embed_resource::compile("../../res/uac.rc", embed_resource::NONE);
        }
    }
}
