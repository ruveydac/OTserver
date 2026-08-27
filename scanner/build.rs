fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource
            .set("CompanyName", "OTserver")
            .set("FileDescription", "Read-only OT discovery for OTserver")
            .set("InternalName", "otserver-scanner")
            .set("OriginalFilename", "otserver-scanner.exe")
            .set("ProductName", "OTserver Scanner")
            .compile()
            .expect("failed to compile Windows executable metadata");
    }
}
