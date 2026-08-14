pub mod contract;
pub mod discovery;
pub mod profinet;
pub mod protocols;
pub mod snmp;

#[cfg(test)]
pub(crate) async fn network_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

pub fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formatting is infallible")
}
