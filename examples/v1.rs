use snmp_rust::v1::V1Options;
use snmp_rust::{Session, SessionOptions};
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Create an SNMP v1 session
    let session = Session::v1(SessionOptions {
        target: "192.168.0.23:161".parse().unwrap(),
        timeout: Duration::from_secs(1),
        snmp: V1Options {
            community: "public".to_string(),
        },
    }).await.unwrap();
    
    // Perform an SNMP v1 GET request
    let var = session.get("1.3.6.1.2.1.1.1.0").await.unwrap();
    println!("{:?}", var);
}
