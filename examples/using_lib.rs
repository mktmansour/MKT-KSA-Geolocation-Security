// Minimal local consumer for the library crate `mkt_ksa_geo_sec`
// Run with: cargo run --example using_lib

use mkt_ksa_geo_sec::core::geo_resolver::{
    DefaultAiModel, DefaultBlockchain, GeoLocation, GeoReaderEnum, GeoResolver, MockGeoReader,
};
use secrecy::SecretVec;
use std::sync::Arc;

fn main() {
    // Build a resolver with a mock geo reader (no external DB needed)
    let resolver = GeoResolver::new(
        SecretVec::new(vec![1; 32]),
        Arc::new(DefaultAiModel),
        Arc::new(DefaultBlockchain),
        true,
        false,
        Arc::new(GeoReaderEnum::Mock(MockGeoReader::new())),
    );

    // Sign a sample location object
    let location = GeoLocation {
        lat: 24.7136,
        lng: 46.6753,
        city: Some("Riyadh".to_string()),
        ..Default::default()
    };

    let sig_hex = resolver.sign_location(&location).expect("sign");
    println!("Signed sample location, signature (hex): {sig_hex}");
}


