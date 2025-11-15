#[cfg(feature = "core_full")]
pub mod behavior_bio;
#[cfg(feature = "core_full")]
pub mod cross_location;
#[cfg(feature = "core_full")]
pub mod device_fp;
pub mod digest;
pub mod geo_db;
#[cfg(feature = "core_full")]
pub mod geo_resolver;
#[cfg(feature = "core_full")]
pub mod network_analyzer;
#[cfg(feature = "core_full")]
pub mod sensors_analyzer;
#[cfg(feature = "core_full")]
pub mod weather_val;

// #[cfg(target_os = "windows")]
// pub mod windows;
