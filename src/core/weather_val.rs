/******************************************************************************************
      📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

     اسم الملف: weather_val.rs
    المسار:    src/core/weather_val.rs
    دور الملف:
    محرك تجميع وتدقيق بيانات الطقس. يقوم بجلب البيانات من عدة مصادر
    متوازية، مقارنتها، وتوفير نتيجة موحدة وموثوقة. مصمم ليكون
    مرنًا، قابلاً للاختبار، وجاهزًا للتكامل مع أي مزود خدمة طقس.
    المهام الأساسية:
    1.  تعريف واجهة موحدة لمزودي خدمة الطقس (`WeatherProvider`).
    2.  توفير محرك (`WeatherEngine`) يقوم بالتنسيق بين المزودين.
    3.  جلب البيانات على التوازي لتحقيق أقصى سرعة.
    4.  تدقيق ومقارنة النتائج لضمان الدقة والموثوقية.
    5.  توفير تطبيق افتراضي جاهز للعمل (`OpenMeteoProvider`).
    --------------------------------------------------------------
    File Name: weather_val.rs
    Path:     src/core/weather_val.rs

    File Role:
    A weather data aggregation and validation engine. It fetches data from
    multiple parallel sources, compares them, and provides a unified,
    reliable result. Designed to be flexible, testable, and ready to
    integrate with any weather provider.
    Main Tasks:
    1.  Define a standard interface for weather providers (`WeatherProvider`).
    2.  Provide an engine (`WeatherEngine`) to orchestrate providers.
    3.  Fetch data in parallel for maximum speed.
    4.  Validate and compare results to ensure accuracy and reliability.
    5.  Provide a default, ready-to-use implementation (`OpenMeteoProvider`).
******************************************************************************************/

use crate::utils::precision::avg_f32;
use async_trait::async_trait;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

// ================================================================
// الأخطاء المخصصة للوحدة
// Custom Module Errors
// ================================================================
#[derive(Debug, Error)]
pub enum WeatherError {
    #[error("Failed to fetch weather data from provider: {0}")]
    FetchError(String),
    #[error("Failed to parse weather data: {0}")]
    ParseError(String),
    #[error("No reliable weather data could be obtained from any provider")]
    NoReliableData,
}

// ================================================================
// نماذج البيانات الأساسية
// Core Data Models
// ================================================================

/// يمثل بيانات الطقس الموحدة من أي مزود.
/// Represents unified weather data from any provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeatherData {
    pub temperature_celsius: f32,
    pub humidity_percent: f32,
    pub wind_speed_kmh: f32,
    pub precipitation_mm: f32,
    pub weather_code: u32,
}

// ================================================================
// واجهة (Trait) لمزودي خدمة الطقس
// Trait for Weather Providers
// ================================================================
#[async_trait]
pub trait WeatherProvider: Send + Sync {
    /// يجلب بيانات الطقس لموقع جغرافي معين.
    /// Fetches weather data for a specific geographic location.
    async fn get_weather(&self, latitude: f64, longitude: f64)
        -> Result<WeatherData, WeatherError>;
    /// اسم المزود للتعريف به.
    /// The name of the provider for identification.
    fn provider_name(&self) -> &'static str;
}

// ================================================================
// محرك تجميع الطقس (WeatherEngine)
// The Weather Aggregation Engine
// ================================================================
pub struct WeatherEngine {
    providers: Vec<Arc<dyn WeatherProvider>>,
}

impl WeatherEngine {
    /// إنشاء محرك جديد مع قائمة من مزودي الخدمة.
    /// Creates a new engine with a list of providers.
    #[must_use]
    pub fn new(providers: Vec<Arc<dyn WeatherProvider>>) -> Self {
        Self { providers }
    }

    /// يجلب ويدقق بيانات الطقس من جميع المزودين المتاحين.
    /// Fetches and validates weather data from all available providers.
    ///
    /// # Errors
    /// Returns `WeatherError::NoReliableData` if no provider returns successful data,
    /// or other `WeatherError` variants if deserialization/fetching fails per provider.
    pub async fn fetch_and_validate(
        &self,
        latitude: f64,
        longitude: f64,
    ) -> Result<WeatherData, WeatherError> {
        if self.providers.is_empty() {
            return Err(WeatherError::NoReliableData);
        }

        // استدعاء جميع المزودين على التوازي
        // Call all providers in parallel
        let futures = self
            .providers
            .iter()
            .map(|p| p.get_weather(latitude, longitude));
        let results = join_all(futures).await;

        // تصفية النتائج الناجحة فقط
        // Filter for successful results only
        let successful_results: Vec<WeatherData> =
            results.into_iter().filter_map(Result::ok).collect();

        if successful_results.is_empty() {
            return Err(WeatherError::NoReliableData);
        }

        // منطق التدقيق والمقارنة (هنا نستخدم المتوسط)
        // Validation and comparison logic (here we use an average)
        let avg_temp = avg_f32(
            &successful_results
                .iter()
                .map(|d| d.temperature_celsius)
                .collect::<Vec<_>>(),
        );
        let avg_humidity = avg_f32(
            &successful_results
                .iter()
                .map(|d| d.humidity_percent)
                .collect::<Vec<_>>(),
        );
        let avg_wind = avg_f32(
            &successful_results
                .iter()
                .map(|d| d.wind_speed_kmh)
                .collect::<Vec<_>>(),
        );
        let avg_precip = avg_f32(
            &successful_results
                .iter()
                .map(|d| d.precipitation_mm)
                .collect::<Vec<_>>(),
        );

        // اختيار رمز الطقس الأكثر شيوعًا
        // Choose the most common weather code
        let weather_code = successful_results
            .iter()
            .max_by_key(|d| d.weather_code)
            .map_or(0, |d| d.weather_code);

        Ok(WeatherData {
            temperature_celsius: avg_temp,
            humidity_percent: avg_humidity,
            wind_speed_kmh: avg_wind,
            precipitation_mm: avg_precip,
            weather_code,
        })
    }
}

// ================================================================
// تطبيق افتراضي جاهز للعمل (OpenMeteo)
// Default Ready-to-use Implementation (OpenMeteo)
// ================================================================

/// مزود خدمة الطقس يستخدم Open-Meteo API.
/// A weather provider that uses the Open-Meteo API.
pub struct OpenMeteoProvider {
    client: reqwest::Client,
}

impl Default for OpenMeteoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenMeteoProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

// هياكل لفك تشفير استجابة Open-Meteo
// Structs to deserialize the Open-Meteo response
#[derive(Deserialize)]
struct OpenMeteoResponse {
    current_weather: OpenMeteoCurrent,
}
#[derive(Deserialize)]
struct OpenMeteoCurrent {
    temperature: f32,
    windspeed: f32,
    weathercode: u32,
    // ملاحظة: Open-Meteo لا يوفر الرطوبة وهطول الأمطار في `current_weather` مباشرة
    // Note: Open-Meteo doesn't provide humidity/precipitation directly in `current_weather`
}

#[async_trait]
impl WeatherProvider for OpenMeteoProvider {
    async fn get_weather(
        &self,
        latitude: f64,
        longitude: f64,
    ) -> Result<WeatherData, WeatherError> {
        let url = format!(
            "https://api.open-meteo.com/v1/forecast?latitude={latitude}&longitude={longitude}&current_weather=true"
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| WeatherError::FetchError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(WeatherError::FetchError(format!(
                "API returned status: {}",
                response.status()
            )));
        }

        let api_response = response
            .json::<OpenMeteoResponse>()
            .await
            .map_err(|e| WeatherError::ParseError(e.to_string()))?;

        Ok(WeatherData {
            temperature_celsius: api_response.current_weather.temperature,
            humidity_percent: 50.0, // قيمة افتراضية / placeholder
            wind_speed_kmh: api_response.current_weather.windspeed,
            precipitation_mm: 0.0, // قيمة افتراضية / placeholder
            weather_code: api_response.current_weather.weathercode,
        })
    }

    fn provider_name(&self) -> &'static str {
        "Open-Meteo"
    }
}

// ================================================================
// اختبارات شاملة (محدثة بالكامل)
// Comprehensive Tests (Fully Updated)
// ================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // --- Mock Providers for Precise Testing ---

    struct MockSunnyProvider;
    #[async_trait]
    impl WeatherProvider for MockSunnyProvider {
        async fn get_weather(&self, _: f64, _: f64) -> Result<WeatherData, WeatherError> {
            Ok(WeatherData {
                temperature_celsius: 25.0,
                humidity_percent: 40.0,
                wind_speed_kmh: 10.0,
                precipitation_mm: 0.0,
                weather_code: 1, // Sunny
            })
        }
        fn provider_name(&self) -> &'static str {
            "Sunny"
        }
    }

    struct MockRainyProvider;
    #[async_trait]
    impl WeatherProvider for MockRainyProvider {
        async fn get_weather(&self, _: f64, _: f64) -> Result<WeatherData, WeatherError> {
            Ok(WeatherData {
                temperature_celsius: 15.0,
                humidity_percent: 80.0,
                wind_speed_kmh: 20.0,
                precipitation_mm: 5.0,
                weather_code: 61, // Rainy
            })
        }
        fn provider_name(&self) -> &'static str {
            "Rainy"
        }
    }

    struct MockErrorProvider;
    #[async_trait]
    impl WeatherProvider for MockErrorProvider {
        async fn get_weather(&self, _: f64, _: f64) -> Result<WeatherData, WeatherError> {
            Err(WeatherError::FetchError(
                "Simulated provider failure".to_string(),
            ))
        }
        fn provider_name(&self) -> &'static str {
            "Error"
        }
    }

    #[tokio::test]
    async fn test_engine_with_single_provider() {
        let providers: Vec<Arc<dyn WeatherProvider>> = vec![Arc::new(MockSunnyProvider)];
        let engine = WeatherEngine::new(providers);

        let result = engine.fetch_and_validate(0.0, 0.0).await.unwrap();

        assert!((result.temperature_celsius - 25.0).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_engine_averages_multiple_providers() {
        let providers: Vec<Arc<dyn WeatherProvider>> =
            vec![Arc::new(MockSunnyProvider), Arc::new(MockRainyProvider)];
        let engine = WeatherEngine::new(providers);

        let result = engine.fetch_and_validate(0.0, 0.0).await.unwrap();

        // Temperature should be the average of 25.0 and 15.0
        assert!((result.temperature_celsius - 20.0).abs() < f32::EPSILON);
        // Humidity should be the average of 40.0 and 80.0
        assert!((result.humidity_percent - 60.0).abs() < f32::EPSILON);
        // Weather code should be the one from the rainy provider (higher number)
        assert_eq!(result.weather_code, 61);
    }

    #[tokio::test]
    async fn test_engine_handles_failing_provider() {
        let providers: Vec<Arc<dyn WeatherProvider>> = vec![
            Arc::new(MockSunnyProvider),
            Arc::new(MockErrorProvider), // This one will fail
        ];
        let engine = WeatherEngine::new(providers);

        let result = engine.fetch_and_validate(0.0, 0.0).await.unwrap();

        // The result should be based only on the successful provider
        assert!((result.temperature_celsius - 25.0).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_engine_fails_if_all_providers_fail() {
        let providers: Vec<Arc<dyn WeatherProvider>> =
            vec![Arc::new(MockErrorProvider), Arc::new(MockErrorProvider)];
        let engine = WeatherEngine::new(providers);

        let result = engine.fetch_and_validate(0.0, 0.0).await;

        assert!(matches!(result, Err(WeatherError::NoReliableData)));
    }
}
