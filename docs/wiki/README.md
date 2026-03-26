# MKT KSA Project Wiki

This folder contains a complete bilingual wiki source for the project in English and Arabic.

## Purpose

- Build a professional project reference from zero to production readiness.
- Provide a clear onboarding journey for engineers, security teams, and decision makers.
- Improve discoverability through structured technical content and strong internal linking.

## Wiki Structure

- Root landing: [Home](Home.md) (links to both language tracks)
- Root sidebar: [_Sidebar](_Sidebar.md) with bilingual navigation
- English entry: [Home](en/Home.md)
- Arabic entry: [الصفحة الرئيسية](ar/Home.md)

### English Track

- [01. Quick Start](en/01-Quick-Start.md)
- [02. Architecture](en/02-Architecture.md)
- [03. Security Deep Dive](en/03-Security-Deep-Dive.md)
- [04. API Guide](en/04-API-Guide.md)
- [05. Deployment and Operations](en/05-Deployment-and-Operations.md)
- [06. Testing and Quality](en/06-Testing-and-Quality.md)
- [07. FAQ and Troubleshooting](en/07-FAQ-and-Troubleshooting.md)
- [08. SEO and Documentation Strategy](en/08-SEO-and-Documentation-Strategy.md)

### Arabic Track

- [01. البدء السريع](ar/01-البدء-السريع.md)
- [02. المعمارية](ar/02-المعمارية.md)
- [03. التعمق الأمني](ar/03-التعمق-الأمني.md)
- [04. دليل API](ar/04-دليل-API.md)
- [05. النشر والتشغيل](ar/05-النشر-والتشغيل.md)
- [06. الاختبارات والجودة](ar/06-الاختبارات-والجودة.md)
- [07. الأسئلة الشائعة وحل المشاكل](ar/07-الأسئلة-الشائعة-وحل-المشاكل.md)
- [08. استراتيجية الظهور والانتشار](ar/08-استراتيجية-الظهور-والانتشار.md)

## Diagram and Image Assets

- [System Context](assets/system-context.svg)
- [Request Lifecycle](assets/request-lifecycle.svg)
- [Data and Trust Flow](assets/data-trust-flow.svg)
- [Deployment Topology](assets/deployment-topology.svg)

## How to Publish as GitHub Wiki

GitHub Wiki is a separate git repository. Use these steps when you want to publish this source as live wiki pages.

1. Clone wiki repo:
   - git clone https://github.com/mktmansour/MKT-KSA-Geolocation-Security.wiki.git wiki-publish
2. Copy files from this folder:
   - cp -r docs/wiki/en wiki-publish/
   - cp -r docs/wiki/ar wiki-publish/
   - cp -r docs/wiki/assets wiki-publish/
   - cp docs/wiki/Home.md wiki-publish/
   - cp docs/wiki/_Sidebar.md wiki-publish/
3. Commit and push.

## Editorial Standards

- Keep each page focused on one intent.
- Keep headings consistent across English and Arabic tracks.
- Keep architecture, security, and API pages synced after every release.
- Add one practical example per critical section.
- Link to canonical code and docs where possible.
