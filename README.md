<p align="center">
  <img src="https://img.shields.io/badge/AetherST-Tunnel-007AFF?style=for-the-badge&logo=shield&logoColor=white" alt="AetherST Logo" width="220">
</p>

<h1 align="center">AetherST Tunnel</h1>

<p align="center">
  <strong>Next-Generation, High-Performance Censorship Circumvention Client for Android & Windows</strong>
</p>

<p align="center">
  <a href="https://github.com/LifeLover-7/AetherST-Private/releases">
    <img src="https://img.shields.io/badge/Release-v2.1.4-007AFF?style=for-the-badge" alt="Release">
  </a>
  <a href="https://github.com/LifeLover-7/AetherST-Private">
    <img src="https://img.shields.io/badge/License-Proprietary-orange?style=for-the-badge" alt="License">
  </a>
  <img src="https://img.shields.io/badge/Platform-Android_&_Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Platforms">
  <img src="https://img.shields.io/badge/Kotlin-Multiplatform-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white" alt="Kotlin Multiplatform">
</p>

---

## 📖 معرفی و نمای کلی (Overview)

**AetherST Tunnel** یک کلاینت فوق‌پیشرفته، بسیار پایدار و با کارایی بالا جهت دورزدن فیلترینگ سخت‌گیرانه، اختلالات عمیق شبکه (DPI) و مسدودسازی‌های پروتکل‌محور در سیستم‌عامل‌های **اندروید (Android)** و **ویندوز (Windows)** است.

این نرم‌افزار با بهره‌گیری از **هسته اختصاصی Aether Core** همراه با ادغام مستقیم هسته‌های معروفی نظیر **sing-box**، **HEV SOCKS5 Tunnel**، **Psiphon Core** و موتور هدایت دومرحله‌ای، امکان اتصال پایدار و تغییر IP به کشورهای گوناگون (با خروجی تمیز برای هوش مصنوعی و سرویس‌های تحریم‌شده) را به آسانی فراهم می‌آورد.

---

## 🌟 قابلیت‌های برجسته (Key Features)

* 🛡️ **مقاومت بی‌نظیر در برابر DPI:** بهینه‌سازی دقیق ترافیک برای عبور از فیلترینگ مدرن و سیستم‌های شناسایی پکت.
* 🚀 **پشتیبانی جامع از پروتکل‌های خط اول (Primary Protocols):**
  * **MASQUE (HTTP/3 & HTTP/2):** مخفی‌سازی ترافیک تانل در قالب ترافیک معتبر و پرسرعت وب با پروتکل‌های QUIC و TLS.
  * **WireGuard Direct:** اتصال مستقیم و فوق‌العاده سریع با رمزنگاری مدرن و بهینه‌ترین مصرف باتری و منابع.
  * **Gool (WARP-in-WARP / WG-in-WG):** دو لایه تانل تو در توی وایرگارد جهت پنهان‌سازی و پایداری مضاعف.
  * **Cloudflare Zero Trust (Teams):** پشتیبانی کامل از اکانت‌های سازمانی زرو‌تراست، توکن‌های احراز هویت و پورت‌های اختصاصی.
* 🔗 **موتور خروج دومرحله‌ای (Advanced Exit Node Chaining):**
  * **مستقیم (Direct):** خروج بدون واسطه از تانل اولیه.
  * **سایفون چند هسته‌ای (Psiphon Multi-Core OSSH):** اجرای موازی هسته‌های سایفون بر بستر تانل اولیه همراه با توازن بار (Load Balancing).
  * **وایرگارد ثانویه (Custom WireGuard Exit / Proton VPN):** هدایت ترافیک به سمت اکانت‌های Proton VPN، Mullvad و کانفیگ‌های دلخواه WireGuard از طریق مسیردهی کاربران با موتور sing-box.
  * **پروکسی SOCKS5 اختصاصی:** امکان رله ترافیک درون‌شبکه‌ای به هر سرور SOCKS5 خارجی.
  * **پروکسی اختصاصی فایرفاکس (Firefox VPN / Mozilla Fastly):** هدایت ترافیک دومرحله‌ای بر روی لبه پرسرعت Fastly موزیلا با متد HTTP/2 CONNECT.
* ⚡ **فشرده‌سازی حداکثری و بهینه‌سازی حجم (UPX & Strip):** باینری‌های اجرایی دسکتاپ و کتابخانه‌های نیتیو اندروید با فناوری UPX LZMA و Strip فشرده شده‌اند که حجم فایل نصبی را تا ۷۵٪ کاهش داده است.
* 🎛️ **رابط کاربری مدرن (Compose Multiplatform):** طراحی شیک با المان‌های الهام‌گرفته از iOS، پشتیبانی کامل از زبان‌های فارسی (RTL) و انگلیسی، تم تیره و روشن، پینگ زنده و نمایش اطلاعات آی‌پی خروجی.
* 🪟 **پشتیبانی اختصاصی ویندوز:** مجهز به درایور قدرتمند Wintun، سیستم روتینگ هوشمند بدون لوپ برای دامنه‌ها و رنج‌های آی‌پی وارپ، و پروکسی دوگانه سیستمی (WinINET HTTP & SOCKS5).

---

## 🏗️ معماری فنی (Technical Architecture)

```
┌────────────────────────────────────────────────────────┐
│             AetherST UI (Compose Multiplatform)        │
│          Android (Compose)  |  Windows (Desktop)       │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│      Connection Controller & TUN Routing Engine        │
│     (Dual System Proxy / Wintun / HEV SOCKS Bridge)    │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
┌──────────────▼───────────┐ ┌────────────▼──────────────┐
│  Primary Tunnel (Layer 1)│ │ Secondary Detour (Layer 2)│
│  • MASQUE (HTTP/3, H2)   │ │ • Psiphon Multi-Core      │
│  • WireGuard Direct      │ │ • WireGuard (Proton VPN)  │
│  • Gool (WG-in-WG)       │ │ • Firefox VPN (Fastly H2) │
│  • Zero Trust            │ │ • Custom External SOCKS5  │
└──────────────────────────┘ └───────────────────────────┘
```

---

### تست دو خروجی روی اندروید

در تنظیمات، **WireGuard** را به‌عنوان لایهٔ اول انتخاب کنید. برای خروجی Proton، فایل `.conf` خود را در **Custom WireGuard** وارد کنید. برای **Firefox VPN** به حسابی نیاز دارید که مجوز سرویس پراکسی موزیلا را داشته باشد. این خروجی TCP را با CONNECT روی TLS منتقل می‌کند؛ از UDP فقط DNS پشتیبانی می‌شود، نه QUIC یا UDP عمومی.

در حالت **Proxy only** آدرس «Exit SOCKS» را از داشبورد کپی کنید: پیش‌فرض Proton برابر `127.0.0.1:10805` و Firefox برابر `127.0.0.1:10810` است. پورت `2021` فقط لایهٔ اول است. در حالت **TUN** تنظیم دستی پراکسی لازم نیست. برای بررسی، IP را از مرورگری که واقعاً از همین مسیر استفاده می‌کند با IP اتصالِ لایهٔ اول مقایسه کنید. کلید خصوصی، فایل کامل کانفیگ یا توکن حساب را در گزارش اشکال نگذارید.

تست‌های توسعه‌دهنده (`bash tools/exit-test/run.sh`، روی Linux x86-64 با JDK 17 و Go 1.24) با peer وایرگارد و پراکسی TLS محلی اجرا می‌شوند و به حساب کاربر متصل نمی‌شوند.

## 📦 دانلود و نصب (Installation)

فایل‌های آماده نصب را می‌توانید مستقیماً از بخش [GitHub Releases](https://github.com/LifeLover-7/AetherST-Private/releases) دریافت نمایید:

* **نسخه ویندوز (Windows):**
  * فایل نصبی آسان: `AetherST-Tunnel-2.1.4.exe`
  * پکیج نصبی سازمانی: `AetherST-Tunnel-2.1.4.msi`
* **نسخه اندروید (Android):**
  * معماری رایج و پرسرعت: `app-arm64-v8a-release.apk`
  * نسخه عمومی سازگار با تمام دستگاه‌ها: `app-universal-release.apk`

---

## 🛠️ ساخت از سورس (Build from Source)

### پیش‌نیازها:
* **JDK:** نسخه 17 (توصیه شده: Zulu OpenJDK 17)
* **Android SDK & NDK:** برای بیلد اندروید (NDK: `30.0.15729638`)
* **Gradle:** 8.10+

### دستورات بیلد:
```bash
# بیلد پکیج نصبی ویندوز (EXE و MSI)
./gradlew :composeApp:packageReleaseDistributionForCurrentOS

# کامپایل نسخه دسکتاپ
./gradlew :composeApp:compileKotlinDesktop

# بیلد بسته انتشار اندروید (Release APK)
./gradlew assembleRelease
```

---

## 👥 ارتباط و پشتیبانی (Community)

* 📢 کانال تلگرام: [PowerSigma](https://t.me/PowerSigma)
* 👨‍💻 توسعه‌دهنده: [@immaghzbad](https://github.com/immaghzbad)

---
<p align="center">
  توسعه داده شده با ❤️ توسط <b>PowerSigma Team</b>
</p>
