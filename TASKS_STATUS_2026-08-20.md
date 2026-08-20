# کارهای جاری — وضعیت پس از سشن ۲۰ اوت ۲۰۲۶

منبع: فهرست کاربر (۲۹ مرداد ۱۴۰۵). این فایل فقط **وضعیت اجرا** است؛ ادعاهای امنیتی → `ASSUMPTIONS.md`.
شاخه کاری: **infra/ready** (نه theory-gaps).

## ۱. هسته فنی AuthGate (+ legitimacy / decision-os)

| کار | وضعیت |
|---|---|
| AE-10 (دلیل وتو در لاگ) | **انجام‌شده** — `execute.py` + `test_fixed6`; conformance AE-10 PASS |
| AE-4 / AE-5 | **انجام‌شده** — `decision_os_min/attenuation.py` (macaroon-lite); **10/10 PASS** |
| جایگزینی تفویض دست‌ساز با تضعیف macaroon/biscuit | **انجام‌شده (lite)** — HMAC caveat chain؛ نه پیاده‌سازی کامل Biscuit |
| تکمیل red team | **جزئی** — break6 بسته؛ 7a/7c/8/8b عمداً باز |
| تصمیم نظریه آزادی | **انجام‌شده** — `FREEDOM_THEORY_POSITION.md` (لایه هنجاری اختیاری، نه ادعای اصلی) |
| ادعای پروفایل انطباق قابل دفاع | **انجام‌شده** — `contracts-spec/conformance/CLAIM.md` |
| مسیر MCP به‌جای RFC جدید | **انجام‌شده** — `MCP_STANDARDIZATION.md` |
| REVIEW_PACKET | **نوشته شد** — `REVIEW_PACKET.md`؛ **push به GitHub هنوز دستی** |
| Ed25519 تأیید‌شده (HACL*/Fiat) | **باز** — فعلاً اصل‌موضوعه در `ASSUMPTIONS.md` |
| مسیر Squirrel/Tamarin | **باز** — پیش‌نویس outreach در `OUTREACH_DRAFTS.md` |

## ۲. پژوهشگران / بازبینی بیرونی

همه پاسخ‌ها به‌صورت **پیش‌نویس** در `OUTREACH_DRAFTS.md` — ارسال واقعی نیاز به انسان دارد (Zoom، OIDF، ccها).

## ۳. OIDF / AuthZEN

پیش‌نویس پست + چک‌لیست توافق‌نامه در `OUTREACH_DRAFTS.md` §8 — امضا/ارسال دستی.

## ۴. انتشار پژوهشی

| کار | وضعیت |
|---|---|
| TLC برای authgate-kernel | **در حال اجرا/تنظیم** — `formal/tlc_run.log`؛ مدل با `Len(audit_log)<=1` برای اولین سبز |
| برنامه ۱۰ هفته‌ای | باز (زمان‌بندی جدا) |
| endorser arXiv cascade-conformal | باز — پیگیری انسانی |
| ایمیل Kotte / MIT ORC | باز — پیگیری انسانی |

## ۵. زیرساخت پورتفولیو

ریپوهای ردهٔ ۲ (PipelineGuard، HAIIP، …) در این workspace نیستند → از این سشن قابل رفع نیستند. ممیزی ۳۵ ریپو: نیاز به کلون/مسیر جدا.

## فرمان‌های تأیید سریع

```text
cd decision-os-min && python -m pytest -q
cd contracts-spec && python -m conformance.suite
```
