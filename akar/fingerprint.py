from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .models import Page

if TYPE_CHECKING:  # pragma: no cover
    from .engine import Context

COOKIE_TECH = [
    ("phpsessid", "PHP"),
    ("jsessionid", "Java"),
    ("asp.net_sessionid", "ASP.NET"),
    ("_sessionid", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("csrftoken", "Django"),
    ("django_language", "Django"),
    ("_app_session", "Ruby on Rails"),
    ("connect.sid", "Express.js"),
    ("next-auth", "NextAuth.js"),
    ("xsrf-token", "Angular / Laravel"),
]

BODY_PATTERNS = [
    (r"wp-content/(?:themes|plugins)/", "cms", "WordPress"),
    (r"wp-includes/", "cms", "WordPress"),
    (r"Joomla!", "cms", "Joomla"),
    (r"/media/jui/", "cms", "Joomla"),
    (r"Drupal\.settings", "cms", "Drupal"),
    (r"/sites/default/files/", "cms", "Drupal"),
    (r"cdn\.shopify\.com", "cms", "Shopify"),
    (r"magento", "cms", "Magento"),
    (r"prestashop", "cms", "PrestaShop"),
    (r"woocommerce", "cms", "WooCommerce"),
    (r"__NEXT_DATA__", "framework", "Next.js"),
    (r"/_nuxt/", "framework", "Nuxt.js"),
    (r"window\.__NUXT__", "framework", "Nuxt.js"),
    (r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__", "framework", "React"),
    (r"data-v-[0-9a-f]{8}(?:\s|\")", "framework", "Vue.js"),
    (r"ng-version=", "framework", "Angular"),
    (r"ng-app=", "framework", "AngularJS"),
    (r"Gatsby", "framework", "Gatsby"),
    (r"csrfmiddlewaretoken", "framework", "Django"),
    (r"laravel_session|XSRF-TOKEN", "framework", "Laravel"),
    (r"_ignition/", "framework", "Laravel Ignition"),
    (r"Werkzeug|Flask", "framework", "Flask"),
    (r"google-analytics\.com/analytics", "analytics", "Google Analytics"),
    (r"gtag\(|googletagmanager\.com", "analytics", "Google Tag Manager"),
    (r"fbq\(|connect\.facebook\.net", "analytics", "Facebook Pixel"),
    (r"cdn\.segment\.com", "analytics", "Segment"),
    (r"matomo|piwik", "analytics", "Matomo"),
    (r"hotjar", "analytics", "Hotjar"),
    (r"clarity\.ms", "analytics", "Microsoft Clarity"),
    (r"plausible\.io", "analytics", "Plausible"),
    (r"mixpanel", "analytics", "Mixpanel"),
    (r"amplitude\.com", "analytics", "Amplitude"),
    (r"fullstory", "analytics", "FullStory"),
    (r"hs-scripts\.com|hubspot", "analytics", "HubSpot"),
    (r"bootstrap[^\"']*\.css", "js", "Bootstrap"),
]

VERSIONED = [
    (r"nginx/([\d.]+)", "server", "nginx"),
    (r"Apache/([\d.]+)", "server", "Apache"),
    (r"Microsoft-IIS/([\d.]+)", "server", "Microsoft IIS"),
    (r"LiteSpeed", "server", "LiteSpeed"),
    (r"PHP/([\d.]+)", "language", "PHP"),
    (r"WordPress ([\d.]+)", "cms", "WordPress"),
    (r"Drupal (\d+)", "cms", "Drupal"),
    (r"Joomla! ?([\d.]*)", "cms", "Joomla"),
    (r"jQuery v([\d.]+)", "js", "jQuery"),
    (r"jQuery[.-]v?([\d.]+)", "js", "jQuery"),
    (r"angular[.-](\d+\.\d+(?:\.\d+)?)", "js", "AngularJS"),
    (r'ng-version="([^"]+)"', "framework", "Angular"),
]


def fingerprint(ctx: "Context", page: Page) -> None:
    headers = page.headers
    server = headers.get("server", "")
    if server:
        ctx.note_technology("server", server)
    powered = headers.get("x-powered-by", "")
    if powered:
        ctx.note_technology("framework", powered)
    if headers.get("x-aspnet-version"):
        ctx.note_technology("framework", "ASP.NET " + headers["x-aspnet-version"])
    if headers.get("x-generator"):
        ctx.note_technology("generator", headers["x-generator"])

    # CDN / WAF
    if headers.get("cf-ray") or server.lower() == "cloudflare":
        ctx.note_technology("cdn", "Cloudflare")
    if headers.get("x-amz-cf-id"):
        ctx.note_technology("cdn", "Amazon CloudFront")
    if headers.get("x-fastly-request-id"):
        ctx.note_technology("cdn", "Fastly")
    if "akamai" in server.lower() or headers.get("x-akamai-transformed"):
        ctx.note_technology("cdn", "Akamai")
    if headers.get("x-sucuri-id") or headers.get("x-sucuri-cache"):
        ctx.note_technology("waf", "Sucuri WAF")
    if headers.get("x-aws-waf") or headers.get("x-amzn-waf"):
        ctx.note_technology("waf", "AWS WAF")
    if headers.get("cf-mitigated"):
        ctx.note_technology("waf", "Cloudflare Bot Management")
    if "incapsula" in headers.get("x-iinfo", "").lower() or headers.get("x-cdn") == "Incapsula":
        ctx.note_technology("waf", "Imperva/Incapsula")

    # cookies
    for raw in page.set_cookies:
        name = raw.split("=", 1)[0].strip().lower()
        for cookie_name, tech in COOKIE_TECH:
            if name == cookie_name:
                ctx.note_technology("framework", tech)

    if "wp-json" in headers.get("link", ""):
        ctx.note_technology("cms", "WordPress")

    body = page.body[:400_000]
    gen = re.search(
        r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body[:20000], re.I
    )
    if gen:
        ctx.note_technology("generator", gen.group(1).strip())

    for pattern, category, label in BODY_PATTERNS:
        if re.search(pattern, body, re.I):
            ctx.note_technology(category, label)

    for pattern, category, label in VERSIONED:
        match = re.search(pattern, body, re.I)
        if match:
            version = match.group(1).strip() if match.groups() else ""
            ctx.note_technology(category, f"{label} {version}".strip())
