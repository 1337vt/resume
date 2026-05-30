#!/usr/bin/env python3
"""CISA KEV News Article Generator for claytonvantol.us.

Usage:
    python .github/scripts/generate_cisa_news.py
    TEST_CVE=CVE-2026-48027 python .github/scripts/generate_cisa_news.py
"""

import json
import os
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from xml.sax.saxutils import escape as xesc

def jsesc(s):
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

import requests
from PIL import Image, ImageDraw, ImageFont

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
INDEXNOW_URL = "https://api.indexnow.org/indexnow"
SITE = "https://claytonvantol.us"
# This key is used to index this specific site on Google.  It's useless to you.
INDEXNOW_KEY = "db34f75ac00547bab08bb1833d1acc63"

REPO = Path(__file__).resolve().parent.parent.parent
NEWS = REPO / "news"
IMAGES = NEWS / "images"
STATE_FILE = REPO / "news/cisa_kev_state.json"
INDEX_FILE = REPO / "index.html"
SITEMAP_FILE = REPO / "sitemap.xml"

OG_W, OG_H = 1200, 630


def slugify(text):
    text = re.sub(r'[^\w\s-]', '', text.lower().strip())
    return re.sub(r'[-\s]+', '-', text).strip('-')


def article_slug(cve):
    cid = cve["cveID"].lower()
    return f"cve-{cid.replace('cve-', '')}-{slugify(cve['vendorProject'])}-{slugify(cve['product'])}"[:120].rstrip("-")


def parse_notes(notes):
    if not notes:
        return []
    return re.findall(r'https?://[^\s;"]+', notes)


def fetch_kev():
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    return resp.json()


def try_font(*paths, size=16):
    for p in paths:
        if Path(p).exists():
            try:
                return ImageFont.truetype(p, size)
            except (IOError, OSError):
                continue
    return ImageFont.load_default()


def make_og_image(cve, slug):
    cve_id = cve["cveID"]
    vendor = cve["vendorProject"]
    product = cve["product"]
    ransomware = cve.get("knownRansomwareCampaignUse", "Unknown")

    img = Image.new("RGB", (OG_W, OG_H), (10, 10, 10))
    draw = ImageDraw.Draw(img)

    font_large = try_font(
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        size=60,
    )
    font_medium = try_font(
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        size=28,
    )
    font_small = try_font(
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        size=18,
    )
    font_badge = try_font(
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        size=22,
    )

    draw.text((30, 25), "CISA KEV", fill=(255, 107, 53), font=font_badge)
    draw.line([(30, 62), (OG_W - 30, 62)], fill=(40, 40, 40), width=1)

    cve_bb = draw.textbbox((0, 0), cve_id, font=font_large)
    cve_x = (OG_W - (cve_bb[2] - cve_bb[0])) // 2
    draw.text((cve_x, 200), cve_id, fill=(0, 255, 65), font=font_large)

    vp_text = f"{vendor} / {product}"
    vp_bb = draw.textbbox((0, 0), vp_text, font=font_medium)
    vp_x = (OG_W - (vp_bb[2] - vp_bb[0])) // 2
    draw.text((vp_x, 280), vp_text, fill=(150, 150, 150), font=font_medium)

    desc_text = "Known Exploited Vulnerability Catalog"
    desc_bb = draw.textbbox((0, 0), desc_text, font=font_small)
    desc_x = (OG_W - (desc_bb[2] - desc_bb[0])) // 2
    draw.text((desc_x, 335), desc_text, fill=(100, 100, 100), font=font_small)

    if ransomware == "Known":
        r_text = "USED IN RANSOMWARE CAMPAIGNS"
        r_bb = draw.textbbox((0, 0), r_text, font=font_small)
        r_x = (OG_W - (r_bb[2] - r_bb[0])) // 2
        draw.text((r_x, 370), r_text, fill=(255, 50, 50), font=font_small)

    wm = "claytonvantol.us"
    wm_bb = draw.textbbox((0, 0), wm, font=font_small)
    wm_x = OG_W - (wm_bb[2] - wm_bb[0]) - 25
    wm_y = OG_H - (wm_bb[3] - wm_bb[1]) - 20
    draw.text((wm_x, wm_y), wm, fill=(60, 60, 60), font=font_small)

    out = IMAGES / f"{slug}.jpg"
    img.save(out, "JPEG", quality=85)
    return out


def render_article(cve, slug):
    cve_id = cve["cveID"]
    vname = cve["vulnerabilityName"]
    title = f"{cve_id} \u2014 {vname}"
    desc = cve["shortDescription"][:160]
    vendor = cve["vendorProject"]
    product = cve["product"]
    date_added = cve["dateAdded"]
    action = cve["requiredAction"]
    due = cve["dueDate"]
    ransomware = cve.get("knownRansomwareCampaignUse", "Unknown")
    cwes = cve.get("cwes", [])
    refs = parse_notes(cve.get("notes", ""))

    tag_items = [vendor, product, cve_id, "CISA", "KEV"]
    if ransomware == "Known":
        tag_items.append("Ransomware")
    tag_items.extend(cwes)
    tags_csv = ", ".join(tag_items)
    tags_og = "\n    ".join(f'<meta property="article:tag" content="{xesc(t)}">' for t in tag_items)
    tags_json = json.dumps(tag_items)

    rows = [
        ("Vendor", vendor),
        ("Product", product),
        ("CVE ID", cve_id),
        ("Date Added", date_added),
        ("Due Date", due),
    ]
    if cwes:
        rows.insert(2, ("CWE", ", ".join(cwes)))
    if ransomware == "Known":
        rows.append(("Ransomware Campaign", "Known \u2014 this vulnerability has been leveraged in ransomware campaigns"))
    else:
        rows.append(("Ransomware Campaign", "Unknown"))

    tr = "\n".join(
        f'''                            <tr>
                                <td style="padding:4px 8px; color:var(--gray); white-space:nowrap;">{k}</td>
                                <td style="padding:4px 8px; color:var(--text);">{xesc(str(v))}</td>
                            </tr>'''
        for k, v in rows
    )

    sections = f'''                    <p style="margin-bottom:16px;">
                        <span style="color:var(--green);">[event]</span>
                        {xesc(cve['shortDescription'])}
                    </p>

                    <ins class="adsbygoogle"
                         style="display:block; text-align:center;"
                         data-ad-layout="in-article"
                         data-ad-format="fluid"
                         data-ad-client="ca-pub-2188611073019382"
                         data-ad-slot="4187618054"></ins>
                    <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>

                    <h2 style="color:var(--lime); font-size:13px; margin-bottom:10px; margin-top:24px;">
                        &gt; AFFECTED SOFTWARE
                    </h2>
                    <div style="border:1px solid var(--gray); padding:12px; font-size:12px; line-height:1.8; margin-bottom:20px;">
                        <table style="width:100%; border-collapse:collapse; font-size:12px;">
                            <tr style="color:var(--gray); border-bottom:1px solid var(--gray);">
                                <th style="padding:4px 8px; text-align:left;">Field</th>
                                <th style="padding:4px 8px; text-align:left;">Value</th>
                            </tr>
{tr}
                        </table>
                    </div>

                    <h2 style="color:var(--green); font-size:13px; margin-bottom:10px; margin-top:24px;">
                        &gt; MITIGATION
                    </h2>
                    <p style="margin-bottom:16px;">
                        {xesc(action)}
                    </p>
                    <p style="margin-bottom:16px; color:var(--orange);">
                        Due Date: {due}
                    </p>'''

    if refs:
        r_li = "\n".join(
            f'''                        <li style="margin-bottom:4px;">
                            <span style="color:var(--gray);">[{i+1}]</span>
                            <a href="{xesc(u)}" target="_blank" rel="noopener" style="color:var(--lime);">{xesc(u[:80] + '...' if len(u) > 80 else u)}</a>
                        </li>'''
            for i, u in enumerate(refs)
        )
        sections += f'''

                    <h2 style="color:var(--gray); font-size:13px; margin-bottom:10px; margin-top:24px;">
                        &gt; REFERENCES
                    </h2>
                    <ul style="list-style:none; margin-bottom:16px; font-size:12px;">
{r_li}
                    </ul>'''

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    prompt = f"clayton@site:~/news$ cat {slug}.log"

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>{xesc(title)}</title>
    <meta name="description" content="{xesc(desc)}">
    <meta name="keywords" content="{xesc(tags_csv)}">
    <meta name="author" content="Clayton VanTol">
    <meta name="robots" content="index, follow">
    <meta name="theme-color" content="#0a0a0a">
    <meta property="og:type" content="article">
    <meta property="og:title" content="{xesc(title)}">
    <meta property="og:description" content="{xesc(desc)}">
    <meta property="og:url" content="{SITE}/news/{slug}.html">
    <meta property="og:site_name" content="claytonvantol.us">
    <meta property="og:locale" content="en_US">
    <meta property="og:image" content="{SITE}/news/images/{slug}.jpg">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">
    <meta property="og:image:alt" content="{xesc(desc)}">
    <meta property="article:published_time" content="{date_added}T00:00:00Z">
    <meta property="article:modified_time" content="{date_added}T00:00:00Z">
    <meta property="article:section" content="CISA Known Exploited Vulnerability">
    {tags_og}
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="{xesc(title)}">
    <meta name="twitter:description" content="{xesc(desc)}">
    <meta name="twitter:image" content="{SITE}/news/images/{slug}.jpg">
    <link rel="canonical" href="{SITE}/news/{slug}.html">
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="apple-touch-icon" href="/apple-touch-icon.png">
    <link rel="stylesheet" href="../style.css">
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-W2QLVH4HZQ"></script>
    <script>
        window.dataLayer = window.dataLayer || [];
        function gtag(){{dataLayer.push(arguments);}}
        gtag('js', new Date());
        gtag('config', 'G-W2QLVH4HZQ');
    </script>
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-2188611073019382" crossorigin="anonymous"></script>
    <script type="application/ld+json">
    {{
        "@context": "https://schema.org",
        "@type": "NewsArticle",
        "headline": {json.dumps(title)},
        "description": "{xesc(desc)}",
        "datePublished": "{date_added}",
        "dateModified": "{date_added}",
        "author": {{ "@type": "Person", "name": "Clayton VanTol", "url": "{SITE}" }},
        "publisher": {{ "@type": "Organization", "name": "claytonvantol.us", "url": "{SITE}" }},
        "mainEntityOfPage": {{ "@type": "WebPage", "@id": "{SITE}/news/{slug}.html" }},
        "image": "{SITE}/news/images/{slug}.jpg",
        "articleSection": "CISA Known Exploited Vulnerability",
        "keywords": {tags_json}
    }}
    </script>
    <script type="application/ld+json">
    {{
        "@context": "https://schema.org",
        "@type": "BreadcrumbList",
        "itemListElement": [
            {{ "@type": "ListItem", "position": 1, "name": "Home", "item": "{SITE}/" }},
            {{ "@type": "ListItem", "position": 2, "name": "News", "item": "{SITE}/news/" }},
            {{ "@type": "ListItem", "position": 3, "name": {json.dumps(cve_id)} }}
        ]
    }}
    </script>
</head>
<body>
<div class="page-wrapper">
    <div class="ad-column ad-left">
        <ins class="adsbygoogle"
             style="display:block"
             data-ad-client="ca-pub-2188611073019382"
             data-ad-slot="8047961692"
             data-ad-format="auto"
             data-full-width-responsive="true"></ins>
        <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
    </div>
    <div class="terminal fade-in">
        <div class="top-bar">
            <div class="left">
                <span class="dot dot-red"></span>
                <span class="dot dot-yellow"></span>
                <span class="dot dot-green"></span>
                <span style="margin-left:10px;">claytonvantol.us</span>
            </div>
            <div class="right">
                <span>SESSION: secure</span>
                <span>TLS: 1.3</span>
                <span>PID: 1337</span>
            </div>
        </div>
        <div class="content">
            <p style="color:var(--gray); font-size:12px; margin-bottom:16px;">
                <span style="color:var(--green);">{xesc(prompt)}</span>
            </p>
            <article>
                <h1 class="glitch" style="font-size:22px; color:var(--orange); letter-spacing:3px; margin-bottom:4px;">
                    {xesc(title)}
                </h1>
                <p style="color:var(--gray); font-size:11px; margin-bottom:24px;">
                    {date_added} &bull; CISA Known Exploited Vulnerability
                </p>
                <hr class="separator">
                <div style="font-size:13px; color:var(--text); line-height:1.9;">
{sections}
                </div>
            </article>
            <hr class="separator">
            <p style="text-align:center; margin-top:16px;">
                <a href="../index.html" class="btn-link">&#8592; back to terminal</a>
            </p>
        </div>
        <div class="bottom-bar">
            <span>UPTIME: 1337d</span>
            <span>v2.0.1</span>
            <span><a href="../privacy.html" style="color:var(--gray); text-decoration:none;">privacy</a></span>
            <span>LAST LOGIN: {now} UTC</span>
        </div>
    </div>
    <div class="ad-column ad-right">
        <ins class="adsbygoogle"
             style="display:block"
             data-ad-client="ca-pub-2188611073019382"
             data-ad-slot="1902189895"
             data-ad-format="auto"
             data-full-width-responsive="true"></ins>
        <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
    </div>
</div><!-- .page-wrapper -->
<script>
window.addEventListener('load', function() {{
    if (typeof adsbygoogle !== 'function') {{
        document.body.classList.add('ads-blocked');
    }}
}});
</script>
</body>
</html>'''


def inject_into_index(cves, slugs):
    html = INDEX_FILE.read_text()
    lines = html.split("\n")

    new_entries = []
    for cve, slug in zip(cves, slugs):
        t = f"{cve['cveID']} \u2014 {cve['vulnerabilityName']} ({cve['dateAdded'][:4]})"
        new_entries.append(
            f'            {{ title: "{jsesc(t)}", url: "news/{slug}.html", date: "{cve["dateAdded"]}", category: "CISA Known Exploited Vulnerability", vendor: "{jsesc(cve["vendorProject"])}" }},'
        )

    insert_after = -1
    for i, line in enumerate(lines):
        if "const newsArticles = [" in line:
            insert_after = i
            break

    if insert_after < 0:
        print("WARNING: could not find newsArticles array in index.html", file=sys.stderr)
        return

    for entry in reversed(new_entries):
        lines.insert(insert_after + 1, entry)

    INDEX_FILE.write_text("\n".join(lines) + "\n")


def update_sitemap(cves, slugs):
    content = SITEMAP_FILE.read_text()

    new_entries = []
    for cve, slug in zip(cves, slugs):
        new_entries.append(f'''  <url>
    <loc>{SITE}/news/{slug}.html</loc>
    <lastmod>{cve["dateAdded"]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>''')

    insert = "\n".join(new_entries) + "\n</urlset>"
    content = content.replace("</urlset>", insert)
    SITEMAP_FILE.write_text(content)


def ping_indexnow(cves, slugs):
    urls = [f"{SITE}/news/{slug}.html" for slug in slugs]
    if not urls:
        return

    payload = {
        "host": "claytonvantol.us",
        "key": INDEXNOW_KEY,
        "keyLocation": f"{SITE}/{INDEXNOW_KEY}.txt",
        "urlList": urls,
    }

    try:
        resp = requests.post(INDEXNOW_URL, json=payload, timeout=10)
        resp.raise_for_status()
        print(f"  IndexNow pinged: {len(urls)} URL(s)")
    except Exception as e:
        print(f"  IndexNow ping failed: {e}", file=sys.stderr)


def process_cves(cves, state, published, force=False):
    """Render articles for a list of CVEs. Returns list of (cve, slug) created.

    If an article file already exists, the CVE is added to state and skipped
    (unless force=True, which forces re-render for test mode).
    """
    created = []
    for cve in cves:
        slug = article_slug(cve)
        cve_id = cve["cveID"]
        article_path = NEWS / f"{slug}.html"

        if not force and article_path.exists():
            print(f"  {cve_id} → article exists, skipped")
            if cve_id not in published:
                state["publishedCves"].append(cve_id)
            continue

        created.append((cve, slug))

        print(f"  Rendering {cve_id} -> news/{slug}.html")
        (NEWS / f"{slug}.html").write_text(render_article(cve, slug))

        print(f"  Generating OG image -> news/images/{slug}.jpg")
        make_og_image(cve, slug)

        state["publishedCves"].append(cve_id)

    return created


def main():
    test_cve = os.environ.get("TEST_CVE", "").strip() or None
    backfill_year = os.environ.get("BACKFILL_YEAR", "").strip() or None
    IMAGES.mkdir(parents=True, exist_ok=True)

    print("Fetching CISA KEV feed ...")
    kev = fetch_kev()
    print(f"  Catalog: {kev['catalogVersion']}, {kev['count']} vulnerabilities")

    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {
        "baselineComplete": False,
        "publishedCves": [],
        "lastCatalogVersion": "",
        "lastDateReleased": "",
    }
    published = set(state["publishedCves"])

    # --- Backfill: process all CVEs from a given year ---
    if backfill_year:
        print(f"  Backfill mode: year {backfill_year}")
        candidates = [v for v in kev["vulnerabilities"]
                      if v["dateAdded"].startswith(backfill_year)]
        print(f"  Found {len(candidates)} CVEs from {backfill_year}")

        created = process_cves(candidates, state, published, force=False)

        if created:
            new_cves, new_slugs = zip(*created)
            print("  Updating index.html ...")
            inject_into_index(new_cves, new_slugs)
            print("  Updating sitemap.xml ...")
            update_sitemap(new_cves, new_slugs)
            ping_indexnow(new_cves, new_slugs)

        state["baselineComplete"] = True
        state["lastCatalogVersion"] = kev["catalogVersion"]
        state["lastDateReleased"] = kev["dateReleased"]
        STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")

        print(f"Done. {len(created)} new article(s) generated from {backfill_year}.")
        return

    # --- Baseline: snapshot all CVEs without generating articles ---
    if not state["baselineComplete"] and not test_cve:
        state["publishedCves"] = [v["cveID"] for v in kev["vulnerabilities"]]
        state["baselineComplete"] = True
        state["lastCatalogVersion"] = kev["catalogVersion"]
        state["lastDateReleased"] = kev["dateReleased"]
        STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")
        print(f"  Baseline snapshot: {len(state['publishedCves'])} CVEs saved.")
        print("  No articles generated. Next run will process new CVEs.")
        return

    # --- Test mode: process a single CVE (force re-render, skip state save) ---
    if test_cve:
        match = [v for v in kev["vulnerabilities"] if v["cveID"] == test_cve]
        if not match:
            print(f"  ERROR: {test_cve} not found in feed.")
            sys.exit(1)
        print(f"  Test mode: processing {test_cve}")
        created = process_cves(match, state, published, force=True)

        if created:
            new_cves, new_slugs = zip(*created)
            print("  Updating index.html ...")
            inject_into_index(new_cves, new_slugs)
            print("  Updating sitemap.xml ...")
            update_sitemap(new_cves, new_slugs)
            ping_indexnow(new_cves, new_slugs)

        # Never save state in test mode — allows repeated testing
        print(f"Done. {len(created)} article(s) generated (test mode, state not saved).")
        return

    # --- Incremental mode: process new CVEs not yet published ---
    candidates = [v for v in kev["vulnerabilities"] if v["cveID"] not in published]
    if not candidates:
        print("  No new CVEs to process.")
        return

    created = process_cves(candidates, state, published, force=False)

    if not created:
        print("  All candidates already exist as files. Updating state.")
        state["lastCatalogVersion"] = kev["catalogVersion"]
        state["lastDateReleased"] = kev["dateReleased"]
        STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")
        return

    new_cves, new_slugs = zip(*created)
    print("  Updating index.html ...")
    inject_into_index(new_cves, new_slugs)
    print("  Updating sitemap.xml ...")
    update_sitemap(new_cves, new_slugs)

    state["lastCatalogVersion"] = kev["catalogVersion"]
    state["lastDateReleased"] = kev["dateReleased"]
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")

    ping_indexnow(new_cves, new_slugs)
    print(f"Done. {len(created)} article(s) generated.")


if __name__ == "__main__":
    main()
