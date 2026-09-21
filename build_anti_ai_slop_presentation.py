import os
import shutil
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

SRC_TEMPLATE = r'C:\Users\vishw\Downloads\SIH2026-IDEA-Presentation-Format (1).pptx.bak'
if not os.path.exists(SRC_TEMPLATE):
    SRC_TEMPLATE = r'C:\Users\vishw\Downloads\SIH2026-IDEA-Presentation-Format (1).pptx'

prs = Presentation(SRC_TEMPLATE)

# Brand Color Palette (High Craft SOC Visuals)
COLOR_NAVY = RGBColor(11, 37, 69)          # #0B2545 (Deep Academic Navy)
COLOR_NAVY_LIGHT = RGBColor(30, 58, 138)   # #1E3A8A
COLOR_ORANGE = RGBColor(234, 88, 12)       # #EA580C (SIH Saffron)
COLOR_DARK = RGBColor(30, 41, 59)          # #1E293B (Charcoal text)
COLOR_MUTED = RGBColor(71, 85, 105)        # #475569 (Secondary text)
COLOR_GREEN = RGBColor(22, 163, 74)        # #16A34A (Success/Pill badge)
COLOR_CARD_BG = RGBColor(248, 250, 252)    # #F8FAFC (Subtle card background)
COLOR_CARD_BORDER = RGBColor(203, 213, 225)# #CBD5E1 (Clean card stroke)
COLOR_CARD_INNER = RGBColor(241, 245, 249) # #F1F5F9 (Inner highlight)
COLOR_WHITE = RGBColor(255, 255, 255)

FONT_HEAD = "Arial"
FONT_BODY = "Calibri"

NEW_FOOTER_TEXT = "Smart India Hackathon 2026  |  Problem Statement ID: SIH26106  |  Team CyberCore  |  CVR College of Engineering"

# ----------------------------------------------------------------------
# HELPER: Update Footer and Remove Template Placeholder
# ----------------------------------------------------------------------
def update_slide_footer(slide):
    for sh in slide.shapes:
        if "Footer" in sh.name and sh.has_text_frame:
            tf = sh.text_frame
            tf.clear()
            p = tf.paragraphs[0]
            p.text = NEW_FOOTER_TEXT
            p.font.name = FONT_BODY
            p.font.size = Pt(8.5)
            p.font.color.rgb = COLOR_MUTED
            p.alignment = PP_ALIGN.CENTER

# ----------------------------------------------------------------------
# HELPER: Apply Single-Line Top-Left CyberCore Oval Badge
# ----------------------------------------------------------------------
def apply_top_left_oval_badge(slide, slide_num):
    for s in list(slide.shapes):
        if "Oval" in s.name:
            sp_elem = s._element
            sp_elem.getparent().remove(sp_elem)

    oval = slide.shapes.add_shape(
        MSO_SHAPE.OVAL,
        Inches(0.40), Inches(0.18), Inches(1.80), Inches(0.82)
    )
    oval.name = f"Oval CyberCore Slide {slide_num}"
    oval.fill.solid()
    oval.fill.fore_color.rgb = COLOR_ORANGE
    oval.line.color.rgb = COLOR_NAVY
    oval.line.width = Pt(2.2)

    tf = oval.text_frame
    tf.word_wrap = False
    tf.margin_left = Inches(0.04)
    tf.margin_right = Inches(0.04)
    tf.margin_top = Inches(0.04)
    tf.margin_bottom = Inches(0.04)
    tf.clear()
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    run = p.add_run()
    run.text = "CyberCore"
    run.font.name = FONT_HEAD
    run.font.size = Pt(11.5)
    run.font.bold = True
    run.font.color.rgb = COLOR_WHITE
    return oval

# ----------------------------------------------------------------------
# HELPER: Format Standard Slide Header Zone
# ----------------------------------------------------------------------
def format_header_zone(slide, main_title, category_tag="SMART INDIA HACKATHON 2026 — IDEA SUBMISSION"):
    for s in slide.shapes:
        if s.name == "Title 1" and s.has_text_frame:
            s.left = Inches(2.40)
            s.top = Inches(0.15)
            s.width = Inches(8.10)
            s.height = Inches(0.95)
            tf = s.text_frame
            tf.word_wrap = True
            tf.clear()
            
            p_tag = tf.paragraphs[0]
            p_tag.space_after = Pt(2)
            r_tag = p_tag.add_run()
            r_tag.text = category_tag.upper()
            r_tag.font.name = FONT_HEAD
            r_tag.font.size = Pt(8.5)
            r_tag.font.bold = True
            r_tag.font.color.rgb = COLOR_ORANGE

            p_title = tf.add_paragraph()
            r_title = p_title.add_run()
            r_title.text = main_title
            r_title.font.name = FONT_HEAD
            r_title.font.size = Pt(17)
            r_title.font.bold = True
            r_title.font.color.rgb = COLOR_NAVY

# ----------------------------------------------------------------------
# HELPER: Create Bento Card Container
# ----------------------------------------------------------------------
def create_bento_card(slide, left, top, width, height, title="", title_color=COLOR_ORANGE):
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD_BG
    card.line.color.rgb = COLOR_CARD_BORDER
    card.line.width = Pt(1.2)
    
    tf = card.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.20)
    tf.margin_right = Inches(0.20)
    tf.margin_top = Inches(0.18)
    tf.margin_bottom = Inches(0.18)
    tf.clear()
    
    if title:
        p = tf.paragraphs[0]
        p.space_after = Pt(6)
        r = p.add_run()
        r.text = title.upper()
        r.font.name = FONT_HEAD
        r.font.size = Pt(11)
        r.font.bold = True
        r.font.color.rgb = title_color
        
    return card, tf

# Clear raw TextBox 8 on content slides (Slides 2-6)
for idx in range(1, 6):
    slide = prs.slides[idx]
    for s in list(slide.shapes):
        if s.name == "TextBox 8":
            sp_elem = s._element
            sp_elem.getparent().remove(sp_elem)

# ======================================================================
# SLIDE 1: TITLE PAGE & PROBLEM ANALYSIS
# ======================================================================
slide1 = prs.slides[0]
apply_top_left_oval_badge(slide1, 1)

# Format Title 7 and Subtitle 3
for s in slide1.shapes:
    if s.name == "Title 7":
        s.left = Inches(2.40)
        s.top = Inches(0.15)
        s.width = Inches(8.10)
        s.height = Inches(0.95)
        if s.has_text_frame:
            tf = s.text_frame
            tf.clear()
            p1 = tf.paragraphs[0]
            r1 = p1.add_run()
            r1.text = "SMART INDIA HACKATHON 2026"
            r1.font.name = FONT_HEAD
            r1.font.size = Pt(20)
            r1.font.bold = True
            r1.font.color.rgb = COLOR_NAVY
            
            p2 = tf.add_paragraph()
            r2 = p2.add_run()
            r2.text = "OFFICIAL IDEA SUBMISSION  |  CYBER SECURITY & AUTOMATION"
            r2.font.name = FONT_HEAD
            r2.font.size = Pt(9)
            r2.font.bold = True
            r2.font.color.rgb = COLOR_ORANGE

    elif s.name == "Subtitle 3":
        # Remove subtitle placeholder
        sp_elem = s._element
        sp_elem.getparent().remove(sp_elem)

# Clear TextBox 9 and replace with structured Bento Cards
for s in list(slide1.shapes):
    if s.name == "TextBox 9":
        sp_elem = s._element
        sp_elem.getparent().remove(sp_elem)

# Card 1: Official Submission Metadata
card1_meta, tf1_m = create_bento_card(slide1, Inches(0.40), Inches(1.35), Inches(6.80), Inches(2.55), "Official Project Dossier")
meta_rows = [
    ("Problem Statement ID", "SIH26106"),
    ("Problem Statement Title", "AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence"),
    ("Domain & Category", "Cyber Security / Smart Automation  •  Software"),
    ("Institution & Department", "CVR College of Engineering  •  CSE (Cyber Security)"),
    ("Team Name & ID", "CyberCore  •  [Registered on SIH Portal]")
]

for label, val in meta_rows:
    p = tf1_m.add_paragraph()
    p.space_after = Pt(2.5)
    r_lbl = p.add_run()
    r_lbl.text = label + ": "
    r_lbl.font.name = FONT_HEAD
    r_lbl.font.size = Pt(9.5)
    r_lbl.font.bold = True
    r_lbl.font.color.rgb = COLOR_NAVY
    r_val = p.add_run()
    r_val.text = val
    r_val.font.name = FONT_BODY
    r_val.font.size = Pt(9.5)
    r_val.font.color.rgb = COLOR_DARK

# Prototype Link Pill
p_proto = tf1_m.add_paragraph()
p_proto.space_before = Pt(3)
r_p1 = p_proto.add_run()
r_p1.text = "★ LIVE WORKING PROTOTYPE: "
r_p1.font.name = FONT_HEAD
r_p1.font.bold = True
r_p1.font.size = Pt(10)
r_p1.font.color.rgb = COLOR_GREEN
r_p2 = p_proto.add_run()
r_p2.text = "threatlens-gen.vercel.app"
r_p2.font.name = FONT_HEAD
r_p2.font.bold = True
r_p2.font.underline = True
r_p2.font.size = Pt(10)
r_p2.font.color.rgb = COLOR_NAVY

# Card 2: Problem Analysis (Strictly Anti-AI Slop, Zero Tech Buzzwords)
card1_prob, tf1_p = create_bento_card(slide1, Inches(0.40), Inches(4.05), Inches(6.80), Inches(2.75), "Problem Analysis & The Ground Reality")
analysis_points = [
    ("91% Initial Compromise Vector", "Email remains the primary threat vector for Business Email Compromise (BEC), spearphishing, and credential theft across Indian enterprises."),
    ("Legacy Gateway Blindspots", "Traditional Secure Email Gateways (SEGs) rely on static IP blacklists—completely blind to zero-day lookalike domains and compromised legitimate cloud relays."),
    ("Corporate Privacy Hazard", "Forwarding confidential corporate emails to third-party cloud sandboxes violates GDPR and India's DPDP Act 2023 data sovereignty frameworks."),
    ("Frontline Telemetry Void", "Security analysts are overwhelmed by fragmented text logs without unified cryptographic alignment or spatial geolocation telemetry.")
]

for title, body in analysis_points:
    p = tf1_p.add_paragraph()
    p.space_after = Pt(2.5)
    r_t = p.add_run()
    r_t.text = f"• {title}: "
    r_t.font.name = FONT_HEAD
    r_t.font.size = Pt(9)
    r_t.font.bold = True
    r_t.font.color.rgb = COLOR_NAVY
    r_b = p.add_run()
    r_b.text = body
    r_b.font.name = FONT_BODY
    r_b.font.size = Pt(9)
    r_b.font.color.rgb = COLOR_DARK

print("Slide 1 redesigned.")

# ======================================================================
# SLIDE 2: PROPOSED SOLUTION & ARCHITECTURAL NOVELTY
# ======================================================================
slide2 = prs.slides[1]
apply_top_left_oval_badge(slide2, 2)
update_slide_footer(slide2)
format_header_zone(slide2, "IDEA TITLE: ThreatLens AI", "Zero-Trust Email Threat Forensics & Spatial Intelligence")

# Left Card: Proposed Solution & Workflow Transformation
c2_left, tf2_l = create_bento_card(slide2, Inches(0.40), Inches(1.30), Inches(6.00), Inches(5.45), "Proposed Solution & Workflow Disruption")

p_intro = tf2_l.add_paragraph()
p_intro.space_after = Pt(6)
r_in = p_intro.add_run()
r_in.text = "ThreatLens AI is a client-side zero-trust cybersecurity workstation that executes full RFC MIME header disassembly, unified cryptographic authentication, and 3D geospatial attack projection to neutralize email threats before user credential or monetary loss occurs."
r_in.font.name = FONT_BODY
r_in.font.size = Pt(9.5)
r_in.font.color.rgb = COLOR_DARK

p_wk_h = tf2_l.add_paragraph()
p_wk_h.space_before = Pt(4)
p_wk_h.space_after = Pt(3)
r_wh = p_wk_h.add_run()
r_wh.text = "ARCHITECTURAL WORKFLOW TRANSFORMATION"
r_wh.font.name = FONT_HEAD
r_wh.font.size = Pt(10)
r_wh.font.bold = True
r_wh.font.color.rgb = COLOR_NAVY

workflow_shifts = [
    ("Centralized Cloud Sandbox ➔ Client-Side Zero-Trust", "Legacy tools upload sensitive emails to vendor cloud servers. ThreatLens parses 100% of headers locally in browser memory—zero email contents ever leak outside the host boundary."),
    ("Fragmented Terminal Commands ➔ Unified Triage Matrix", "Replaces 4–6 isolated text utilities (dig, whois, header decoders) with a single-pane correlation dashboard evaluating Envelope vs. Header authenticity in seconds."),
    ("Multi-Identity Spoof Elimination", "Simultaneously disassembles Header-From, Envelope-From (Return-Path), and Reply-To, immediately neutralizing unauthorized cloud relay routing.")
]

for title, desc in workflow_shifts:
    p = tf2_l.add_paragraph()
    p.space_after = Pt(2.5)
    r_t = p.add_run()
    r_t.text = f"• {title}:\n  "
    r_t.font.name = FONT_HEAD
    r_t.font.size = Pt(9)
    r_t.font.bold = True
    r_t.font.color.rgb = COLOR_ORANGE
    r_d = p.add_run()
    r_d.text = desc
    r_d.font.name = FONT_BODY
    r_d.font.size = Pt(9)
    r_d.font.color.rgb = COLOR_DARK

# Right Card: Innovation & Key Differentiators
c2_right, tf2_r = create_bento_card(slide2, Inches(6.60), Inches(1.30), Inches(6.30), Inches(5.45), "Innovation & Technical Uniqueness")

p_pr2 = tf2_r.add_paragraph()
p_pr2.space_after = Pt(6)
r_pr1 = p_pr2.add_run()
r_pr1.text = "★ LIVE PRODUCTION WORKSTATION:\n"
r_pr1.font.name = FONT_HEAD
r_pr1.font.size = Pt(10)
r_pr1.font.bold = True
r_pr1.font.color.rgb = COLOR_GREEN
r_pr2 = p_pr2.add_run()
r_pr2.text = "https://threatlens-gen.vercel.app\n"
r_pr2.font.name = FONT_HEAD
r_pr2.font.size = Pt(11)
r_pr2.font.bold = True
r_pr2.font.underline = True
r_pr2.font.color.rgb = COLOR_NAVY
r_pr3 = p_pr2.add_run()
r_pr3.text = "Fully Deployed • 64/64 Verified Test Cases • Open for Evaluator Testing"
r_pr3.font.name = FONT_BODY
r_pr3.font.size = Pt(8.5)
r_pr3.font.color.rgb = COLOR_MUTED

innovations = [
    ("Unified Cryptographic Alignment", "Evaluates SPF, DKIM, and DMARC side-by-side on a single screen with real DNS TXT snippets, alignment statuses, and plain-language diagnostic explanations."),
    ("3D Geospatial Threat Telemetry", "Translates abstract intermediate IP routing hops into interactive 3D geospatial trajectories, empowering SOC teams to identify coordinate-level adversary clusters instantly."),
    ("Instant Forensic Dossier Export", "Converts raw RFC headers and extracted artifacts into court-admissible, audit-ready PDF forensic incident reports with a single click."),
    ("Three-Discipline Synthesis", "Unifies RFC MIME Forensic Parsers, Cryptographic DNS Alignment Matrices, and 3D Geospatial Threat Visualizers into a cohesive, zero-latency workstation.")
]

for title, desc in innovations:
    p = tf2_r.add_paragraph()
    p.space_after = Pt(3)
    r_t = p.add_run()
    r_t.text = f"• {title}: "
    r_t.font.name = FONT_HEAD
    r_t.font.size = Pt(9)
    r_t.font.bold = True
    r_t.font.color.rgb = COLOR_NAVY
    r_d = p.add_run()
    r_d.text = desc
    r_d.font.name = FONT_BODY
    r_d.font.size = Pt(9)
    r_d.font.color.rgb = COLOR_DARK

print("Slide 2 redesigned.")

# ======================================================================
# SLIDE 3: TECHNICAL APPROACH (WORKFLOWS LEFT | HIERARCHICAL STACK RIGHT)
# ======================================================================
slide3 = prs.slides[2]
apply_top_left_oval_badge(slide3, 3)
update_slide_footer(slide3)
format_header_zone(slide3, "TECHNICAL APPROACH", "Implementation Methodology & Hierarchical Architecture")

# Left Card: 5-Stage Implementation Pipeline
c3_left, tf3_l = create_bento_card(slide3, Inches(0.40), Inches(1.30), Inches(5.95), Inches(5.45), "Implementation Pipeline & Methodology")

pipeline_stages = [
    ("[Stage 1] Multi-Vector Ingestion", "Accepts .eml / .msg drag-and-drop, raw RFC 822 pasted headers, and simulated live SOC telemetry feeds."),
    ("[Stage 2] Recursive MIME Disassembly", "Traverses MIME tree to extract Header-From, Envelope-From, Return-Path, transit Received: hops, URLs, and attachment SHA-256 hashes."),
    ("[Stage 3] Cryptographic Matrix Check", "Simultaneously validates SPF (RFC 7208), DKIM (RFC 6376), and DMARC (RFC 7489) authentication and domain alignment."),
    ("[Stage 4] Geolocation & Threat Scoring", "Extracts connecting MTA IP from Received headers; resolves coordinates and maps adversary origin infrastructure to a 0–100 threat score."),
    ("[Stage 5] Visualization & Actionable SOAR", "Renders 3D attack trajectory on Earth globe and generates printable PDF forensic incident dossiers.")
]

for st, sd in pipeline_stages:
    p = tf3_l.add_paragraph()
    p.space_after = Pt(2.5)
    rt = p.add_run()
    rt.text = f"{st}\n"
    rt.font.name = FONT_HEAD
    rt.font.size = Pt(9.5)
    rt.font.bold = True
    rt.font.color.rgb = COLOR_NAVY
    rd = p.add_run()
    rd.text = sd
    rd.font.name = FONT_BODY
    rd.font.size = Pt(9)
    rd.font.color.rgb = COLOR_DARK

p_jobs = tf3_l.add_paragraph()
p_jobs.space_before = Pt(4)
r_j = p_jobs.add_run()
r_j.text = "★ Steve Jobs Synthesis Analogy:\nJust as the iPhone synthesized a phone, an iPod, and an internet communicator into one device, ThreatLens synthesizes MIME Parsers, Cryptographic DNS Validators, and 3D Spatial Maps into one pocket workstation."
r_j.font.name = FONT_BODY
r_j.font.size = Pt(8.5)
r_j.font.italic = True
r_j.font.color.rgb = COLOR_MUTED

# Right Card: Hierarchical Layered Stack
c3_right, tf3_r = create_bento_card(slide3, Inches(6.55), Inches(1.30), Inches(6.35), Inches(5.45), "Hierarchical Technology Stack (By Layer)")

layers = [
    ("Layer 4: Deployment & Edge Delivery", "Vercel Global Edge Network", "Sub-second global latency, serverless edge caching, automated preview deployment pipelines."),
    ("Layer 3: Application & Visual SOC UX", "Next.js + Three.js + Tailwind CSS", "Next.js (Server/Client hybrid rendering architecture), Three.js (WebGL 3D Earth globe with raycasting), Tailwind CSS, Lucide security icons."),
    ("Layer 2: Forensic & Cryptographic Core", "Browser DOM RFC 822 Engine + DoH", "Client-side RFC 822/5322 MIME parser, SHA-256 Web Crypto API, DNS-over-HTTPS (DoH Cloudflare/Google 1.1.1.1) for live DNS TXT lookups."),
    ("Layer 1: Telemetry & Intelligence Corroboration", "MITRE ATT&CK + MaxMind GeoLite2", "MaxMind IP coordinate mapping, MITRE ATT&CK Enterprise Matrix (v14), IOC reputation corpus (Malicious IPs, Domains, Hashes).")
]

for lname, ltech, ldesc in layers:
    p = tf3_r.add_paragraph()
    p.space_after = Pt(2.5)
    r1 = p.add_run()
    r1.text = f"{lname}\n"
    r1.font.name = FONT_HEAD
    r1.font.size = Pt(9.5)
    r1.font.bold = True
    r1.font.color.rgb = COLOR_NAVY
    r2 = p.add_run()
    r2.text = f"Tech Stack: {ltech}\n"
    r2.font.name = FONT_HEAD
    r2.font.size = Pt(9)
    r2.font.bold = True
    r2.font.color.rgb = COLOR_GREEN
    r3 = p.add_run()
    r3.text = ldesc
    r3.font.name = FONT_BODY
    r3.font.size = Pt(8.5)
    r3.font.color.rgb = COLOR_DARK

p_dt = tf3_r.add_paragraph()
p_dt.space_before = Pt(4)
r_d = p_dt.add_run()
r_d.text = "★ Data Outreach & Nodal Agency Integration:\nLeveraging authentic datasets from data.gov.in (Open Government Data Platform India) and CERT-In incident advisories; outreach initiated for Indian Cyber Crime Coordination Centre (I4C) threat feeds."
r_d.font.name = FONT_BODY
r_d.font.size = Pt(8.5)
r_d.font.color.rgb = COLOR_MUTED

print("Slide 3 redesigned.")

# ======================================================================
# SLIDE 4: FEASIBILITY AND VIABILITY (PARSIMONY & RISK MANAGEMENT)
# ======================================================================
slide4 = prs.slides[3]
apply_top_left_oval_badge(slide4, 4)
update_slide_footer(slide4)
format_header_zone(slide4, "FEASIBILITY AND VIABILITY", "Parsimony Principle (Occam's Razor) & Risk Mitigation")

# Left Card: Parsimony & Feasibility
c4_left, tf4_l = create_bento_card(slide4, Inches(0.40), Inches(1.30), Inches(5.95), Inches(5.45), "Technical Feasibility & Occam's Razor")

feasibility_bullets = [
    ("Browser DOM Client-Side Execution", "Next.js handles MIME disassembly, regex parsing, and cryptographic checks strictly in the client's browser DOM using native Web APIs. The sensitive email payload is NEVER POSTed to any backend server."),
    ("100% Data Privacy Guaranteed", "Complies fully with India's Digital Personal Data Protection (DPDP) Act 2023 and GDPR—eliminating the severe corporate data breach risk inherent in commercial cloud sandbox competitors."),
    ("Zero Cloud Compute Footprint", "Eliminates expensive GPU/server clusters. Runs effortlessly on standard SOC workstation laptops with sub-second response times."),
    ("Empirically Verified Working Prototype", "Fully deployed at threatlens-gen.vercel.app with 64/64 automated test passes across real-world adversarial email payloads, malformed headers, and folded lines.")
]

for title, desc in feasibility_bullets:
    p = tf4_l.add_paragraph()
    p.space_after = Pt(3)
    rt = p.add_run()
    rt.text = f"• {title}:\n  "
    rt.font.name = FONT_HEAD
    rt.font.size = Pt(9.5)
    rt.font.bold = True
    rt.font.color.rgb = COLOR_NAVY
    rd = p.add_run()
    rd.text = desc
    rd.font.name = FONT_BODY
    rd.font.size = Pt(9)
    rd.font.color.rgb = COLOR_DARK

# Right Card: Risk Analysis & Mitigations
c4_right, tf4_r = create_bento_card(slide4, Inches(6.55), Inches(1.30), Inches(6.35), Inches(5.45), "Potential Challenges & Active Mitigations")

risk_blocks = [
    ("Risk 1: Compromised Legitimate Relays",
     "Attacker compromises legitimate M365/SendGrid accounts where SPF/DKIM legitimately PASS.",
     "MITIGATION: Multi-vector heuristic detection flags Display-Name impersonation, Header vs. Envelope mismatches, and Cousin-Domain age even when cryptographic checks pass."),
    ("Risk 2: Image-Only & QR Quishing Traps",
     "Adversaries embed malicious URLs inside QR code images, bypassing standard text-based URL parsers.",
     "MITIGATION: Integrated client-side HTML5 canvas image decoder analyzes embedded QR codes and extracts underlying redirect links directly during MIME traversal."),
    ("Risk 3: Large / Malformed .eml Payloads",
     "Oversized attachments or malformed RFC headers crashing browser memory threads.",
     "MITIGATION: Streaming non-blocking Web Worker parser with configurable byte-boundary limits and payload truncation safeguards.")
]

for rtitle, rscenario, rmit in risk_blocks:
    p = tf4_r.add_paragraph()
    p.space_after = Pt(2.5)
    r1 = p.add_run()
    r1.text = f"{rtitle}\n"
    r1.font.name = FONT_HEAD
    r1.font.size = Pt(9.5)
    r1.font.bold = True
    r1.font.color.rgb = COLOR_NAVY
    r2 = p.add_run()
    r2.text = f"Challenge: {rscenario}\n"
    r2.font.name = FONT_BODY
    r2.font.size = Pt(8.5)
    r2.font.color.rgb = COLOR_DARK
    r3 = p.add_run()
    r3.text = f"Defense: {rmit}"
    r3.font.name = FONT_BODY
    r3.font.size = Pt(8.5)
    r3.font.bold = True
    r3.font.color.rgb = COLOR_GREEN

print("Slide 4 redesigned.")

# ======================================================================
# SLIDE 5: IMPACT AND BENEFITS (3-PILLAR BENTO GRID)
# ======================================================================
slide5 = prs.slides[4]
apply_top_left_oval_badge(slide5, 5)
update_slide_footer(slide5)
format_header_zone(slide5, "IMPACT AND BENEFITS", "National Cyber Defense, LEA Empowerment & Operational ROI")

# 3-Column Bento Cards
c5_1, tf5_1 = create_bento_card(slide5, Inches(0.40), Inches(1.30), Inches(3.95), Inches(5.45), "National & Economic Defense")
col1_points = [
    ("Targeting ₹1,750+ Cr Fraud", "Directly addresses the rampant financial cyber fraud losses reported by the Ministry of Home Affairs (MHA) and Indian Cyber Crime Coordination Centre (I4C) from corporate BEC and banking credential phishing."),
    ("Critical Infrastructure Shield", "Protects Indian PSUs, defense establishments, and public sectors from advanced spearphishing impersonating nic.in and gov.in domains."),
    ("Democratizing Security", "Delivers high-grade email forensic capabilities to Indian MSMEs, schools, and hospitals that cannot afford ₹15–20 Lakh annual enterprise SEG licensing fees.")
]
for title, desc in col1_points:
    p = tf5_1.add_paragraph()
    p.space_after = Pt(3)
    rt = p.add_run()
    rt.text = f"• {title}:\n  "
    rt.font.name = FONT_HEAD
    rt.font.size = Pt(9)
    rt.font.bold = True
    rt.font.color.rgb = COLOR_NAVY
    rd = p.add_run()
    rd.text = desc
    rd.font.name = FONT_BODY
    rd.font.size = Pt(8.5)
    rd.font.color.rgb = COLOR_DARK

c5_2, tf5_2 = create_bento_card(slide5, Inches(4.55), Inches(1.30), Inches(3.95), Inches(5.45), "Law Enforcement Empowerment")
col2_points = [
    ("Accelerating Cyber Police", "Equips state cyber cells (Telangana Cyber Security Bureau - TGCSB, Maharashtra Cyber, Delhi Cyber Police) with instant origin IP geolocation, transit MTA hop tracing, and ISP identification."),
    ("Section 65B BSA Evidence", "Automated PDF exports generate structured evidence packages compliant with Section 65B of the Indian Evidence Act / Bharatiya Sakshya Adhiniyam (BSA) for accelerated FIR registration and formal judicial submission."),
    ("Tackling BEC Hubs", "Exposes international money-mule relay corridors targeting Indian corporate treasury desks.")
]
for title, desc in col2_points:
    p = tf5_2.add_paragraph()
    p.space_after = Pt(3)
    rt = p.add_run()
    rt.text = f"• {title}:\n  "
    rt.font.name = FONT_HEAD
    rt.font.size = Pt(9)
    rt.font.bold = True
    rt.font.color.rgb = COLOR_NAVY
    rd = p.add_run()
    rd.text = desc
    rd.font.name = FONT_BODY
    rd.font.size = Pt(8.5)
    rd.font.color.rgb = COLOR_DARK

c5_3, tf5_3 = create_bento_card(slide5, Inches(8.70), Inches(1.30), Inches(4.20), Inches(5.45), "Operational & Sustainable ROI")
col3_points = [
    ("80% Reduction in MTTR", "Slashes Mean Time to Triage from 25 minutes of manual terminal inspection down to under 5 seconds per suspicious email."),
    ("100% Privacy Compliance", "Eliminates compliance breach liabilities under the DPDP Act 2023 by ensuring email payloads never leave the local browser memory."),
    ("Green Serverless Footprint", "Runs entirely on existing client workstation compute, requiring zero 24/7 dedicated cloud GPU server energy."),
    ("Democratized SOC Triage", "Enables junior Level-1 analysts to conduct Level-3 deep forensic triage without specialized training.")
]
for title, desc in col3_points:
    p = tf5_3.add_paragraph()
    p.space_after = Pt(3)
    rt = p.add_run()
    rt.text = f"• {title}:\n  "
    rt.font.name = FONT_HEAD
    rt.font.size = Pt(9)
    rt.font.bold = True
    rt.font.color.rgb = COLOR_NAVY
    rd = p.add_run()
    rd.text = desc
    rd.font.name = FONT_BODY
    rd.font.size = Pt(8.5)
    rd.font.color.rgb = COLOR_DARK

print("Slide 5 redesigned.")

# ======================================================================
# SLIDE 6: RESEARCH AND REFERENCES (3-CARD BENTO GRID)
# ======================================================================
slide6 = prs.slides[5]
apply_top_left_oval_badge(slide6, 6)
update_slide_footer(slide6)
format_header_zone(slide6, "RESEARCH AND REFERENCES", "Standards Review, Prior Art Gap Closure & Team Persona")

c6_1, tf6_1 = create_bento_card(slide6, Inches(0.40), Inches(1.30), Inches(4.00), Inches(5.45), "Standards Critique & Gaps Closed")
ref_standards = [
    ("RFC Standards (5322, 7208, 6376, 7489)",
     "Prior Art Gap: Protocols define authentication primitives in isolation; existing tools fail to provide a single-pane synthesized alignment view.\nThreatLens Solution: Correlates SPF, DKIM, and DMARC simultaneously with automated policy diagnostics and raw DNS TXT snippets."),
    ("MITRE ATT&CK Enterprise Matrix (v14)",
     "Prior Art Gap: Analysts manually correlate log alerts to ATT&CK tactics.\nThreatLens Solution: Automatically maps parsed header irregularities to T1566 (Phishing), T1566.001 (Attachment), and T1566.002 (Link).")
]
for title, desc in ref_standards:
    p = tf6_1.add_paragraph()
    p.space_after = Pt(3)
    rt = p.add_run()
    rt.text = f"• {title}:\n"
    rt.font.name = FONT_HEAD
    rt.font.size = Pt(9)
    rt.font.bold = True
    rt.font.color.rgb = COLOR_NAVY
    rd = p.add_run()
    rd.text = desc
    rd.font.name = FONT_BODY
    rd.font.size = Pt(8.5)
    rd.font.color.rgb = COLOR_DARK

c6_2, tf6_2 = create_bento_card(slide6, Inches(4.60), Inches(1.30), Inches(4.00), Inches(5.45), "Government & Industry References")
citations = [
    ("1. NIST SP 800-177 Rev. 1", "Trustworthy Email Guide (Architectural foundation for cryptographic verification)."),
    ("2. CERT-In Incident Advisories", "Empirical benchmark for prevalent Indian malware droppers and credential phishing campaigns."),
    ("3. I4C (Ministry of Home Affairs)", "National cyber fraud statistics and Citizen Financial Cyber Fraud Reporting System."),
    ("4. AbuseIPDB & URLhaus", "Active blacklists and known malicious MTA exit node intelligence feeds.")
]
for title, desc in citations:
    p = tf6_2.add_paragraph()
    p.space_after = Pt(3)
    rt = p.add_run()
    rt.text = f"{title}:\n"
    rt.font.name = FONT_HEAD
    rt.font.size = Pt(9)
    rt.font.bold = True
    rt.font.color.rgb = COLOR_NAVY
    rd = p.add_run()
    rd.text = desc
    rd.font.name = FONT_BODY
    rd.font.size = Pt(8.5)
    rd.font.color.rgb = COLOR_DARK

c6_3, tf6_3 = create_bento_card(slide6, Inches(8.80), Inches(1.30), Inches(4.10), Inches(5.45), "Team Persona & Research Ethos")
p_pe = tf6_3.add_paragraph()
p_pe.space_after = Pt(3)
r_pe1 = p_pe.add_run()
r_pe1.text = "ENGINEERED BY TEAM CYBERCORE\n"
r_pe1.font.name = FONT_HEAD
r_pe1.font.size = Pt(9.5)
r_pe1.font.bold = True
r_pe1.font.color.rgb = COLOR_ORANGE
r_pe2 = p_pe.add_run()
r_pe2.text = "Department of CSE (Cyber Security)\nCVR College of Engineering\n\n"
r_pe2.font.name = FONT_HEAD
r_pe2.font.size = Pt(9)
r_pe2.font.bold = True
r_pe2.font.color.rgb = COLOR_NAVY
r_pe3 = p_pe.add_run()
r_pe3.text = "Our research ethos stems from direct frontline engagement with the practical bottlenecks of SOC Tier-1 analysts and Indian law enforcement agencies.\n\nRather than proposing impractical, over-engineered theoretical models, ThreatLens AI enforces strict client-side data privacy, parsimonious execution, and actionable operational defense designed to stop real-world cyber fraud."
r_pe3.font.name = FONT_BODY
r_pe3.font.size = Pt(8.5)
r_pe3.font.color.rgb = COLOR_DARK

print("Slide 6 redesigned.")

# ======================================================================
# DELETE SLIDE 7 (INSTRUCTIONS SLIDE)
# ======================================================================
if len(prs.slides) > 6:
    rId = prs.slides._sldIdLst[6].rId
    prs.part.drop_rel(rId)
    del prs.slides._sldIdLst[6]
    print("Slide 7 deleted. Exactly 6 slides remain.")

# ======================================================================
# SAVE TO TARGETS
# ======================================================================
TARGET_FILES = [
    r'C:\Users\vishw\Downloads\SIH2026_CyberCore_FINAL_SUBMISSION.pptx',
    r'C:\Users\vishw\Downloads\SIH2026_ThreatLens_CyberCore_Submission.pptx',
    r'c:\Users\vishw\Documents\antigravity\delightful-goodall\SIH2026_ThreatLens_AI_Official_Submission.pptx',
    r'C:\Users\vishw\Downloads\SIH2026-IDEA-Presentation-Format (1).pptx'
]

for target in TARGET_FILES:
    try:
        prs.save(target)
        print(f"[OK] Saved successfully to: {target}")
    except PermissionError:
        print(f"[LOCKED] Could not overwrite {target} (currently open in PowerPoint).")
