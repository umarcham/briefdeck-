# ============================================================
# 🔹 Full Import and Configuration Section for Zoom + Google Calendar Integration
# ============================================================

# ------------------------------
# Standard Library
# ------------------------------
import base64
from collections import defaultdict
import os
import re
import json
import time
import uuid
import pytz
import secrets
import logging
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote
from flask import abort, send_from_directory
from flask_cors import CORS
from datetime import datetime, timezone
from google.cloud import firestore as gc_firestore
from sendgrid.helpers.mail import Mail


import logging
import threading
from datetime import datetime, timezone
from typing import Tuple, Optional


# ------------------------------
# Flask
# ------------------------------
from flask import (
    Flask,
    request,
    redirect,
    jsonify,
    session,
    render_template,
    send_from_directory,
    url_for
)


# ------------------------------
# Google API Clients
# ------------------------------
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request  # ✅ For token refresh
from google.cloud import firestore as gc_firestore  # only used for typing, actual db from firebase_admin
import google.auth.exceptions
from google.cloud import firestore as _gc_firestore

# ------------------------------
# Firebase Admin SDK
# ------------------------------
import firebase_admin
from firebase_admin import credentials, firestore, storage, auth
from firebase_admin import auth as firebase_auth
from firebase_admin import firestore as admin_firestore



# ------------------------------
# Environment & Networking
# ------------------------------
from dotenv import load_dotenv
import requests


# ------------------------------
# Media & AI Libraries
# ------------------------------
from moviepy import VideoFileClip   # 🎥 Video processing
from pydub import AudioSegment             # 🎵 Audio chunking
from groq import Groq                      # 🧠 Groq AI SDK


# ============================================================
# 🔧 Basic Logging & Env Setup
# ============================================================
logging.basicConfig(level=logging.DEBUG)
load_dotenv("aqa.env")  # Load environment variables from file


# ============================================================
# ⚙️ Flask App Initialization
# ============================================================
app = Flask(__name__, template_folder="pages", static_folder="assets")
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")
#CORS(app, resources={r"/api/*": {"origins": ["http://http://127.0.0.1:10000", "http://localhost:10000"]}})
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/assets/<path:filename>')
def assets_root(filename):
    return send_from_directory('assets', filename)

@app.route('/assets3/<path:filename>')
def assets3_root(filename):
    return send_from_directory('assets3', filename)


@app.route('/pages/<path:filename>')
def serve_pages(filename):
    return send_from_directory('pages', filename)

# 🧩 Ignore Socket.IO requests injected by Ngrok or browser extensions
@app.route("/socket.io/", methods=["GET", "POST", "OPTIONS"])
def socketio_stub():
    return ("", 200)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()}), 200


# ============================================================
# 🌍 OAuth + API Configurations
# ============================================================
CLIENT_SECRETS_FILE = os.environ.get("CLIENT_SECRETS_FILE", "credentials.json")

REDIRECT_URI = os.environ.get(
    "REDIRECT_URI",
    "https://nelda-grippelike-kaylee.ngrok-free.dev/oauth/callback"
)

FRONTEND_URL = os.environ.get(
    "FRONTEND_URL",
    "https://briefdeck.tech/pages/integrati.html"
)

WATCH_ADDRESS = os.environ.get(
    "WATCH_ADDRESS",
    "https://nelda-grippelike-kaylee.ngrok-free.dev/calendar_notify"
)

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/calendar.events.readonly",
    "https://www.googleapis.com/auth/calendar.readonly"
    ]
SCOPES_GMAIL = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.readonly"
]


CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# ============================================================
# 🤖 External APIs & Keys
# ============================================================

# 🧑‍💼 Attendee API
API_KEY = os.getenv("ATTENDEE_API_KEY")
BASE_URL = os.getenv("ATTENDEE_BASE_URL", "https://app.attendee.dev/api/v1")

# 💫 Gemini (Google Generative AI)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_URL = os.getenv("GEMINI_URL")

# ⚡️ Groq API
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# 🔊 Audio/Video Config
CHUNK_LENGTH_MS = 60 * 1000  # 1 min per chunk

# ============================================================
# 🔥 Firebase Initialization
# ============================================================


# ============================================================
# 🔹 Temporary Stores & Globals
# ============================================================
temp_store = {}       # For OAuth state mapping
bot_to_user_map = {}  # Maps bot IDs to users
LAST_BOT_EVENT_ID = None

@app.route("/")
def home_page():
    user_email = session.get("app_user_email")
    return render_template("index.html", user_email=user_email)

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("sign-in3.html")

@app.route("/about")
def about_page():
    user_email = session.get("app_user_email")
    return render_template("about.html", user_email=user_email)

@app.route("/privacy")
def privacy_page():
    return render_template("privacy.html")

@app.route("/terms-of-service")
def terms_page():
    return render_template("terms-of-service.html")

@app.route("/security")
def security_page():
    return render_template("security.html")

@app.route("/how-it-works")
def how_it_works_page():
    user_email = session.get("app_user_email")
    return render_template("how-it-works.html", user_email=user_email)

@app.route("/documentation")
def documentation_page():
    return render_template("documentation.html")

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    session["app_user_email"] = email
    logging.debug(f"User logged in: {email}")
    return redirect("/")




# ---------------------------
# Firebase Admin initialization (FIREBASE_KEY must be JSON string)
# ---------------------------
firebase_key_json = os.environ.get("FIREBASE_KEY")
if not firebase_key_json:
    raise Exception("FIREBASE_KEY not found in environment (must be service account JSON string)")


firebase_cred_dict = json.loads(firebase_key_json)
cred = credentials.Certificate(firebase_cred_dict)
firebase_admin.initialize_app(cred, {
    "storageBucket": os.getenv("STORAGE_BUCKET")
})
db = admin_firestore.client()
bucket = storage.bucket()
print("✅ Firebase initialized successfully!")


# temporary in-memory map for oauth state -> app user email (used during OAuth flow)
temp_store = {}

def extract_meeting_url(event: dict) -> str:
    # 1. Google Meet (new API)
    conf = event.get("conferenceData", {})
    entrypoints = conf.get("entryPoints", [])
    for ep in entrypoints:
        if ep.get("entryPointType") == "video" and ep.get("uri"):
            return ep["uri"]

    # 2. Old Google Meet field
    if event.get("hangoutLink"):
        return event["hangoutLink"]

    # 3. Zoom or others (if using description blob)
    description = event.get("description", "")
    if "https://" in description:
        # crude extraction
        url = description.split("https://")[1].split()[0]
        return "https://" + url

    return ""





EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or "").strip().lower()
    if not email or not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "invalid_email"}), 400

    # OPTIONAL: very simple rate-limit / abuse-control by IP (stateless best-effort)
    # ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # implement a more robust limit with redis or a DB if needed

    # dedupe: if already subscribed return 200 (or 409)
    coll = db.collection('prepilot_subscribers')
    q = coll.where('email', '==', email).limit(1).stream()
    if any(q):
        return jsonify({"ok": True, "message": "already_subscribed"}), 200

    # write
    try:
        doc = coll.document()
        doc.set({
            "email": email,
            "createdAt": datetime.utcnow()
        })
        return jsonify({"ok": True}), 201
    except Exception as e:
        app.logger.exception("Failed to write subscriber")
        return jsonify({"ok": False, "error": "server_error"}), 500
    



CONTACT_EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

@app.route('/contact', methods=['POST'])
def contact():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or "").strip()
    email = (data.get('email') or "").strip().lower()
    subject = (data.get('subject') or "").strip()
    message = (data.get('message') or "").strip()

    # --- Validation ---
    if not all([name, email, subject, message]):
        return jsonify({"ok": False, "error": "missing_fields"}), 400
    if not CONTACT_EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "invalid_email"}), 400

    coll = db.collection('contact_messages')

    try:
        doc = coll.document()
        doc.set({
            "name": name,
            "email": email,
            "subject": subject,
            "message": message,
            "createdAt": datetime.utcnow()
        })
        return jsonify({"ok": True}), 201

    except Exception as e:
        app.logger.exception("Failed to save contact message")
        return jsonify({"ok": False, "error": "server_error"}), 500


# ---------------------------
# Helper: build creds and refresh, persist updated tokens
# ---------------------------
def build_creds_and_refresh(user_email, token_data):
    if not token_data:
        raise ValueError("token_data missing")

    creds = Credentials(
        token=token_data.get("access_token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=SCOPES
    )

    # If expiry info exists, the Credentials object may set .expiry and .expired appropriately.
    # If expired and refresh_token present, refresh and persist.
    try:
        if creds and getattr(creds, "expired", False) and creds.refresh_token:
            try:
                creds.refresh(Request())
                db.collection("users").document(user_email).update({
                    "google_tokens.access_token": creds.token,
                    "google_tokens.expiry": creds.expiry.isoformat() if creds.expiry else None
                })
                logging.debug(f"♻️ Refreshed tokens for {user_email}")
            except Exception as e:
                logging.error(f"Failed to refresh credentials for {user_email}: {e}")
                raise
    except Exception:
        # In some cases `.expired` is not available; ignore and return creds
        pass

    return creds

# ---------------------------
# Create watch for user's calendar
# ---------------------------
def create_calendar_watch_for_user(user_email):
    user_ref = db.collection("users").document(user_email)
    user_doc = user_ref.get()
    if not user_doc.exists:
        raise ValueError("user not found")

    token_data = user_doc.to_dict().get("google_tokens", {})
    if not token_data:
        raise ValueError("no google tokens for user")

    creds = build_creds_and_refresh(user_email, token_data)
    service = build("calendar", "v3", credentials=creds)

    # if existing and not expired, reuse
    existing = user_doc.to_dict().get("calendar_watch", {})
    now_ms = int(time.time() * 1000)
    if existing and existing.get("expiration") and existing.get("expiration") > now_ms + (60 * 60 * 1000):
        logging.debug(f"Reusing existing watch for {user_email}")
        return existing

    channel_id = str(uuid.uuid4())
    channel_token = secrets.token_urlsafe(32)

    body = {
        "id": channel_id,
        "type": "web_hook",
        "address": WATCH_ADDRESS,
        "token": channel_token
    }

    try:
        resp = service.events().watch(calendarId="primary", body=body).execute()
        watch_info = {
            "channel_id": resp.get("id"),
            "resource_id": resp.get("resourceId"),
            "expiration": int(resp.get("expiration", 0)),
            "token": channel_token,
            "address": WATCH_ADDRESS,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        user_ref.update({"calendar_watch": watch_info})
        logging.debug(f"Created watch for {user_email}: {watch_info}")
        return watch_info
    except Exception as e:
        logging.error(f"Error creating watch for {user_email}: {e}")
        raise

# ---------------------------
# Stop a watch
# ---------------------------
def stop_calendar_watch(user_email):
    user_ref = db.collection("users").document(user_email)
    doc = user_ref.get().to_dict()
    watch = doc.get("calendar_watch")
    token_data = doc.get("google_tokens", {})
    if not watch:
        return

    creds = build_creds_and_refresh(user_email, token_data)
    service = build("calendar", "v3", credentials=creds)

    body = {"id": watch["channel_id"], "resourceId": watch["resource_id"]}
    try:
        service.channels().stop(body=body).execute()
        user_ref.update({"calendar_watch": firestore.DELETE_FIELD})
        logging.debug(f"Stopped watch for {user_email}")
    except Exception as e:
        logging.error(f"Failed to stop watch for {user_email}: {e}")

# ---------------------------
# Fetch changed events using syncToken if present
    
# ---------------------------
def fetch_changed_events_for_user(user_email):
    """
    Fetch changed events for a user using syncToken when available.
    Detect Zoom, Google Meet, and Teams links and return normalized meeting events.

    Returned event shape:
    {
        "userEmail": "...",
        "summary": "...",
        "start": "ISO DATETIME",
        "end": "ISO DATETIME",
        "meetingLink": "https://...",
        "platform": "zoom" | "google_meet" | "teams",
        "eventId": "...",
        "participants": [
            {"email": "...", "name": "..."},
            ...
        ]
    }
    """
    user_doc = db.collection("users").document(user_email).get()
    if not user_doc.exists:
        logging.warning(f"No Firestore doc for user: {user_email}")
        return []

    data = user_doc.to_dict() or {}
    token_data = data.get("google_tokens", {})
    watch = data.get("calendar_watch", {})

    try:
        creds = build_creds_and_refresh(user_email, token_data)
        service = build("calendar", "v3", credentials=creds)
    except Exception as e:
        logging.error(f"Failed to initialize Google Calendar API for {user_email}: {e}")
        return []

    params = {
        "calendarId": "primary",
        "singleEvents": True,
        "orderBy": "startTime",
        "maxResults": 2500
    }

    # Use incremental sync if available
    if watch.get("sync_token"):
        params["syncToken"] = watch["sync_token"]
    else:
        params["timeMin"] = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

    try:
        resp = service.events().list(**params).execute()
    except Exception as e:
        err_str = str(e)
        # If syncToken expired, full resync
        if "410" in err_str or "RESOURCE_GONE" in err_str:
            logging.info(f"syncToken invalid for {user_email}, doing full resync")
            db.collection("users").document(user_email).update({
                "calendar_watch.sync_token": firestore.DELETE_FIELD
            })
            params.pop("syncToken", None)
            params["timeMin"] = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            resp = service.events().list(**params).execute()
        else:
            logging.error(f"Error fetching events for {user_email}: {e}")
            return []

    events = resp.get("items", [])
    next_sync_token = resp.get("nextSyncToken")

    if next_sync_token:
        db.collection("users").document(user_email).update({
            "calendar_watch.sync_token": next_sync_token,
            "calendar_watch.last_checked": datetime.now(timezone.utc).isoformat()
        })

    # Meeting link patterns
    patterns = {
        "zoom": re.compile(r"https?://[\w.-]*zoom\.us/[^\s]+", re.IGNORECASE),
        "google_meet": re.compile(r"https?://meet\.google\.com/[^\s]+", re.IGNORECASE),
        "teams": re.compile(r"https?://(?:teams\.microsoft\.com|teams\.live\.com)/[^\s]+", re.IGNORECASE),
    }

    meeting_events = []
    processed_event_ids = data.get("processed_events", []) or []

    for ev in events:
        try:
            if ev.get("status") == "cancelled":
                continue

            found_link = None
            found_platform = None

            # Search meeting links in fields
            for field in ["location", "description", "summary", "hangoutLink"]:
                text = str(ev.get(field, "") or "")
                if not text:
                    continue
                for platform_name, pat in patterns.items():
                    match = pat.search(text)
                    if match:
                        found_link = match.group(0)
                        found_platform = platform_name
                        break
                if found_link:
                    break

            if not found_link:
                continue

            event_id = ev.get("id")
            if event_id in processed_event_ids:
                continue

            start = ev.get("start", {}).get("dateTime")
            end = ev.get("end", {}).get("dateTime")

            # ----------- Extract participants (organizer + attendees) -----------
            participants_list = []

            # Organizer
            organizer = ev.get("organizer") or {}
            org_email = organizer.get("email") if isinstance(organizer, dict) else None
            org_name = organizer.get("displayName") if isinstance(organizer, dict) else None
            if org_email:
                participants_list.append({
                    "email": org_email.strip().lower(),
                    "name": (org_name or "").strip()
                })

            # Attendees
            attendees = ev.get("attendees") or []
            if isinstance(attendees, list):
                for att in attendees:
                    if not att:
                        continue
                    if isinstance(att, dict):
                        email = att.get("email")
                        name = att.get("displayName") or att.get("display_name") or ""
                        if email:
                            participants_list.append({
                                "email": email.strip().lower(),
                                "name": (name or "").strip()
                            })
                    elif isinstance(att, str) and "@" in att:
                        participants_list.append({"email": att.strip().lower(), "name": ""})

            # Deduplicate by email (preserve order)
            unique = {}
            deduped_participants = []
            for p in participants_list:
                em = (p.get("email") or "").lower()
                if not em:
                    continue
                if em not in unique:
                    unique[em] = True
                    deduped_participants.append({
                        "email": em,
                        "name": p.get("name", "")
                    })

            # Remove self if desired
            # deduped_participants = [p for p in deduped_participants if p["email"] != user_email.lower()]

            meeting_event = {
                "userEmail": user_email,
                "summary": ev.get("summary", "Untitled"),
                "start": start,
                "end": end,
                "meetingLink": found_link,
                "platform": found_platform,
                "eventId": event_id,
                "participants": deduped_participants
            }

            meeting_events.append(meeting_event)
            processed_event_ids.append(event_id)

        except Exception as e:
            logging.warning(f"Failed to parse event for {user_email}: {e}")

    # persist processed event IDs
    try:
        db.collection("users").document(user_email).update({
            "processed_events": processed_event_ids
        })
    except Exception as e:
        logging.warning(f"Failed to persist processed_events for {user_email}: {e}")

    return meeting_events



# ---------------------------
# Handler: process discovered Zoom events
# (Adapt to your actual logic - this is a safe default)
# ---------------------------
bot_to_user_map = {}


# ---------------------------
# Webhook: /calendar_notify - handle Google push notifications
# ---------------------------
@app.route("/calendar_notify", methods=["POST"])
def calendar_notify():
    headers = request.headers
    channel_id = headers.get("X-Goog-Channel-ID")
    resource_id = headers.get("X-Goog-Resource-ID")
    resource_state = headers.get("X-Goog-Resource-State")
    channel_token = headers.get("X-Goog-Channel-Token")

    # find user doc by channel id
    users_q = db.collection("users").where("calendar_watch.channel_id", "==", channel_id).stream()
    user_docs = list(users_q)
    if not user_docs:
        logging.warning("No user found for channel id: %s", channel_id)
        return ("", 200)

    user_doc = user_docs[0]
    user_email = user_doc.id
    watch = user_doc.to_dict().get("calendar_watch", {})

    # token verification if you set one
    if watch.get("token") and channel_token != watch.get("token"):
        logging.warning("Channel token mismatch for %s", user_email)
        return ("", 401)

    logging.info("Calendar webhook notification for %s: state=%s, resourceId=%s", user_email, resource_state, resource_id)

    # only respond to change-like notifications
    if resource_state in ("exists", "update", "sync", "notified", "change"):
        try:
            meeting_events = fetch_changed_events_for_user(user_email)
            logging.info("fetch_changed_events_for_user returned %d meeting events for %s", len(meeting_events), user_email)

            for me in meeting_events:
                try:
                    # normalize minimal event shape expected by handlers
                    normalized_event = {
                        "id": me.get("eventId") or me.get("event_id") or me.get("id"),
                        "start_time": me.get("start") or me.get("start_time") or me.get("start_time_iso"),
                        "end_time": me.get("end") or me.get("end_time"),
                        "summary": me.get("summary") or me.get("title"),
                        "attendees": [
                            {"email": p.get("email"), "displayName": p.get("name") or p.get("displayName") or ""}
                            for p in (me.get("participants") or me.get("attendees") or [])
                        ],
                        # multiple common names for meeting link
                        "meetingLink": me.get("meetingLink") or me.get("hangoutLink") or me.get("location") or me.get("meeting_url"),
                        "platform": (me.get("platform") or "").lower(),
                        "raw_event": me.get("raw") or me
                    }
                    raw = normalized_event.get("raw_event") or normalized_event
                    join_url = extract_meeting_url(raw) or (
                     normalized_event.get("meetingLink")
                     or normalized_event.get("meeting_url")
                      or normalized_event.get("hangoutLink")
                     or normalized_event.get("location")
                      or ""
                    )
                    normalized_event["meeting_url"] = join_url
                    normalized_event["meetingLink"] = normalized_event.get("meetingLink") or join_url
                    logging.info("canonical join_url -> %r for event %s", join_url, normalized_event.get("id") or "<no-id>")

                    eid = normalized_event.get("id") or "<no-id>"
                    logging.debug("Processing event id=%s start=%s link=%s", eid, normalized_event.get("start_time"), normalized_event.get("meetingLink"))

                    # --- Refresh user doc so processed_events is up-to-date ---
                    try:
                        user_doc = db.collection("users").document(user_email).get()
                        user_data = user_doc.to_dict() if user_doc.exists else {}
                        processed_list = user_data.get("processed_events", []) or []
                        processed_times = user_data.get("processed_event_times", {}) or {}
                    except Exception:
                        processed_list = []
                        processed_times = {}

                    # DEBUG: force reprocess for dev troubleshooting
                    # Set to True temporarily if you want to re-run handlers for every event
                    FORCE_REPROCESS = True

                    # Decide whether to skip: only skip if event processed recently (cooldown)
                    skip_this = False
                    if not FORCE_REPROCESS and eid in processed_list:
                        ts = processed_times.get(eid)
                        if ts:
                            try:
                                from datetime import datetime, timezone, timedelta
                                proc_dt = datetime.fromisoformat(ts)
                                # cooldown window: 2 hours (adjust as needed)
                                if proc_dt > datetime.now(timezone.utc) - timedelta(hours=2):
                                    skip_this = True
                                else:
                                    # old timestamp — allow reprocessing (and cleanup timestamp below if desired)
                                    skip_this = False
                            except Exception:
                                # paranoid: if timestamp parsing fails, skip
                                skip_this = True
                        else:
                            # Old-style processed_list entry without timestamp -> treat as processed (skip)
                            skip_this = True

                    if skip_this:
                        logging.info("Skipping already-processed event %s for %s (within cooldown)", eid, user_email)
                        continue

                    # Build zoom-ready event shape (the shape handle_zoom_events likely expects)
                    zoom_ready_event = {
    "userEmail": user_email,  # handle_zoom_events needs this
    "googleAccount": user_email,  # optional alias
    "meetingLink": normalized_event.get("meetingLink")
        or normalized_event.get("meeting_url")
        or normalized_event.get("hangoutLink")
        or normalized_event.get("location"),
    "zoomLink": normalized_event.get("meetingLink"),  # alias for backward compat
    "platform": normalized_event.get("platform") or "google_meet",
    "summary": normalized_event.get("summary") or normalized_event.get("title"),
    "start": normalized_event.get("start_time") or normalized_event.get("start") or normalized_event.get("start_time_iso"),
    "end": normalized_event.get("end_time") or normalized_event.get("end"),
    "eventId": normalized_event.get("id") or normalized_event.get("eventId"),
    "participants": [
        {"email": p.get("email"), "name": p.get("displayName") or p.get("name") or ""}
        for p in (normalized_event.get("attendees") or [])
    ]
}

                    # 1) If event looks like it has a meeting link / external platform — call handle_zoom_events
                    if zoom_ready_event.get("meeting_url") or zoom_ready_event.get("platform") in ("zoom", "google_meet", "meet"):
                        logging.info("Calling handle_zoom_events for event %s (link detected)", eid)
                        logging.debug("Calling handle_zoom_events with payload: %s", zoom_ready_event)

                        try:
                            # adapt if your function expects a single dict instead of list
                            handle_zoom_events([zoom_ready_event])
                        except Exception as e:
                            logging.exception("handle_zoom_events failed for %s: %s", eid, e)

                    # 2) Call handle_new_calendar_event for email / prebrief extraction (if attendees exist)
                    if normalized_event.get("attendees"):
                        logging.info("Calling handle_new_calendar_event for event %s (email/prebrief)", eid)
                        try:
                            handle_new_calendar_event(user_email, normalized_event)
                        except Exception as e:
                            logging.exception("handle_new_calendar_event failed for %s: %s", eid, e)
                    else:
                        logging.debug("No attendees for event %s — skipping prebrief extraction", eid)

                    # 3) mark event processed (so subsequent notifications don't re-run both handlers)
                    try:
                        from datetime import datetime, timezone
                        now_iso = datetime.now(timezone.utc).isoformat()
                        # Try atomic ArrayUnion update + timestamp map if available
                        try:
                            db.collection("users").document(user_email).update({
                                "processed_events": _gc_firestore.ArrayUnion([eid]),
                                f"processed_event_times.{eid}": now_iso
                            })
                        except Exception:
                            # fallback naive approach: read-modify-write
                            ud = db.collection("users").document(user_email)
                            current = ud.get().to_dict().get("processed_events", []) or []
                            if eid not in current:
                                current.append(eid)
                                ud.update({"processed_events": current, "processed_event_times": {**(ud.get().to_dict().get("processed_event_times", {}) or {}), eid: now_iso}})
                        logging.info("Marked event %s as processed for %s", eid, user_email)
                    except Exception:
                        logging.exception("Failed to record processed event %s for %s", eid, user_email)

                except Exception as e:
                    logging.exception("Failed to process meeting_event %s: %s", me.get("eventId") or me.get("id"), e)
        except Exception as e:
            logging.exception("Error in calendar_notify processing for %s: %s", user_email, e)

    return ("", 200)



# assume `db`, GEMINI_URL, GEMINI_API_KEY, verify_and_get_email_from_token are already available

def save_summary_to_firebase(user_email, connection_email, bot_id, summary_text):
    """
    Save plain text executive summary into Summaries collection (adds a doc).
    Also keep a convenience 'latest' document containing structured fields
    when available (set by enhance_with_gemini).
    """
    try:
        col = (db.collection("users").document(user_email)
                 .collection("Connections").document(connection_email)
                 .collection("Bots").document(bot_id)
                 .collection("Summaries"))
        col.add({
            "summary_text": summary_text,
            "created_at": firestore.SERVER_TIMESTAMP
        })
        logging.info("✅ Summary saved successfully for %s (%s) - Bot ID: %s", user_email, connection_email, bot_id)
    except Exception as e:
        logging.exception("❌ Error saving summary: %s", e)


def _extract_json_from_text1(text):
    """
    Try to find the first JSON object/array in text and return parsed JSON.
    Returns None on failure.
    """
    if not text:
        return None

    # 1) try direct JSON parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # 2) regex find {...} or [...]
    m = re.search(r'(\{(?:.|\n)*\}|\[(?:.|\n)*\])', text)
    if not m:
        return None

    candidate = m.group(1)

    # 3) attempt to balance braces if needed (trim trailing garbage)
    # Try progressively shorter tails until parse succeeds.
    for end in range(len(candidate), 0, -1):
        try:
            return json.loads(candidate[:end])
        except Exception:
            continue

    return None


def _save_followups(user_email, connection_email, bot_id, followups):
    """
    Persist followups into Firestore under:
    users/{user_email}/Connections/{connection_email}/Bots/{bot_id}/FollowUps
    Each follow-up becomes a document (adds created_at).
    """
    try:
        if not followups:
            return
        col_ref = (db.collection("users").document(user_email)
                     .collection("Connections").document(connection_email)
                     .collection("Bots").document(bot_id).collection("FollowUps"))
        count = 0
        for fu in followups:
            if not isinstance(fu, dict):
                fu = {"text": str(fu)}
            clean = {k: (v if v is not None else "") for k, v in fu.items()}
            clean["created_at"] = firestore.SERVER_TIMESTAMP
            col_ref.add(clean)
            count += 1
        logging.info("Saved %d followups for %s/%s/%s", count, user_email, connection_email, bot_id)
    except Exception as e:
        logging.exception("Failed saving followups: %s", e)


@app.route("/meeting_detail", methods=["GET"])
def meeting_detail():
    auth_header = request.headers.get("Authorization", "") or request.args.get("id_token", "")
    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1] if auth_header.startswith("Bearer ") else auth_header
    user_email = verify_and_get_email_from_token(id_token)
    if not user_email:
        return jsonify({"error": "Invalid token"}), 401

    bot_id = request.args.get("bot_id")
    connection = request.args.get("connection")
    if not bot_id or not connection:
        return jsonify({"error": "bot_id and connection required"}), 400

    try:
        user_ref = db.collection("users").document(user_email)
        conn_ref = user_ref.collection("Connections").document(connection)
        bot_ref = conn_ref.collection("Bots").document(bot_id)

        if not bot_ref.get().exists:
            return jsonify({"error": "bot not found"}), 404

        bot_doc = bot_ref.get().to_dict() or {}

        # latest summary (pick most recent doc; prefer structured 'latest' if present)
        summaries = list(bot_ref.collection("Summaries")
                         .order_by("created_at", direction=firestore.Query.DESCENDING)
                         .limit(1).stream())
        exec_summary = None
        key_highlights = []
        follow_ups = []
        raw_summary_text = None

        if summaries:
            sd = summaries[0].to_dict() or {}
            raw_summary_text = sd.get("summary_text") or sd.get("summary")
            # If raw summary is actually JSON, try parsing structured content
            parsed = None
            try:
                parsed = _extract_json_from_text1(raw_summary_text) if isinstance(raw_summary_text, str) else None
            except Exception:
                parsed = None

            if parsed and isinstance(parsed, dict):
                exec_summary = parsed.get("executive_summary") or parsed.get("summary") or None
                key_highlights = parsed.get("key_highlights") or parsed.get("highlights") or []
                follow_ups = parsed.get("follow_ups") or parsed.get("followUps") or []
            else:
                # if you also wrote a 'latest' doc with structured fields, prefer that
                latest_doc = bot_ref.collection("Summaries").document("latest").get()
                if latest_doc.exists:
                    ld = latest_doc.to_dict() or {}
                    exec_summary = ld.get("summary_text") or ld.get("executive_summary") or exec_summary
                    key_highlights = ld.get("key_highlights") or key_highlights
                    # don't try to read the FollowUps subcollection here; leave follow_ups for separate query
                    follow_ups = ld.get("follow_ups") or follow_ups

        # latest recording
        recordings = list(bot_ref.collection("Recordings")
                          .order_by("created_at", direction=firestore.Query.DESCENDING)
                          .limit(1).stream())
        recording = None
        if recordings:
            rec = recordings[0].to_dict() or {}
            recording = {
                "video_url": rec.get("video_url") or rec.get("videoUrl"),
                "audio_url": rec.get("audio_url") or rec.get("audioUrl") or rec.get("recording_url"),
                "transcript_url": rec.get("transcript_url") or rec.get("transcriptUrl"),
                "transcript_turns": rec.get("transcript_turns") or rec.get("transcript") or rec.get("transcript_turns_raw"),
                "duration_seconds": rec.get("duration"),
            }

        return jsonify({
            "bot_doc": bot_doc,
            "recording": recording,
            "executive_summary": exec_summary,
            "key_highlights": key_highlights,
            "follow_ups": follow_ups,
            "summary_text": raw_summary_text
        }), 200

    except Exception as e:
        logging.exception("meeting_detail error")
        return jsonify({"error": str(e)}), 500


def enhance_with_gemini(text: str, user_email: str, connection_email: str, bot_id: str) -> str:
    """
    Use Gemini to summarize text, parse structured JSON if present, save plain summary + structured fields.
    Returns executive_summary (string) for backward compatibility.
    """
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": f"""
You are a meeting intelligence assistant. Analyze the meeting transcript and return structured insights.

Transcript:
\"\"\"
{text}
\"\"\"

Return only valid JSON in this format:

{{
  "executive_summary": "1 short paragraph summarizing key points",
  "key_highlights": ["Short bullet points (3–6 total)"],
  "follow_ups": [
    {{
      "text": "Actionable next step (max 20 words)",
      "owner": "Optional person responsible",
      "due_date": "Optional ISO 8601 date if mentioned",
      "priority": "high | medium | low",
      "context": "Optional topic where this came from"
    }}
  ]
}}

Rules:
- Skip generic statements or greetings.
- Do not include markdown or text outside JSON.
- Limit follow_ups to 6 maximum.
"""
                    }
                ]
            }
        ]
    }

    try:
        res = requests.post(GEMINI_URL, headers=headers, params={"key": GEMINI_API_KEY}, json=payload, timeout=60)
        res.raise_for_status()
        data = res.json()

        # defensive extraction of assistant text
        text_out = None
        try:
            text_out = data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            try:
                text_out = json.dumps(data)
            except Exception:
                text_out = str(data)

        # Try to parse structured JSON out of response text
        parsed = _extract_json_from_text1(text_out)

        executive_summary = None
        key_highlights = []
        follow_ups = []

        if parsed and isinstance(parsed, dict):
            executive_summary = parsed.get("executive_summary") or parsed.get("summary") or None

            # normalize highlights
            highlights = parsed.get("key_highlights") or parsed.get("highlights") or []
            if isinstance(highlights, str):
                key_highlights = [h.strip() for h in highlights.splitlines() if h.strip()]
            elif isinstance(highlights, list):
                key_highlights = [str(h).strip() for h in highlights if str(h).strip()]

            # normalize followups
            fups = parsed.get("follow_ups") or parsed.get("followUps") or parsed.get("followups") or []
            if isinstance(fups, dict):
                follow_ups = [fups]
            elif isinstance(fups, list):
                follow_ups = [fu if isinstance(fu, dict) else {"text": str(fu)} for fu in fups]
            else:
                follow_ups = []
        else:
            # fallback: treat whole assistant output as plain executive summary
            executive_summary = (text_out or "").strip()

        # ensure non-empty executive text
        if not executive_summary:
            executive_summary = "Summary not available."

        # 1) save plain summary (existing behaviour)
        try:
            save_summary_to_firebase(user_email, connection_email, bot_id, executive_summary)
        except Exception:
            logging.exception("Failed to save plain summary to Summaries subcollection.")

        # 2) save structured 'latest' doc for easy reads by frontend
        try:
            latest_ref = (db.collection("users").document(user_email)
                            .collection("Connections").document(connection_email)
                            .collection("Bots").document(bot_id)
                            .collection("Summaries").document("latest"))

            latest_ref.set({
                "summary_text": executive_summary,
                "executive_summary": executive_summary,
                "key_highlights": key_highlights,
                "follow_ups": follow_ups,
                "updated_at": firestore.SERVER_TIMESTAMP
            }, merge=True)
        except Exception:
            logging.exception("Failed to save structured latest summary.")

        # 3) persist follow-ups into their collection (if present)
        try:
            if follow_ups:
                _save_followups(user_email, connection_email, bot_id, follow_ups)
        except Exception:
            logging.exception("Failed saving followups to subcollection.")

        # 4) keep lightweight summary on Bot doc for quick list views
        try:
            bot_ref = (db.collection("users").document(user_email)
                        .collection("Connections").document(connection_email)
                        .collection("Bots").document(bot_id))
            bot_ref.set({
                "last_executive_summary": executive_summary,
                "last_key_highlights": key_highlights,
                "last_followups_count": len(follow_ups),
                "last_summary_at": firestore.SERVER_TIMESTAMP
            }, merge=True)
        except Exception:
            logging.exception("Failed to update Bot doc with structured summary.")

        logging.info("✅ Gemini summary generated and saved for %s", user_email)
        return executive_summary

    except Exception as e:
        logging.exception("❌ Gemini summarization error")
        err = f"❌ Gemini summarization error: {str(e)}"
        try:
            save_summary_to_firebase(user_email, connection_email, bot_id, err)
        except Exception:
            pass
        return err


def save_bot_details(user_email, connection_email, calendar_id, bot_id, bot_data):
    """
    Save bot metadata (meeting details) + participants to Firestore:
    users/{user}/Connections/{connection}/Bots/{bot_id}
    """

    if not (user_email and connection_email and bot_id):
        print(f"[ERROR] save_bot_details: Missing required keys (user_email={user_email}, connection_email={connection_email}, bot_id={bot_id})")
        return

    # --- Normalize title/start_time ---
    extra_fields = {}
    if bot_data.get("summary"):
        extra_fields["title"] = bot_data["summary"]
    elif bot_data.get("title"):
        extra_fields["title"] = bot_data["title"]

    if bot_data.get("start"):
        extra_fields["start_time"] = bot_data["start"]
    elif bot_data.get("start_time"):
        extra_fields["start_time"] = bot_data["start_time"]

    # --- Normalize and deduplicate participants ---
    participants_data = []
    seen_emails = set()

    if isinstance(bot_data.get("participants"), list):
        for p in bot_data["participants"]:
            try:
                if isinstance(p, dict):
                    email = str(p.get("email", "")).strip().lower()
                    name = str(p.get("name", "")).strip()
                    if email and email not in seen_emails:
                        seen_emails.add(email)
                        participants_data.append({"email": email, "name": name})
                elif isinstance(p, str) and "@" in p:
                    email = p.strip().lower()
                    if email not in seen_emails:
                        seen_emails.add(email)
                        participants_data.append({"email": email, "name": ""})
            except Exception as e:
                print(f"[WARN] Failed to parse participant {p}: {e}")

    # --- Build final Firestore payload ---
    bot_doc = {
        **bot_data,
        **extra_fields,
        "calendar_id": calendar_id,
        "created_at": firestore.SERVER_TIMESTAMP,
    }

    if participants_data:
        bot_doc["participants"] = participants_data

    # --- Firestore write ---
    try:
        db.collection("users").document(user_email) \
            .collection("Connections").document(connection_email) \
            .collection("Bots").document(bot_id).set(bot_doc, merge=True)

        print(f"✅ Bot {bot_id} saved successfully "
              f"({len(participants_data)} participants, title='{extra_fields.get('title', '')}')")

    except Exception as e:
        print(f"❌ Failed to save bot {bot_id} for {user_email}: {e}")



def create_bot_for_meeting(user_email, connection_email, calendar_id, meeting_url,
                           deduplication_key=None, join_at_iso=None, calendar_event_id=None,
                           title=None, start_time=None, participants=None):
    """
    Create a bot on Attendee. Ensures all metadata values are strings.
    If participants is provided (list/dict), it will be JSON-stringified before sending.
    """
    global LAST_BOT_EVENT_ID

    deduplication_key = deduplication_key or f"bot-{int(time.time())}"

    # --- Prepare metadata ensuring all values are strings ---
    metadata = {
        "title": str(title or ""),
        "start_time": str(start_time or "")
    }

    # If participants passed, stringify them (JSON) so Attendee accepts it
    if participants:
        try:
            # If participants is already a list/dict, json.dumps -> string
            # If it's a string, keep as-is
            if isinstance(participants, (list, dict)):
                metadata["participants"] = json.dumps(participants, ensure_ascii=False)
            else:
                metadata["participants"] = str(participants)
        except Exception as ex:
            print(f"[WARN] Failed to stringify participants, storing simple string: {ex}")
            metadata["participants"] = str(participants)

    bot_payload = {
        "bot_name": "Briefdeck bot",
        "meeting_url": meeting_url,
        "deduplication_key": deduplication_key,
        "webhooks": [
            {
                "url": "https://nelda-grippelike-kaylee.ngrok-free.dev/attendee-webhook",
                "triggers": ["bot.state_change", "async_transcription.state_change", "participant_events.join_leave"]
            }
        ],
        "metadata": metadata
    }

    if join_at_iso:
        bot_payload["join_at"] = join_at_iso

    headers = {
        "Authorization": f"Token {API_KEY}",
        "Content-Type": "application/json"
    }

    # Debug: log payload so you can see exactly what's being sent
    try:
        print("DEBUG: Attendee bot payload:", json.dumps(bot_payload, indent=2, ensure_ascii=False))
    except Exception:
        print("DEBUG: Attendee bot payload (non-serializable)")

    try:
        res = requests.post(f"{BASE_URL}/bots", headers=headers, json=bot_payload, timeout=30)
        res.raise_for_status()
        bot_data = res.json()
        bot_id = bot_data.get("id")
        state = bot_data.get("state") or bot_data.get("status") or "created"
        print(f"✅ Bot created successfully: {bot_id} (state={state}) join_at={join_at_iso}")

        LAST_BOT_EVENT_ID = deduplication_key

        # Persist bot details to Firestore
        try:
            save_bot_details(user_email, connection_email, calendar_id, bot_id, {
                "meeting_url": meeting_url,
                "deduplication_key": deduplication_key,
                "status": state,
                "join_at": join_at_iso,
                "calendar_event_id": calendar_event_id,
                "recording_url": None,
                "title": title,
                "start_time": start_time,
                # store participants as a structured field in Firestore too (not required by Attendee),
                # Firestore can accept lists/dicts so we store the original object here:
                "participants": participants if participants else []
            })
        except Exception as e:
            print(f"[WARN] Failed to persist bot details to Firestore: {e}")

        # map for webhook mapping
        bot_to_user_map[bot_id] = {
            "user_email": user_email,
            "connection_email": connection_email,
            "calendar_event_id": calendar_event_id
        }

        return bot_id

    except requests.HTTPError as he:
        try:
            body = he.response.json()
        except Exception:
            body = he.response.text if he.response is not None else str(he)
        print(f"❌ Bot creation failed (HTTP {getattr(he.response, 'status_code', '')}) body={body}")
    except requests.RequestException as re:
        print(f"❌ Bot creation failed (RequestException): {re}")
    except Exception as e:
        print(f"❌ Bot creation failed (unexpected): {e}")

    return None







def handle_recording(bot_id, user_email, connection_email):
    try:
        print(f"🎥 Fetching recording for bot: {bot_id}")
        url = f"{BASE_URL}/bots/{bot_id}/recording"
        headers = {"Authorization": f"Token {API_KEY}"}

        res = requests.get(url, headers=headers)
        if res.status_code != 200:
            print("❌ Failed:", res.status_code, res.text)
            return

        video_url = res.json().get("url")
        print(f"✅ Recording URL: {video_url}")

        video_path = f"meeting_{bot_id}.mp4"
        audio_path = f"audio_{bot_id}.wav"
        chunks_dir = f"audio_chunks_{bot_id}"

        # Download video
        with open(video_path, "wb") as f:
            f.write(requests.get(video_url).content)

        # Extract audio
        video = VideoFileClip(video_path)
        video.audio.write_audiofile(audio_path)
        duration = video.duration
        video.close()

        # Split audio into chunks
        audio = AudioSegment.from_wav(audio_path)
        os.makedirs(chunks_dir, exist_ok=True)
        chunk_files = []

        for i, start in enumerate(range(0, len(audio), CHUNK_LENGTH_MS)):
            end = min(start + CHUNK_LENGTH_MS, len(audio))
            chunk = audio[start:end].set_channels(1).set_frame_rate(16000)
            chunk_path = os.path.join(chunks_dir, f"chunk_{i}.wav")
            chunk.export(chunk_path, format="wav", bitrate="64k")
            chunk_files.append(chunk_path)

        print(f"✅ Created {len(chunk_files)} chunks.")

        # Transcribe with Groq Whisper
        client = Groq(api_key=GROQ_API_KEY)
        final_text = ""
        for path in chunk_files:
            try:
                with open(path, "rb") as f:
                    tr = client.audio.transcriptions.create(
                        file=f,
                        model="whisper-large-v3-turbo",
                        response_format="verbose_json",
                        language="en",
                    )
                    text = " ".join([s.get("text", "") for s in tr.segments])
                    final_text += text + " "
            except Exception as e:
                print(f"⚠️ Failed chunk {path}: {e}")

        # Save locally
        transcript_path = f"meeting_transcript_{bot_id}.txt"
        summary_path = f"meeting_summary_{bot_id}.txt"

        with open(transcript_path, "w") as f:
            f.write(final_text.strip())

        # ✅ FIXED argument order for enhance_with_gemini
        summary = enhance_with_gemini(final_text, user_email, connection_email, bot_id)

        with open(summary_path, "w") as f:
            f.write(summary)

        print("\n📄 Summary:\n", summary)

        # --- 🔥 Firebase Upload Section ---
       # cred = credentials.Certificate("serviceAccountKey.json")
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred, {
                "storageBucket": "teachly-ca5ed.firebasestorage.app"
            })

        db = admin_firestore.client()
        bucket = storage.bucket()

        def upload_to_firebase(local_path, cloud_path):
            blob = bucket.blob(cloud_path)
            blob.upload_from_filename(local_path)
            blob.make_public()
            return blob.public_url

        # Firebase Storage path
        folder = f"users/{user_email}/Connections/{connection_email}/Bots/{bot_id}/Recording/"

        video_url_firebase = upload_to_firebase(video_path, folder + "video.mp4")
        audio_url_firebase = upload_to_firebase(audio_path, folder + "audio.wav")
        transcript_url = upload_to_firebase(transcript_path, folder + "transcript.txt")
        summary_url = upload_to_firebase(summary_path, folder + "summary.txt")

        # ✅ Firestore Recordings subcollection
        recording_ref = (
            db.collection("users")
            .document(user_email)
            .collection("Connections")
            .document(connection_email)
            .collection("Bots")
            .document(bot_id)
            .collection("Recordings")
            .document()
        )

        recording_ref.set({
            "bot_id": bot_id,
            "created_at": firestore.SERVER_TIMESTAMP,
            "duration": duration,
            "video_url": video_url_firebase,
            "audio_url": audio_url_firebase,
            "transcript_url": transcript_url,
            "summary_url": summary_url,
            "summary_text": summary,
        })

        print("✅ Uploaded all files to Firebase successfully!")

        # Cleanup
        os.remove(video_path)
        os.remove(audio_path)
        for f in chunk_files:
            os.remove(f)
        os.rmdir(chunks_dir)
        os.remove(transcript_path)
        os.remove(summary_path)

    except Exception as e:
        print("⚠️ Error handling recording:", e)

# ---------------- FLASK ROUTES ----------------
@app.route("/")
def home():
    return "Google Calendar Connector → <a href='/authorize'>Connect your Google Calendar</a>"


# global mapping
bot_to_user_map = {}  # Make sure this is updated when creating bots

@app.route('/attendee-webhook', methods=['POST'])
def attendee_webhook():
    data = request.get_json()
    bot_data = data.get('data', {})
    event = data.get('trigger') or data.get('event_type') or data.get('event')

    print(f"\n⚡ Webhook received: {event}")
    print(json.dumps(data, indent=2))

    bot_id = data.get('bot_id')

    # ✅ Get emails from mapping instead of relying on webhook (may be missing)
    email_info = bot_to_user_map.get(bot_id, {})
    user_email = email_info.get('user_email')
    connection_email = email_info.get('connection_email')
    print(user_email)
    print(connection_email)

    if event == 'bot.state_change':
        new_state = bot_data.get('new_state')
        old_state = bot_data.get('old_state')
        event_type = bot_data.get('event_type')
        print(f"🔁 Bot state: {old_state} → {new_state} ({event_type})")

        if new_state == 'joined_recording':
            print("🎥 Bot started recording...")
        elif new_state == 'post_processing':
            print("🌀 Meeting ended, post-processing in progress...")
        elif new_state == 'ended':
            print("✅ Bot meeting ended completely.")
            event_meta = bot_data.get('event_metadata', {})
            if 'transcription_errors' in event_meta:
                print(f"⚠️ Transcription errors: {event_meta['transcription_errors']}")
            if bot_id:
                print("📌 Starting recording processing...")
                threading.Thread(target=handle_recording, args=(bot_id, user_email, connection_email)).start()

    elif event == 'recording.completed':
        recording_url = bot_data.get('recording', {}).get('url')
        if recording_url:
            print(f"🎬 Recording available: {recording_url}")

    elif event == 'post_processing_completed':
        print("✅ Meeting post-processing completed (recording ready soon).")
        if bot_id:
            print("📌 Starting recording processing...")
            threading.Thread(target=handle_recording, args=(bot_id, user_email, connection_email)).start()

    else:
        print(f"⚠️ Unknown or unhandled event: {event}")

    return jsonify({'status': 'ok'}), 200





# /authorize endpoint
@app.route("/authorize", methods=["GET"])
def authorize():
    id_token = request.args.get("token")  # optional - if using firebase id token auth
    app_user_email = None

    # If using Firebase ID token to identify app user, verify and extract email:
    if id_token:
        try:
            decoded_token = auth.verify_id_token(id_token)
            app_user_email = decoded_token.get("email")
        except Exception as e:
            return f"Invalid Firebase token: {e}", 401
    else:
        # fallback to session or query param
        app_user_email = session.get("app_user_email") or request.args.get("email")
        if not app_user_email:
            return "No app user provided", 400

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes= [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/calendar.events.readonly",
    "https://www.googleapis.com/auth/calendar.readonly"
    ]
,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="false",
        prompt="select_account consent"
    )

    temp_store[state] = app_user_email
    return redirect(auth_url)


@app.route("/oauth/callback")
def oauth_callback():
    state = request.args.get("state")
    code = request.args.get("code")
    if not code or not state:
        return "Missing code or state", 400

    app_user_email = temp_store.get(state)
    if not app_user_email:
        return "Error: No app user found for this OAuth flow", 400

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=[
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/calendar.events.readonly",
    "https://www.googleapis.com/auth/calendar.readonly"
    ]
,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(code=code)
    credentials = flow.credentials

    # get connected google account email
    import requests as _requests
    headers = {"Authorization": f"Bearer {credentials.token}"}
    resp = _requests.get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json", headers=headers)
    resp.raise_for_status()
    google_email = resp.json().get("email")

    # persist tokens to Firestore
    user_ref = db.collection("users").document(app_user_email)
    user_ref.set({
        "google_tokens": {
            "access_token": credentials.token,
            "refresh_token": getattr(credentials, "refresh_token", None),
            "expiry": credentials.expiry.isoformat() if credentials.expiry else None,
            "google_email": google_email
        }
    }, merge=True)
    logging.debug(f"Saved Google credentials for user {app_user_email} (google_email={google_email})")

    # create calendar watch immediately (best-effort)
    try:
        create_calendar_watch_for_user(app_user_email)
    except Exception as e:
        logging.error("Failed to create calendar watch right after OAuth: %s", e)

    return redirect(FRONTEND_URL + f"?connected_google={google_email}")   


@app.route("/check-google-connection", methods=["GET"])
def check_google_connection():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    id_token = auth_header.split("Bearer ")[1]
    try:
        decoded_token = auth.verify_id_token(id_token)
        user_email = decoded_token["email"]

        user_doc = db.collection("users").document(user_email).get()
        user_data = user_doc.to_dict() if user_doc.exists else {}
        is_connected = "google_tokens" in user_data

        return jsonify({"connected": is_connected})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# ---------------- FETCH EVENTS ----------------
def fetch_zoom_events_for_user(google_email, token_data):
    try:
        creds = Credentials.from_authorized_user_info(token_data, SCOPES)
        service = build("calendar", "v3", credentials=creds)

        events = []
        page_token = None
        # Include events that started slightly before now to catch ongoing meetings
        time_min = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat() + "Z"

        while True:
            events_result = service.events().list(
                calendarId="primary",
                maxResults=2500,  # fetch as many as possible per page
                singleEvents=True,
                orderBy="startTime",
                timeMin=time_min,
                pageToken=page_token,
            ).execute()
            events.extend(events_result.get("items", []))
            page_token = events_result.get("nextPageToken")
            if not page_token:
                break

        zoom_events = []
        user_ref = db.collection("users").document(google_email)
        processed_events = user_ref.get().to_dict().get("processed_events", [])

        for ev in events:
            # Detect Zoom link
            location = ev.get("location", "")
            description = ev.get("description", "")
            summary = ev.get("summary", "")
            zoom_link = None

            for field in [location, description, summary, ev.get("hangoutLink", "")]:
                if "zoom.us/j/" in field:
                    zoom_link = field
                    break

            if not zoom_link:
                continue  # skip non-Zoom events

            event_id = ev.get("id")
            if event_id in processed_events:
                continue  # skip already processed events

            # Convert start/end to user's timezone
            start = ev.get("start", {}).get("dateTime")
            end = ev.get("end", {}).get("dateTime")
            tz = ev.get("start", {}).get("timeZone", "UTC")
            start_dt = datetime.fromisoformat(start).astimezone(pytz.timezone(tz)) if start else None
            end_dt = datetime.fromisoformat(end).astimezone(pytz.timezone(tz)) if end else None

            zoom_event_data = {
                "user": google_email,
                "summary": summary,
                "start": start_dt.isoformat() if start_dt else None,
                "end": end_dt.isoformat() if end_dt else None,
                "zoomLink": zoom_link
            }

            # Handle only unprocessed events
            handle_zoom_events([zoom_event_data])
            zoom_events.append(zoom_event_data)

            # Mark event as processed
            processed_events.append(event_id)

        # Update Firestore with processed events
        user_ref.update({"processed_events": processed_events})

        return zoom_events

    except Exception as e:
        print(f"Error fetching events for {google_email}: {e}")
        return []
    




@app.route("/debug_my_paths", methods=["GET"])
def debug_my_paths():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split("Bearer ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        logging.exception("verify_id_token failed")
        return jsonify({"error": "Invalid token", "detail": str(e)}), 401

    email = decoded.get("email")
    uid = decoded.get("uid")
    if not email and not uid:
        return jsonify({"error": "No email/uid in token"}), 400

    result = {"token_email": email, "token_uid": uid, "user_doc_candidates_checked": [], "found_connections": []}
    # 1. try email as doc id
    def check_user_doc(doc_id):
        info = {"doc_id": doc_id, "exists": False, "subcollections": [], "connections_count": 0}
        doc_ref = db.collection("users").document(doc_id)
        doc = doc_ref.get()
        info["exists"] = doc.exists
        if not doc.exists:
            return info
        # list subcollections under that doc
        try:
            colls = list(doc_ref.collections())
            info["subcollections"] = [c.id for c in colls]
            # if Connections exists, list connection docs
            if "Connections" in info["subcollections"]:
                con_docs = list(doc_ref.collection("Connections").stream())
                info["connections_count"] = len(con_docs)
                info["connections"] = [c.id for c in con_docs]
        except Exception as e:
            info["error_listing"] = str(e)
        return info

    # check email, uid, and also a common encoded form (replace '.' with ',') if you use encoded ids
    candidates = []
    if email:
        candidates.append(email)
        # common encoding variations (if you used encode)
        candidates.append(email.replace(".", "%2E"))
        candidates.append(email.replace(".", ","))
    if uid:
        candidates.append(uid)

    checked = []
    for c in candidates:
        if not c: continue
        info = check_user_doc(c)
        checked.append(info)
        if info["exists"]:
            result["found_user_doc"] = c
            result["user_doc_info"] = info
            break

    result["user_doc_candidates_checked"] = checked

    # If none found, try a query search for a user document where email == token email
    if "found_user_doc" not in result and email:
        try:
            q = db.collection("users").where("email", "==", email).limit(5).stream()
            hits = [d.id for d in q]
            result["queried_by_email_hits"] = hits
        except Exception as e:
            result["query_error"] = str(e)

    return jsonify(result), 200




# temp debug route - returns connections and bot ids for the current user
@app.route("/debug_list_connections", methods=["GET"])
def debug_list_connections():
    try:
        # token->uid/email code you already have in meetings_with_summaries
        id_token = request.headers.get("Authorization", "").split("Bearer ")[-1]
        if not id_token:
            return jsonify({"error": "missing auth"}), 401
        uid_email = verify_and_get_email_from_token(id_token)  # reuse your existing helper
        if not uid_email:
            return jsonify({"error": "invalid token"}), 401

        user_ref = db.collection("users").document(uid_email)
        if not user_ref.get().exists:
            return jsonify({"error": "no user doc"}), 404

        out = {"user": uid_email, "connections": []}

        conns = list(user_ref.collection("Connections").stream())
        for c in conns:
            conn_id = c.id
            bots = [b.id for b in c.reference.collection("Bots").stream()]
            out["connections"].append({"connection_id": conn_id, "bots": bots})
        return jsonify(out), 200
    except Exception as e:
        logging.exception("debug_list_connections err")
        return jsonify({"error": str(e)}), 500




def _iso_if_ts(val):
    """Return iso string if val is timestamp-like, else val as-is or None."""
    if not val:
        return None
    # Firestore python timestamps are often datetime
    if isinstance(val, datetime):
        return val.astimezone(timezone.utc).isoformat()
    return str(val)

def _infer_platform(bot_doc_dict):
    """Try to infer platform from bot data/meeting_url"""
    if not bot_doc_dict:
        return None
    url = (bot_doc_dict.get("meeting_url") or "").lower()
    if "zoom.us" in url or "zoom.us" in bot_doc_dict.get("platform", "").lower():
        return "zoom"
    if "meet.google" in url or "google_meet" in bot_doc_dict.get("platform", "").lower():
        return "google_meet"
    if "teams.live" in url or "microsoft" in url or "teams" in bot_doc_dict.get("platform", "").lower():
        return "teams"
    return bot_doc_dict.get("platform") or "unknown"

def verify_and_get_email_from_token(id_token):
    """Replace with your actual token verification. This example assumes Firebase Admin."""
    # Example using firebase_admin:
    # from firebase_admin import auth
    # decoded = auth.verify_id_token(id_token)
    # return decoded.get("email")
    # --- PLACEHOLDER: adapt to your project ---
    try:
        from firebase_admin import auth
        decoded = auth.verify_id_token(id_token)
        return decoded.get("email")
    except Exception as e:
        logging.exception("token verify failed")
        return None
    









from urllib.parse import unquote
from flask import request, jsonify
import logging

@app.route("/meetings_with_summaries", methods=["GET"])
def meetings_with_summaries():
    logging.info("meetings_with_summaries: start")
    auth_header = request.headers.get("Authorization", "") or request.args.get("id_token", "")
    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 401

    id_token = auth_header.split(" ", 1)[1] if auth_header.startswith("Bearer ") else auth_header
    user_email = verify_and_get_email_from_token(id_token)
    if not user_email:
        logging.info("meetings_with_summaries: invalid token or no email")
        return jsonify({"error": "Invalid token"}), 401

    logging.info("meetings_with_summaries: user=%s", user_email)

    # Optional: allow client to request all summaries per bot (default: only latest)
    return_all_summaries = bool(request.args.get("all_summaries", "") in ("1", "true", "yes"))

    try:
        user_ref = db.collection("users").document(user_email)
        if not user_ref.get().exists:
            logging.info("user doc missing: users/%s", user_email)
            return jsonify({"meetings": []}), 200

        meetings_by_key = {}  # dedupe: key -> meeting dict (we'll use bot_id or bot_id:summary_id)
        connections = list(user_ref.collection("Connections").list_documents())
        logging.info("found %d connection docs for %s", len(connections), user_email)

        for conn_doc in connections:
            conn_id = conn_doc.id
            bots_col = user_ref.collection("Connections").document(conn_id).collection("Bots")

            for bot_doc_snapshot in bots_col.stream():
                try:
                    bot_id = bot_doc_snapshot.id
                    bot_data = bot_doc_snapshot.to_dict() or {}

                    # --- fetch most recent recording (if any) ---
                    duration_minutes = None
                    duration_seconds_raw = None
                    audio_url = None
                    summary_url = None
                    try:
                        recs_q = bots_col.document(bot_id).collection("Recordings") \
                            .order_by("created_at", direction=firestore.Query.DESCENDING) \
                            .limit(1).stream()
                        recs = list(recs_q)
                        if recs:
                            rec_data = recs[0].to_dict() or {}
                            raw_duration = rec_data.get("duration")
                            if isinstance(raw_duration, (int, float)):
                                duration_seconds_raw = float(raw_duration)
                                duration_minutes = round(duration_seconds_raw / 60.0, 2)
                            audio_url = rec_data.get("audio_url") or rec_data.get("audioUrl")
                            summary_url = rec_data.get("summary_url") or rec_data.get("summaryUrl")
                    except Exception as rexc:
                        logging.debug("couldn't read recordings for %s/%s: %s", conn_id, bot_id, rexc)

                    # --- summaries ---
                    summaries_col = bots_col.document(bot_id).collection("Summaries")

                    if return_all_summaries:
                        # legacy behavior: return every summary doc (but still avoid duplicates)
                        summaries_iter = summaries_col.order_by("created_at", direction=firestore.Query.DESCENDING).stream()
                    else:
                        # prefer only the latest summary per bot to avoid duplicates/cost
                        summaries_iter = summaries_col.order_by("created_at", direction=firestore.Query.DESCENDING).limit(1).stream()

                    for s in summaries_iter:
                        sdata = s.to_dict() or {}
                        text = (sdata.get("summary_text") or
                                sdata.get("summary") or
                                sdata.get("summaryText") or "") or ""
                        if not text.strip():
                            continue

                        start_iso = (bot_data.get("start_time") or
                                     bot_data.get("start") or
                                     sdata.get("created_at") or
                                     sdata.get("createdAt"))

                        raw_title = (bot_data.get("title") or
                                     bot_data.get("meeting_title") or
                                     bot_data.get("meetingTitle"))
                        if not raw_title:
                            first_line = (text.strip().splitlines()[0] if text.strip() else "")[:200]
                            raw_title = first_line or None

                        # Decode email safely in Python
                        try:
                            person = unquote(conn_id)
                        except Exception:
                            person = conn_id

                        meeting = {
                            "bot_id": bot_id,
                            "connection": conn_id,
                            "person": person,
                            "summary_id": s.id,
                            "summary_text": text,
                            "created_at": _iso_if_ts(sdata.get("created_at") or sdata.get("createdAt")),
                            "meeting_url": bot_data.get("meeting_url") or bot_data.get("meetingUrl"),
                            "title": raw_title,
                            "start": _iso_if_ts(start_iso),
                            "start_time": bot_data.get("start_time"),
                            "duration": duration_minutes,
                            "duration_seconds_raw": duration_seconds_raw,
                            "audio_url": audio_url,
                            "summary_url": summary_url,
                            "platform": _infer_platform(bot_data),
                        }

                        # dedupe key — default keep only one entry per bot (latest)
                        if return_all_summaries:
                            dedupe_key = f"{bot_id}:{s.id}"
                        else:
                            dedupe_key = f"{bot_id}"

                        # store if not present, or if this one appears newer
                        existing = meetings_by_key.get(dedupe_key)
                        if not existing:
                            meetings_by_key[dedupe_key] = meeting
                        else:
                            # try to prefer the most recent created_at (ISO compare is ok if _iso_if_ts returns ISO)
                            try:
                                existing_ts = existing.get("created_at")
                                new_ts = meeting.get("created_at")
                                if new_ts and existing_ts and new_ts > existing_ts:
                                    meetings_by_key[dedupe_key] = meeting
                            except Exception:
                                pass

                        # if we intentionally only wanted latest-per-bot, there is no reason to loop more
                        if not return_all_summaries:
                            break

                except Exception as be:
                    logging.exception("error reading bot %s under connection %s", bot_doc_snapshot.id, conn_id)

        # Build list and sort descending by created_at (newest first)
        meetings = list(meetings_by_key.values())
        meetings.sort(key=lambda m: m.get("created_at") or "", reverse=True)

        logging.info("returning %d meetings for %s", len(meetings), user_email)
        return jsonify({"meetings": meetings}), 200

    except Exception as e:
        logging.exception("error reading Firestore for meetings_with_summaries")
        return jsonify({"error": str(e)}), 500




@app.route("/bot_recording_details", methods=["GET"])
def bot_recording_details():
    auth_header = request.headers.get("Authorization", "") or request.args.get("id_token", "")
    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1] if auth_header.startswith("Bearer ") else auth_header

    user_email = verify_and_get_email_from_token(id_token)
    if not user_email:
        return jsonify({"error": "Invalid token"}), 401

    connection = request.args.get("connection")
    bot_id = request.args.get("bot_id")
    if not connection or not bot_id:
        return jsonify({"error": "Missing bot_id or connection"}), 400

    try:
        recs_ref = db.collection("users").document(user_email) \
            .collection("Connections").document(connection) \
            .collection("Bots").document(bot_id) \
            .collection("Recordings")

        recs = list(recs_ref.order_by("created_at", direction=firestore.Query.DESCENDING).limit(1).stream())
        if not recs:
            return jsonify({"error": "No recording found"}), 404

        data = recs[0].to_dict()
        if not data:
            return jsonify({"error": "Empty recording data"}), 404

        duration_sec = data.get("duration")
        duration_min = round(duration_sec / 60, 2) if isinstance(duration_sec, (int, float)) else None

        result = {
            "audio_url": data.get("audio_url"),
            "summary_text": data.get("summary_text"),
            "duration_seconds": duration_sec,
            "duration_minutes": duration_min,
            "created_at": _iso_if_ts(data.get("created_at")),
            "bot_id": bot_id,
            "connection": connection,
        }
        return jsonify(result), 200

    except Exception as e:
        logging.exception("Error fetching bot recording details")
        return jsonify({"error": str(e)}), 500




def handle_zoom_events(events):
    for e in events:
        user_email = e.get("userEmail")
        connection_email = e.get("googleAccount") or user_email
        meeting_url = e.get("meetingLink") or e.get("zoomLink")
        platform = e.get("platform", "zoom")
        summary = e.get("summary", "No Title")
        start_time = e.get("start")
        calendar_id = "primary"

        # participants should be provided by fetch_changed_events_for_user
        participants = e.get("participants", []) or []
        # normalize to list of {"email": "...", "name": "..."}
        if not isinstance(participants, list):
            participants = []

        if not meeting_url or not user_email:
            print(f"[ERROR] Missing required fields in event: {e}")
            continue

        # calculate join_at (set to meeting start time)
        join_at_iso = None
        try:
            if start_time:
                start_dt = datetime.fromisoformat(start_time)
                if start_dt.tzinfo is None:
                    start_dt = start_dt.replace(tzinfo=timezone.utc)

                join_dt = start_dt
                now_utc = datetime.now(timezone.utc)

                # schedule only if join_dt is sufficiently in the future
                if (join_dt - now_utc).total_seconds() > 30:
                    join_at_iso = (
                        join_dt.astimezone(timezone.utc)
                        .replace(microsecond=0)
                        .isoformat()
                        .replace("+00:00", "Z")
                    )
                else:
                    # if meeting is near or in the past, request join immediately
                    join_at_iso = None
        except Exception as err:
            print(f"[WARN] Failed to parse event start time for {summary}: {err}")
            join_at_iso = None

        print(f"[BOT] Scheduling {platform.upper()} bot for {user_email}: {summary}")
        print(f"      Start: {start_time} | Join At: {join_at_iso or 'Now'} | Link: {meeting_url}")

        try:
            dedup_key = f"{user_email}-{int(time.time())}"

            # IMPORTANT: pass title=summary (and participants) to keep field names consistent
            creation_result = create_bot_for_meeting(
                user_email=user_email,
                connection_email=connection_email,
                calendar_id=calendar_id,
                meeting_url=meeting_url,
                deduplication_key=dedup_key,
                join_at_iso=join_at_iso,
                calendar_event_id=e.get("eventId") or e.get("id"),
                title=summary,            # keep using "title"
                start_time=start_time,
                participants=e.get("participants") # NEW: pass participants list to create function
            )

            # Normalize result for older behavior where function returned bot_id directly
            status = None
            created_bot_id = None
            scheduled_id = None

            if isinstance(creation_result, dict):
                status = creation_result.get("status")
                created_bot_id = creation_result.get("bot_id")
                scheduled_id = creation_result.get("scheduled_id")
            elif isinstance(creation_result, str):
                # legacy behavior: string bot id
                status = "created"
                created_bot_id = creation_result
            elif creation_result:
                # any truthy non-dict value treat as created id
                try:
                    created_bot_id = str(creation_result)
                    status = "created"
                except Exception:
                    status = None

            if status == "scheduled":
                print(f"⏳ Bot creation scheduled (scheduled_id={scheduled_id}) for {summary}")
                # persist mapping for scheduled job so you can create it later (optional)
                try:
                    db.collection("users").document(user_email) \
                        .collection("Connections").document(connection_email) \
                        .collection("BotsScheduled").document(scheduled_id) \
                        .set({
                            "deduplication_key": dedup_key,
                            "meeting_url": meeting_url,
                            "title": summary,
                            "start_time": start_time,
                            "join_at": join_at_iso,
                            "calendar_event_id": e.get("eventId") or e.get("id"),
                            "platform": platform,
                            "participants": participants,   # NEW: persist participants for scheduled bots
                            "created_at": firestore.SERVER_TIMESTAMP,
                            "status": "scheduled"
                        }, merge=True)
                except Exception as ex:
                    logging.exception("failed to persist scheduled bot mapping: %s", ex)

            elif status == "created" and created_bot_id:
                print(f"✅ Bot created for {summary} [ID: {created_bot_id}]")

                # Save mapping for webhook tracking
                bot_to_user_map[created_bot_id] = {
                    "user_email": user_email,
                    "connection_email": connection_email,
                    "summary": summary,
                    "platform": platform,
                    "join_at": join_at_iso,
                    "meeting_url": meeting_url,
                }

                # Ensure participants are saved on the Bot document (create_bot_for_meeting may already do this;
                # we call save_bot_details as a safe merge to make sure participants exist).
                try:
                    save_bot_details(user_email, connection_email, calendar_id, created_bot_id, {
                        "meeting_url": meeting_url,
                        "deduplication_key": dedup_key,
                        "status": "created",
                        "join_at": join_at_iso,
                        "calendar_event_id": e.get("eventId") or e.get("id"),
                        "recording_url": None,
                        "title": summary,
                        "start_time": start_time,
                        "participants": participants  # NEW: store participants under bot doc
                    })
                except Exception as ex:
                    logging.exception("Failed to persist participants to bot doc: %s", ex)

            else:
                print(f"❌ Failed to create/schedule bot for {summary} ({platform}, {user_email}) - result={creation_result}")

        except Exception as e:
            print(f"[ERROR] Exception while creating bot for {platform} ({user_email}): {e}")

# ====== AUTHORIZE GMAIL ======
@app.route("/authorize_gmail", methods=["GET"])
def authorize_gmail():
    id_token = request.args.get("token")
    app_user_email = None

    # Verify Firebase user
    if id_token:
        try:
            decoded = firebase_auth.verify_id_token(id_token)
            app_user_email = decoded.get("email")
            app.logger.debug("authorize_gmail: decoded Firebase token for %s", app_user_email)
        except Exception as e:
            app.logger.exception("authorize_gmail: invalid Firebase token")
            return f"Invalid Firebase ID token: {e}", 401

    if not app_user_email:
        app_user_email = session.get("app_user_email") or request.args.get("email")
    if not app_user_email:
        return "No app user provided", 400

    redirect_uri_gmail = "https://nelda-grippelike-kaylee.ngrok-free.dev/oauth/callback_gmail"

    # Gmail-only scopes
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/gmail.readonly"
        ],
        redirect_uri=redirect_uri_gmail
    )

    # 🚨 Important difference:
    # include_granted_scopes="false" + prompt="consent"
    # => new consent screen, no scope mixing
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="false",
        prompt="consent"
    )

    temp_store[state] = app_user_email
    app.logger.debug("authorize_gmail: created new Gmail flow for %s", app_user_email)
    return redirect(auth_url)


@app.route("/oauth/callback_gmail")
def oauth_callback_gmail():
    state = request.args.get("state")
    code = request.args.get("code")
    if not code or not state:
        return "Missing code or state", 400

    app_user_email = temp_store.get(state)
    if not app_user_email:
        return "Error: OAuth state mismatch", 400

    redirect_uri_gmail = "https://nelda-grippelike-kaylee.ngrok-free.dev/oauth/callback_gmail"

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/gmail.readonly"
        ],
        state=state,
        redirect_uri=redirect_uri_gmail
    )

    try:
        flow.fetch_token(code=code)
    except Exception as e:
        app.logger.exception("oauth_callback_gmail: token exchange failed")
        return f"Token exchange failed: {e}", 400

    credentials = flow.credentials

    # Fetch user email from token
    import requests as _requests
    google_email = None
    try:
        headers = {"Authorization": f"Bearer {credentials.token}"}
        resp = _requests.get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json", headers=headers, timeout=10)
        resp.raise_for_status()
        google_email = resp.json().get("email")
    except Exception as e:
        app.logger.warning("oauth_callback_gmail: userinfo fetch failed: %s", e)

    db.collection("users").document(app_user_email).set({
        "gmail_tokens": {
            "access_token": credentials.token,
            "refresh_token": getattr(credentials, "refresh_token", None),
            "expiry": credentials.expiry.isoformat() if credentials.expiry else None,
            "google_email": google_email
        }
    }, merge=True)

    frontend = os.environ.get("FRONTEND_URL", FRONTEND_URL)
    return redirect(frontend + f"?connected_gmail={google_email or app_user_email}")


@app.route("/check-gmail-connection", methods=["GET"])
def check_gmail_connection():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    id_token = auth_header.split("Bearer ")[1]
    try:
        decoded = auth.verify_id_token(id_token)
        user_email = decoded.get("email")
        if not user_email:
            return jsonify({"error": "Missing user email in token"}), 400

        user_doc = db.collection("users").document(user_email).get()
        user_data = user_doc.to_dict() if user_doc.exists else {}

        gmail_connected = "gmail_tokens" in user_data and bool(user_data.get("gmail_tokens", {}).get("access_token"))
        calendar_connected = "google_tokens" in user_data and bool(user_data.get("google_tokens", {}).get("access_token"))

        return jsonify({
            "gmail_connected": gmail_connected,
            "calendar_connected": calendar_connected
        }), 200

    except Exception as e:
        logging.exception("check_gmail_connection failed")
        return jsonify({"error": str(e)}), 500



DOCS_PATH = os.path.join(os.path.dirname(__file__), "briefdeck_docs.txt")

try:
    with open(DOCS_PATH, "r", encoding="utf-8") as f:
        KNOWLEDGE_BASE = f.read()
        print(f"[INFO] Loaded knowledge base from {DOCS_PATH} ({len(KNOWLEDGE_BASE)} chars)")
except Exception as e:
    KNOWLEDGE_BASE = ""
    print(f"[WARN] Could not load briefdeck_docs.txt: {e}")

# -------------------------------------------------
SYSTEM_PROMPT = (
    "You are the Briefdeck AI Assistant. Be concise, friendly, and answer using the "
    "documentation context provided below. If unsure, say so and suggest where in the docs to look."
)

conversations = {}  # session_id -> [{"role":"user"|"assistant", "content":"..."}]

@app.post("/api/chat")
def chat_gemini():
    data = request.get_json(force=True, silent=True) or {}
    message = (data.get("message") or "").strip()
    session_id = (data.get("session_id") or "anon").strip()[:100]

    if not message:
        return jsonify({"error": "message required"}), 400

    history = conversations.setdefault(session_id, [])
    history.append({"role": "user", "content": message})

    # 🧠 Combine prompt + loaded knowledge base
    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Documentation Knowledge Base:\n{KNOWLEDGE_BASE}\n\n"
        f"User question: {message}"
    )

    payload = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1024},
    }

    try:
        res = requests.post(
            GEMINI_URL,
            params={"key": GEMINI_API_KEY},
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )

        if res.status_code != 200:
            print("Gemini Error:", res.text)
            return jsonify({"error": f"Gemini {res.status_code}: {res.text}"}), res.status_code

        data = res.json()
        reply = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )

        if not reply.strip():
            reply = "Sorry, I didn’t get a response from Gemini."

    except Exception as e:
        print("Gemini Exception:", e)
        reply = f"Error contacting Gemini: {e}"

    history.append({"role": "assistant", "content": reply})
    return jsonify({"reply": reply})










# Put these imports near the top of your Flask app file
import base64
import logging
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from flask import request, jsonify
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# -----------------------
# Helper: extract plain/text from Gmail message resource (full/raw)
# -----------------------
def _extract_body_from_message(msg: Dict[str, Any]) -> str:
    """
    Extract a readable text excerpt from a Gmail message resource.
    Accepts format='full' or 'raw' style resource.
    """
    # Try payload.parts (most common when format='full')
    try:
        payload = msg.get("payload", {})
        # If single part with body => payload['body']['data']
        if payload:
            # If body at payload level
            main_body = payload.get("body", {}).get("data")
            if main_body:
                try:
                    txt = base64.urlsafe_b64decode(main_body + "==").decode("utf-8", errors="ignore")
                    return txt.strip()
                except Exception:
                    pass

            parts = payload.get("parts") or []
            # walk parts to find text/plain; fallback to text/html
            text_candidate = None
            html_candidate = None
            for part in parts:
                mime = part.get("mimeType", "")
                body = part.get("body", {}).get("data")
                if not body:
                    # nested parts (multipart/alternative)
                    nested = part.get("parts") or []
                    for np in nested:
                        if np.get("mimeType") == "text/plain" and np.get("body", {}).get("data"):
                            try:
                                return base64.urlsafe_b64decode(np["body"]["data"] + "==").decode("utf-8", errors="ignore").strip()
                            except Exception:
                                continue
                else:
                    try:
                        decoded = base64.urlsafe_b64decode(body + "==").decode("utf-8", errors="ignore")
                    except Exception:
                        decoded = ""
                    if mime == "text/plain" and decoded:
                        return decoded.strip()
                    if mime == "text/html" and decoded:
                        html_candidate = decoded

            # fallback: convert html_candidate -> naive text (strip tags)
            if html_candidate:
                # quick naive conversion: remove tags
                import re
                text = re.sub("<[^<]+?>", " ", html_candidate)
                text = " ".join(text.split())
                return text.strip()
    except Exception as e:
        logging.debug("body extraction (payload) failed: %s", e)

    # If message resource provided as 'raw'
    try:
        raw = msg.get("raw")
        if raw:
            rb = base64.urlsafe_b64decode(raw + "==")
            from email import message_from_bytes
            em = message_from_bytes(rb)
            # prefer text/plain part
            if em.is_multipart():
                for part in em.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            return part.get_payload(decode=True).decode(part.get_content_charset("utf-8"), errors="ignore").strip()
                        except Exception:
                            continue
                # html fallback
                for part in em.walk():
                    if part.get_content_type() == "text/html":
                        try:
                            html = part.get_payload(decode=True).decode(part.get_content_charset("utf-8"), errors="ignore")
                            import re
                            text = re.sub("<[^<]+?>", " ", html)
                            return " ".join(text.split()).strip()
                        except Exception:
                            continue
            else:
                payload = em.get_payload(decode=True)
                if payload:
                    return payload.decode(em.get_content_charset("utf-8"), errors="ignore").strip()
    except Exception as e:
        logging.debug("body extraction (raw) failed: %s", e)

    return ""


# -----------------------
# Core: fetch messages between two addresses using Gmail API
# -----------------------
def fetch_emails_between(creds, from_email: str, to_email: str, max_results: int = 10, days: int = 90) -> List[Dict[str, Any]]:
    """
    Returns list of messages (subject, snippet, body_excerpt, date) between two addresses.
    creds: google.auth.credentials.Credentials (authorized for Gmail)
    """
    try:
        service = build("gmail", "v1", credentials=creds)
        # Query that covers both directions
        query = f"(from:{from_email} AND to:{to_email}) OR (from:{to_email} AND to:{from_email}) newer_than:{days}d"
        logging.debug("Gmail query: %s", query)
        results = []

        # list messages (may return None)
        resp = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
        msg_refs = resp.get("messages", []) or []

        for ref in msg_refs:
            try:
                m = service.users().messages().get(userId="me", id=ref["id"], format="full").execute()
                # headers
                headers = {h["name"].lower(): h["value"] for h in (m.get("payload", {}).get("headers") or [])}
                subject = headers.get("subject", "")
                date_hdr = headers.get("date", "")
                snippet = m.get("snippet", "") or ""
                body = _extract_body_from_message(m)
                if body and len(body) > 1000:
                    body_excerpt = body[:1000] + "..."
                else:
                    body_excerpt = body

                results.append({
                    "id": ref.get("id"),
                    "subject": subject,
                    "snippet": snippet,
                    "body_excerpt": body_excerpt,
                    "date_header": date_hdr
                })
            except HttpError as he:
                logging.warning("Gmail message fetch failed id=%s: %s", ref.get("id"), he)
            except Exception as e:
                logging.exception("Unexpected error fetching message %s: %s", ref.get("id"), e)

        return results
    except HttpError as he:
        logging.exception("Gmail list failed: %s", he)
        return []
    except Exception as e:
        logging.exception("Gmail fetch failed: %s", e)
        return []


# -----------------------
# Flask route: test endpoint to call above function (paste into your app)
# -----------------------
@app.route("/generate_prebrief_from_gmail", methods=["POST"])
def generate_prebrief_from_gmail():
    """
    Request JSON:
    {
      "user_email": "owner@example.com",           # optional if Firebase token provided
      "title": "Meeting Title",
      "start_time": "2025-10-28T15:00:00Z",       # optional
      "participants": [
         {"email":"alice@example.com","name":"Alice"},
         "bob@example.com",
         ...
      ],
      "max_emails_per_participant": 5,             # optional
      "days": 90                                   # optional time window
    }

    Auth: Prefer Authorization: Bearer <firebase_id_token>
    """
    try:
        payload = request.get_json(force=True) or {}
    except Exception:
        payload = {}

    # auth: try firebase id token first (if you already verify elsewhere, adapt)
    auth_header = request.headers.get("Authorization", "") or ""
    user_email = None
    if auth_header.startswith("Bearer "):
        id_token = auth_header.split("Bearer ", 1)[1]
        try:
            decoded = firebase_auth.verify_id_token(id_token)
            user_email = decoded.get("email")
        except Exception:
            # ignore here; fallback to body
            pass

    user_email = user_email or payload.get("user_email")
    participants = payload.get("participants", []) or []
    meeting_title = payload.get("title", "Untitled Meeting")
    meeting_start = payload.get("start_time")
    max_per = int(payload.get("max_emails_per_participant", 5))
    days = int(payload.get("days", 90))

    if not user_email:
        return jsonify({"error": "Missing user authentication (user_email). Provide Firebase ID token or user_email in body."}), 401
    if not participants or not isinstance(participants, list):
        return jsonify({"error": "Missing participants list"}), 400

    # normalize participants -> list of dicts {email,name}
    normalized = []
    for p in participants:
        if isinstance(p, str):
            normalized.append({"email": p.strip().lower(), "name": ""})
        elif isinstance(p, dict):
            if p.get("email"):
                normalized.append({"email": str(p.get("email")).strip().lower(), "name": p.get("name") or ""})
    if len(normalized) == 0:
        return jsonify({"error": "No valid participant emails"}), 400

    # load gmail tokens for user
    user_doc = db.collection("users").document(user_email).get()
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404
    user_data = user_doc.to_dict() or {}
    token_data = user_data.get("gmail_tokens", {})
    if not token_data:
        return jsonify({"error": "No gmail_tokens stored for this user"}), 400

    # build creds (auto-refreshing)
    try:
        creds = build_creds_and_refresh1(user_email, token_data)
    except Exception as e:
        logging.exception("Failed to build Gmail credentials")
        return jsonify({"error": "Failed to build Gmail credentials"}), 500

    # Step A: gather emails between user and each participant
    combined_entries = []
    total_found = 0
    for p in normalized:
        p_email = p["email"]
        if not p_email or "@" not in p_email:
            continue
        try:
            msgs = fetch_emails_between(creds, user_email, p_email, max_results=max_per, days=days)
            total_found += len(msgs)
            # annotate each message with who it's between
            for m in msgs:
                combined_entries.append({
                    "participant_email": p_email,
                    "participant_name": p.get("name", ""),
                    "subject": m.get("subject", ""),
                    "snippet": m.get("snippet", "") or "",
                    "body_excerpt": m.get("body_excerpt", "") or "",
                    "date_header": m.get("date_header", "")
                })
        except Exception as e:
            logging.exception("Gmail fetch failed for participant %s: %s", p_email, e)

    # If nothing found, return graceful message
    if total_found == 0:
        summary_text = "No recent email exchanges found between you and these participants."
        prebrief_id = str(uuid.uuid4())
        # persist minimal doc
        prebrief_doc = {
            "title": meeting_title,
            "participants": normalized,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": summary_text,
            "source_count": 0,
            "start_time": meeting_start or None
        }
        try:
            db.collection("users").document(user_email) \
              .collection("PreBriefs").document(prebrief_id).set(prebrief_doc, merge=True)
        except Exception:
            logging.exception("Failed to persist empty prebrief")
        return jsonify({"summary": summary_text, "source_count": 0, "prebrief_id": prebrief_id}), 200

    # Step B: prepare combined_text (concise)
    pieces = []
    for e in combined_entries:
        hdr = f"Participant: {e['participant_email']} Subject: {e['subject']}"
        snippet = e.get("snippet", "")
        body = e.get("body_excerpt", "")
        piece = f"{hdr}\n{snippet}\n{(body[:800] + '...') if body else ''}"
        pieces.append(piece)
    combined_text = "\n\n".join(pieces)

    # Truncate to safe size
    max_context = 12000
    if len(combined_text) > max_context:
        combined_text = combined_text[:max_context] + "\n\n[TRUNCATED]"

    # Step C: call Gemini (simple HTTP wrapper) to produce structured JSON
    gemini_url = os.environ.get("GEMINI_URL") or "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-preview:generateContent"
    gemini_key = os.environ.get("GEMINI_API_KEY")
    summary_text = None
    action_items = []
    questions = []

    if not gemini_key:
        logging.warning("No GEMINI_API_KEY set, returning combined text as summary")
        summary_text = combined_text[:2000]  # fallback
    else:
        prompt = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": f"""
You are Briefdeck, an AI pre-brief assistant.

Meeting Title: {meeting_title}
Participants: {[p['email'] for p in normalized]}

Here are recent email exchanges (most relevant excerpts):
{combined_text}

Return ONLY a JSON object with keys:
- executive_summary: short paragraph (1-3 sentences)
- action_items: array of short action item strings
- questions: array of 3 smart questions to ask during the meeting

If you cannot extract, return empty arrays appropriately.
"""
                        }
                    ]
                }
            ]
        }

        try:
            headers = {"Content-Type": "application/json"}
            resp = requests.post(gemini_url, headers=headers, params={"key": gemini_key}, json=prompt, timeout=30)
            resp.raise_for_status()
            parsed = resp.json()
            # defensive: try to pull assistant text
            assistant_text = None
            try:
                assistant_text = parsed["candidates"][0]["content"]["parts"][0]["text"]
            except Exception:
                # try other common fields
                assistant_text = parsed.get("output", parsed.get("text", None)) or str(parsed)

            # attempt to extract JSON object from assistant_text
            def _maybe_parse_json(s):
                try:
                    # find first { ... } substring and parse
                    import re
                    m = re.search(r"\{.*\}\s*$", s, flags=re.S)
                    js = s if m is None else m.group(0)
                    return json.loads(js)
                except Exception:
                    try:
                        return json.loads(s)
                    except Exception:
                        return None

            j = _maybe_parse_json(assistant_text)
            if isinstance(j, dict):
                summary_text = j.get("executive_summary") or j.get("summary") or j.get("prebrief") or (assistant_text[:2000])
                action_items = j.get("action_items") or j.get("actions") or []
                questions = j.get("questions") or []
            else:
                # fallback: return assistant raw
                summary_text = assistant_text[:4000]
        except Exception as e:
            logging.exception("Gemini call failed: %s", e)
            summary_text = combined_text[:2000]

    # Step D: persist prebrief doc
    prebrief_id = str(uuid.uuid4())
    prebrief_doc = {
        "title": meeting_title,
        "participants": normalized,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": summary_text,
        "action_items": action_items,
        "questions": questions,
        "source_count": total_found,
        "start_time": meeting_start or None
    }
    try:
        db.collection("users").document(user_email) \
          .collection("PreBriefs").document(prebrief_id).set(prebrief_doc, merge=True)
    except Exception:
        logging.exception("Failed to persist prebrief to Firestore")

    # response
    return jsonify({
        "prebrief_id": prebrief_id,
        "summary": summary_text,
        "action_items": action_items,
        "questions": questions,
        "source_count": total_found
    }), 200


def build_creds_and_refresh1(user_email: str, token_data: dict):
    """
    Builds Google Credentials from stored token data (Firestore).
    Automatically refreshes if expired and updates Firestore with new access_token + expiry.
    """
    if not token_data:
        raise ValueError("Missing token_data")

    creds = Credentials(
        token=token_data.get("access_token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        scopes=[
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.readonly"
]
    )

    try:
        # If expired or invalid, refresh automatically
        if not creds.valid or creds.expired:
            logging.info(f"Refreshing Gmail token for {user_email}...")
            creds.refresh(Request())

            # Save updated token and expiry back to Firestore
            new_token_data = {
                "access_token": creds.token,
                "refresh_token": creds.refresh_token,
                "token_expiry": creds.expiry.isoformat() if creds.expiry else None,
            }

            db.collection("users").document(user_email).update({
                "gmail_tokens": new_token_data,
                "gmail_last_refresh": datetime.now(timezone.utc).isoformat()
            })

            logging.info(f"✅ Refreshed and saved Gmail token for {user_email}")
    except Exception as e:
        logging.exception("Failed to refresh Gmail token: %s", e)
        raise

    return creds




import os
import json
import uuid
import logging
import threading
from datetime import datetime, timedelta, timezone
from flask import request, jsonify

# Google Cloud Tasks (optional production scheduler)
try:
    from google.cloud import tasks_v2
    CLOUD_TASKS_AVAILABLE = True
except Exception:
    CLOUD_TASKS_AVAILABLE = False

# existing helpers you already have:
# - db (Firestore client)
# - build_creds_and_refresh(user_email, token_data)
# - fetch_emails_between(creds, from_email, to_email, max_results, days)
# - create_bot_for_meeting(...)  -- not used here
# - existing Gemini wrapper: enhance_with_gemini or call using requests to GEMINI_URL + GEMINI_API_KEY

PROJECT_ID = "deal-hunt-0e8jp3"
CLOUD_TASKS_QUEUE = "briefdeck-prebrief-queue"
CLOUD_TASKS_LOCATION = "asia-south1"
BACKEND_BASE = "https://nelda-grippelike-kaylee.ngrok-free.dev"
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_URL = os.environ.get("GEMINI_URL", "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent")

# ---------- Utility: detect follow-up meeting ----------
# requires: pip install python-dateutil
import re
import threading
from google.cloud import firestore

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I)

def _normalize_participant_emails(raw) -> Optional[str]:
    """
    Normalize participant entry into a lowercase email string or return None.

    Accepts:
      - dict: {'email': 'a@b.com', 'name': '...'} (many key variants supported)
      - list/tuple containing a dict/string -> first element inspected
      - string variants:
         - plain email 'a@b.com'
         - 'email: a@b.com, name: ""'
         - JSON-like '"email": "a@b.com", "name": ""'
         - other text containing an email
    Behavior:
      - returns lowercased email or None if not found.
    """
    if not raw:
        return None

    # If passed a sequence, try first element
    if isinstance(raw, (list, tuple)) and raw:
        return _normalize_participant_emails(raw[0])

    # If dict-like, try common keys
    if isinstance(raw, dict):
        for key in ("email", "email_address", "emailAddress", "e-mail", "mail"):
            val = raw.get(key)
            if val:
                s = str(val).strip().lower()
                if _EMAIL_RE.search(s):
                    return _EMAIL_RE.search(s).group(0).lower()
                return s or None
        # fall back to scanning values for an email-like string
        for v in raw.values():
            if isinstance(v, str):
                m = _EMAIL_RE.search(v)
                if m:
                    return m.group(0).lower()
        return None

    # If it's already a string, inspect it
    s = str(raw).strip()

    # quick handle of "email: a@b.com, name: ''" style
    if "email:" in s.lower():
        try:
            after = s.lower().split("email:", 1)[1]
            candidate = after.split(",")[0].strip().strip('"').strip("'")
            m = _EMAIL_RE.search(candidate)
            if m:
                return m.group(0).lower()
            return candidate.lower() if "@" in candidate else None
        except Exception:
            pass

    # try JSON-like '"email": "a@b.com"'
    m = re.search(r'"?email"?\s*[:=]\s*["\']\s*([^"\'\s,}]+)', s, flags=re.I)
    if m:
        candidate = m.group(1).strip()
        mm = _EMAIL_RE.search(candidate)
        if mm:
            return mm.group(0).lower()
        return candidate.lower() if "@" in candidate else None

    # final fallback: find any email-like substring
    m2 = _EMAIL_RE.search(s)
    if m2:
        return m2.group(0).lower()

    # nothing found
    return None



EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

def _parse_iso_like(value):
    if not value:
        return None
    # Firestore Timestamp-like -> to_datetime()
    try:
        if hasattr(value, "to_datetime"):
            return value.to_datetime().astimezone(timezone.utc)
    except Exception:
        pass
    # datetime already
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    s = str(value)
    # handle trailing Z
    if s.endswith("Z"):
        s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except Exception:
        # last attempt: find an ISO-like substring
        m = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?", s)
        if m:
            try:
                ms = m.group(0)
                if ms.endswith("Z"):
                    ms = ms.replace("Z", "+00:00")
                return datetime.fromisoformat(ms).astimezone(timezone.utc)
            except Exception:
                return None
    return None

def _normalize_email(raw):
    """Return a lowercased email extracted from many shapes, or None."""
    if not raw:
        return None
    # dict-like
    if isinstance(raw, dict):
        for key in ("email", "email_address", "emailAddress", "e-mail"):
            if raw.get(key):
                return str(raw.get(key)).strip().lower()
        # sometimes dict contains nested strings
        raw_str = str(raw)
    else:
        raw_str = str(raw)

    raw_str = raw_str.strip().strip('"').strip("'")

    # Quick attempt: JSON-like key "email": "..."
    m = re.search(r'"?email"?\s*[:=]\s*["\']?([^"\'\s,}]+)', raw_str, flags=re.I)
    if m:
        return m.group(1).strip().lower()

    # "email: a@b.com, name: ''" style
    if "email:" in raw_str.lower():
        try:
            after = raw_str.split("email:", 1)[1]
            candidate = after.split(",")[0].strip().strip('"').strip("'")
            if EMAIL_RE.search(candidate):
                return candidate.lower()
        except Exception:
            pass

    # fallback: find any email-like substring
    m2 = EMAIL_RE.search(raw_str)
    if m2:
        return m2.group(0).lower()

    # if the string itself looks like an email
    if "@" in raw_str and "." in raw_str:
        return raw_str.lower()

    return None

def find_most_recent_bot_with_participant(user_email: str, participant_email: str, before_time_iso, lookback_days: int = 365):
    """
    Search Connections/*/Bots/* for the most recent bot document that:
      - contains the participant_email (in any shape)
      - has a timestamp strictly before before_time_iso

    Returns (meeting_id_or_bot_doc_id, doc_dict) or (None, None)
    """

    logging.info("Searching Bots under user=%s for participant=%s before=%s", user_email, participant_email, before_time_iso)
    try:
        # Normalize the target email so all comparisons are lowercase
        target = _normalize_email(participant_email)
        if not target:
            logging.warning("normalize failed for participant_email=%s", participant_email)
            return None, None

        before_dt = _parse_iso_like(before_time_iso)
        if not before_dt:
            before_dt = datetime.now(timezone.utc)

        SKIP_CONNECTION_IDS = {"prebrief_job", "postbrief_job", "pre_brief_job", "system", "_metadata"}
        best = (None, None, None)  # (id, data, ts)
        any_conn = False

        # --- 1️⃣ Normal path: look in user's Connections/<conn>/Bots ---
        conns = db.collection("users").document(user_email).collection("Connections").stream()
        for conn in conns:
            any_conn = True
            conn_id = conn.id
            if conn_id in SKIP_CONNECTION_IDS or conn_id.startswith("_") or conn_id.endswith("_job"):
                continue

            bots_coll = (
                db.collection("users")
                .document(user_email)
                .collection("Connections")
                .document(conn_id)
                .collection("Bots")
            )

            for bdoc in bots_coll.stream():
                try:
                    b = bdoc.to_dict() or {}
                except Exception:
                    continue

                # Pick a timestamp
                ts = None
                for k in ("last_summary_at", "end_time", "end", "start_time", "start", "created_at", "updated_at"):
                    if k in b and b.get(k):
                        ts = _parse_iso_like(b.get(k))
                        if ts:
                            break

                # Check if the participant is present
                found = False
                pfield = b.get("participants") or b.get("attendees") or b.get("participants_emails") or b.get("emails")

                if isinstance(pfield, list):
                    for item in pfield:
                        if _normalize_email(item) == target:
                            found = True
                            break
                elif pfield:
                    if _normalize_email(pfield) == target:
                        found = True

                # Also check alternative fields
                if not found:
                    for alt in ("participant", "attendee", "owner", "email"):
                        v = b.get(alt)
                        if v and _normalize_email(v) == target:
                            found = True
                            break

                if not found:
                    continue
                if ts and ts >= before_dt:
                    continue

                # Choose the most recent bot
                if best[2] is None or (ts and ts > best[2]):
                    best = (bdoc.id, b, ts)

        # --- 2️⃣ Fallback path: global collection_group('Bots') ---
        if not any_conn or best[0] is None:
            logging.info("No valid connections or bots found under user=%s; using collection_group('Bots') fallback (client-side filter)", user_email)
            try:
                bots_stream = db.collection_group("Bots").limit(500).stream()
            except Exception as e:
                logging.exception("collection_group('Bots') stream failed: %s", e)
                bots_stream = []

            for bdoc in bots_stream:
                try:
                    path = bdoc.reference.path
                except Exception:
                    path = getattr(bdoc, "path", "") or ""
                if not path.startswith(f"users/{user_email}/"):
                    continue

                try:
                    b = bdoc.to_dict() or {}
                except Exception:
                    continue

                # Pick timestamp
                ts = None
                for k in ("last_summary_at", "end_time", "end", "start_time", "start", "created_at"):
                    if k in b and b.get(k):
                        ts = _parse_iso_like(b.get(k))
                        if ts:
                            break

                # Match participant locally
                pfield = b.get("participants") or b.get("attendees") or b.get("participants_emails") or b.get("emails") or []
                found = False
                if isinstance(pfield, list):
                    for item in pfield:
                        if _normalize_email(item) == target:
                            found = True
                            break
                elif pfield:
                    if _normalize_email(pfield) == target:
                        found = True

                # Alternative single fields
                if not found:
                    for alt in ("participant", "attendee", "owner", "email"):
                        v = b.get(alt)
                        if v and _normalize_email(v) == target:
                            found = True
                            break

                if not found:
                    continue
                if ts and ts >= before_dt:
                    continue

                # Pick most recent
                if best[2] is None or (ts and ts > best[2]):
                    best = (bdoc.id, b, ts)

        # --- 3️⃣ Return final result ---
        if best[0]:
            doc_id = best[1].get("calendar_event_id") or best[1].get("meeting_id") or best[0]
            logging.info("✅ Found previous Bot %s (ts=%s)", doc_id, best[2])
            return doc_id, best[1]

        logging.info("ℹ️ No previous meeting found for %s under user %s", target, user_email)
        return None, None

    except Exception as e:
        logging.exception("find_most_recent_bot_with_participant failed: %s", e)
        return None, None







from google.oauth2 import service_account
from google.api_core.client_options import ClientOptions

def schedule_prebrief_job_cloudtasks(user_email, meeting_doc):
    """
    Schedule a Cloud Task to POST /run_prebrief_job at the desired time.

    Uses explicit service account credentials (preferred) or falls back to local scheduler.
    """
    # Quick checks
    if not CLOUD_TASKS_AVAILABLE:
        logging.info("Cloud Tasks library not available — using local scheduler fallback")
        return schedule_prebrief_job_local(user_email, meeting_doc)
    if not PROJECT_ID:
        logging.info("PROJECT_ID missing — using local scheduler fallback")
        return schedule_prebrief_job_local(user_email, meeting_doc)

    # Resolve service account file: env var -> repo file
    sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not sa_path:
        sa_path = os.path.join(os.path.dirname(__file__), "GOOGLE_APPLICATION_CREDENTIALS.json")

    if not os.path.exists(sa_path):
        logging.warning("Service account file not found at %s — using local scheduler fallback", sa_path)
        return schedule_prebrief_job_local(user_email, meeting_doc)

    # Create Cloud Tasks client with explicit credentials
    try:
        creds = service_account.Credentials.from_service_account_file(sa_path)
        # If your service account belongs to a different project than PROJECT_ID you can pass
        # client_options={"quota_project_id": PROJECT_ID} to ensure quota is charged to PROJECT_ID.
        client_opts = ClientOptions(quota_project_id=PROJECT_ID)
        client = tasks_v2.CloudTasksClient(credentials=creds, client_options=client_opts)
    except Exception as e:
        logging.exception("Failed to initialize CloudTasks client with SA key '%s': %s", sa_path, e)
        return schedule_prebrief_job_local(user_email, meeting_doc)

    # Build queue path
    try:
        parent = client.queue_path(PROJECT_ID, CLOUD_TASKS_LOCATION, CLOUD_TASKS_QUEUE)
    except Exception as e:
        logging.exception("Failed to compute queue path: %s (project=%s location=%s queue=%s)", e, PROJECT_ID, CLOUD_TASKS_LOCATION, CLOUD_TASKS_QUEUE)
        return schedule_prebrief_job_local(user_email, meeting_doc)

    # Compute run_at (30 minutes before meeting)
    try:
        start_dt = datetime.fromisoformat(meeting_doc["start_time"]).astimezone(timezone.utc)
    except Exception:
        logging.warning("Invalid meeting start_time, scheduling for +1 minute")
        start_dt = datetime.now(timezone.utc) + timedelta(minutes=1)

    run_at = start_dt - timedelta(minutes=30)
    if run_at < datetime.now(timezone.utc) + timedelta(seconds=10):
        run_at = datetime.now(timezone.utc) + timedelta(seconds=5)

    payload = {
        "user_email": user_email,
        "meeting_id": meeting_doc.get("meeting_id"),
        "title": meeting_doc.get("title"),
        "start_time": meeting_doc.get("start_time"),
        "participants": meeting_doc.get("participants", [])
    }

    task = {
        "http_request": {
            "http_method": tasks_v2.HttpMethod.POST,
            "url": f"{BACKEND_BASE}/run_prebrief_job",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(payload).encode("utf-8")
        },
        "schedule_time": {"seconds": int(run_at.timestamp())}
    }

    try:
        resp = client.create_task(parent=parent, task=task)
        logging.info("Scheduled Cloud Task: %s (run_at=%s) -> queue=%s", resp.name, run_at.isoformat(), CLOUD_TASKS_QUEUE)
        return resp.name
    except Exception as e:
        logging.exception("Failed to create Cloud Task (falling back to local scheduler): %s", e)
        return schedule_prebrief_job_local(user_email, meeting_doc)


def schedule_prebrief_job_local(user_email, meeting_doc):
    """
    Local fallback: use threading.Timer to schedule the job. Suitable for dev. Not reliable across restarts.
    """
    try:
        start_dt = datetime.fromisoformat(meeting_doc["start_time"]).astimezone(timezone.utc)
    except Exception:
        start_dt = datetime.now(timezone.utc) + timedelta(minutes=1)
    run_at = start_dt - timedelta(minutes=30)
    delay = max(1, (run_at - datetime.now(timezone.utc)).total_seconds())
    logging.info("Scheduling local prebrief job in %.1f seconds (run_at=%s)", delay, run_at.isoformat())

    def _delayed():
        try:
            with app.app_context():
                run_prebrief_job_internal(user_email, meeting_doc)
        except Exception as e:
            logging.exception("Local prebrief job failed: %s", e)

    t = threading.Timer(delay, _delayed)
    t.daemon = True
    t.start()
    return f"local-timer-{uuid.uuid4()}"

# ---------- Entrypoint: calendar webhook should call this when event created/updated ----------
def handle_new_calendar_event(user_email: str, event: dict):
    """
    Called when a calendar event is created or updated.
    event should include: id, start_time (ISO), end_time (ISO, optional), attendees list (emails), summary/title

    Behavior:
      - Check prior meetings between user_email and each participant (existing behavior).
      - ALSO check prior meetings between any two attendees (pairwise).
      - If any prior meeting is found (either user <> participant OR attendeeA <> attendeeB),
        schedule a prebrief job for this meeting (30m before start) for the calendar owner (user_email).
    """
    logging.info("Calling handle_new_calendar_event for event %s (user=%s)", event.get("id"), user_email)
    # normalize participants (emails)
    participants = []
    for a in (event.get("attendees") or []):
        if isinstance(a, dict):
            if a.get("email"):
                participants.append({"email": a["email"].lower().strip(), "name": a.get("displayName", "")})
        elif isinstance(a, str) and "@" in a:
            participants.append({"email": a.lower().strip(), "name": ""})

    if not participants:
        logging.info("No attendees found on event %s; skipping prebrief checks", event.get("id"))
        return

    # ---- 1) Check user <> participant (original behavior) ----
    scheduled = False
    for p in participants:
        p_email = p.get("email")
        if not p_email:
            continue
        # Skip if same as user
        if p_email == (user_email or "").lower():
            continue

        logging.info("🔍 Looking for previous meeting between %s and %s", user_email, p_email)
        prev_id, prev_doc = find_most_recent_bot_with_participant(user_email, p_email, event.get("start_time"))
        join_url = extract_meeting_url(event.get("raw_event") or event) or event.get("meeting_url") or ""
        if prev_id:
            logging.info("🔔 Previous meeting found between user and participant (%s). Scheduling prebrief.", p_email)
            meeting_doc = {
                "meeting_id": event.get("id") or str(uuid.uuid4()),
                "title": event.get("summary") or event.get("title") or "Untitled",
                "start_time": event.get("start_time"),
                "participants": participants,
                "join_url": join_url, 
                "prev_meeting_id": prev_id
            }
            schedule_id = schedule_prebrief_job_cloudtasks(user_email, meeting_doc)
            # persist metadata
            try:
                db.collection("users").document(user_email) \
                  .collection("ScheduledPreBriefs").document(meeting_doc["meeting_id"]).set({
                    "scheduled_at": datetime.now(timezone.utc).isoformat(),
                    "run_at": (datetime.fromisoformat(meeting_doc["start_time"]).astimezone(timezone.utc) - timedelta(minutes=30)).isoformat(),
                    "prev_meeting_id": prev_id,
                    "join_url": join_url,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "task_ref": schedule_id,
                    "trigger": "user_vs_participant",
                    "matched_with": p_email
                }, merge=True)
            except Exception:
                logging.exception("Failed to persist scheduled prebrief metadata for user_vs_participant")
            scheduled = True
            break  # only need to schedule once per event (same as original)

    if scheduled:
        return

    # ---- 2) Check pairwise among attendees (A <> B) ----
    # We'll check each unordered pair (i < j)
    n = len(participants)
    for i in range(n):
        for j in range(i + 1, n):
            a = participants[i].get("email")
            b = participants[j].get("email")
            if not a or not b or a == b:
                continue
            # Skip pairs involving the calendar owner if already checked above for user vs participant
            # (but it's safe to still check)
            logging.info("🔍 Looking for previous meeting between attendees %s and %s", a, b)
            # Check for a prior meeting between a and b (we search under a for b)
            prev_id_ab, prev_doc_ab = find_most_recent_bot_with_participant(a, b, event.get("start_time"))
            if prev_id_ab:
                logging.info("🔔 Previous meeting found between attendees %s and %s. Scheduling prebrief for owner %s.", a, b, user_email)
                meeting_doc = {
                    "meeting_id": event.get("id") or str(uuid.uuid4()),
                    "title": event.get("summary") or event.get("title") or "Untitled",
                    "start_time": event.get("start_time"),
                    "participants": participants,
                    "join_url": join_url, 
                    "prev_meeting_id": prev_id_ab,
                    "matched_pair": [a, b]
                }
                schedule_id = schedule_prebrief_job_cloudtasks(user_email, meeting_doc)
                try:
                    db.collection("users").document(user_email) \
                      .collection("ScheduledPreBriefs").document(meeting_doc["meeting_id"]).set({
                        "scheduled_at": datetime.now(timezone.utc).isoformat(),
                        "run_at": (datetime.fromisoformat(meeting_doc["start_time"]).astimezone(timezone.utc) - timedelta(minutes=30)).isoformat(),
                        "prev_meeting_id": prev_id_ab,
                        "join_url": join_url,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "task_ref": schedule_id,
                        "trigger": "attendee_pair",
                        "matched_pair": [a, b]
                    }, merge=True)
                except Exception:
                    logging.exception("Failed to persist scheduled prebrief metadata for attendee_pair")
                return  # scheduled, stop checking further pairs

    logging.info("No prior meetings found for event %s; no prebrief scheduled.", event.get("id"))


# ---------- Job handler endpoint for Cloud Tasks or local calls ----------
@app.route("/run_prebrief_job", methods=["POST"])
def run_prebrief_job():
    """
    Cloud Tasks POSTS here; or local dev can POST here to run job now.
    Body JSON expected: { user_email, meeting_id, title, start_time, participants }
    """
    payload = request.get_json(force=True)
    user_email = payload.get("user_email")
    meeting_id = payload.get("meeting_id")
    # optional prev_meeting_id passed earlier; we'll look it up if missing
    prev_meeting_id = payload.get("prev_meeting_id")
    try:
        run_prebrief_job_internal(user_email, payload, prev_meeting_id=prev_meeting_id)
        return jsonify({"ok": True}), 200
    except Exception as e:
        logging.exception("run_prebrief_job failed: %s", e)
        return jsonify({"error": str(e)}), 500
    



import re
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

# Assumes the following symbols exist in your module:
# db, gc_firestore, find_most_recent_bot_with_participant,
# build_creds_and_refresh1, fetch_emails_between,
# enhance_with_gemini_prebrief, GEMINI_URL, GEMINI_API_KEY



def _normalize_meeting_participants(participants_field):
    """Return list of normalized email strings from meeting_doc['participants']."""
    emails = []
    if not participants_field:
        return emails
    if isinstance(participants_field, str):
        # maybe a JSON string
        try:
            parsed = json.loads(participants_field)
            return _normalize_meeting_participants(parsed)
        except Exception:
            # fallback: comma separated or single email
            for p in participants_field.split(","):
                e = _normalize_participant_emails(p)
                if e:
                    emails.append(e)
            return emails
    if isinstance(participants_field, dict):
        e = _normalize_participant_emails(participants_field)
        if e:
            emails.append(e)
        return emails
    if isinstance(participants_field, (list, tuple)):
        for it in participants_field:
            e = _normalize_participant_emails(it)
            if e:
                emails.append(e)
        return emails
    # fallback single value
    e = _normalize_participant_emails(participants_field)
    if e:
        emails.append(e)
    return emails



def _try_extract_json_candidates(text: str):
    """
    Try to find and parse JSON objects from assistant text. Return best dict or None.
    Prefers candidate containing our keys.
    """
    if not text:
        return None
    candidates = []
    # find balanced { ... } blocks (simple heuristic)
    for m in re.finditer(r"\{(?:[^{}]|\{[^{}]*\})*\}", text, flags=re.DOTALL):
        candidate = m.group(0)
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                candidates.append(obj)
        except Exception:
            # attempt light cleanup
            cleaned = candidate.strip("` \n\r\t")
            try:
                obj = json.loads(cleaned)
                if isinstance(obj, dict):
                    candidates.append(obj)
            except Exception:
                continue
    if not candidates:
        return None
    def score(obj):
        s = 0
        if "questions" in obj: s += 5
        if "executive_summary" in obj or "summary" in obj or "prebrief" in obj: s += 3
        if "action_items" in obj or "actions" in obj: s += 2
        return s
    candidates.sort(key=score, reverse=True)
    return candidates[0]

def _extract_prebrief(result_obj_or_text):
    """
    Normalize the prebrief output into (executive_summary, action_items, questions).
    Accepts dict or string.
    """
    if isinstance(result_obj_or_text, dict):
        executive_summary = result_obj_or_text.get("executive_summary") or result_obj_or_text.get("summary") or result_obj_or_text.get("prebrief") or ""
        action_items = result_obj_or_text.get("action_items") or result_obj_or_text.get("actions") or []
        questions = result_obj_or_text.get("questions") or []
        return executive_summary, action_items, questions

    text = str(result_obj_or_text or "")
    parsed = _try_extract_json_candidates(text)
    if isinstance(parsed, dict):
        return _extract_prebrief(parsed)

    # fallback: use first 1-2 sentences as a summary
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if s.strip()]
    if sentences:
        executive_summary = " ".join(sentences[:2])[:3000]
    else:
        executive_summary = text[:2000]
    return executive_summary, [], []

def run_prebrief_job_internal(user_email, meeting_doc, prev_meeting_id=None):
    """
    Core internal worker:
      - find previous meeting summary (if prev_meeting_id not provided, search)
      - fetch emails between prev_end_time and meeting start_time for each participant
      - combine previous summary + emails + context and call Gemini
      - save prebrief to Firestore under users/{user}/PreBriefs/{meeting_id}
      - update Bots under users/{user}/Connections/*/Bots/* where applicable
      - LOG (print) fetched email extracts to terminal
    """
    # basic validation
    if not user_email or not meeting_doc:
        raise ValueError("Missing user_email or meeting_doc")

    meeting_id = meeting_doc.get("meeting_id") or str(uuid.uuid4())
    raw_participants = meeting_doc.get("participants", []) or []
    meeting_start = meeting_doc.get("start_time")  # could be ISO string or datetime or Firestore Timestamp

    logging.info("run_prebrief_job_internal: user=%s meeting=%s", user_email, meeting_id)

    meeting_start_dt = _parse_iso_like(meeting_start)
    normalized_participants = _normalize_meeting_participants(raw_participants)
    logging.debug("Meeting start (parsed): %s ; participants(normalized): %s", meeting_start_dt, normalized_participants)

    # -----------------------
    # 1) try to find most recent via Bots / Connections
    # -----------------------
    prev_data = None
    prev_meeting_id = prev_meeting_id or None
    if not prev_meeting_id and normalized_participants:
        first_email = normalized_participants[0]
        before_arg = meeting_start_dt.isoformat() if meeting_start_dt else meeting_start
        try:
            prev_meeting_id, prev_data = find_most_recent_bot_with_participant(user_email, first_email, before_arg)
        except Exception:
            logging.exception("Error calling find_most_recent_bot_with_participant")

    # -----------------------
    # 2) validate candidate (reject if it's the same meeting or ends at/after meeting_start)
    # -----------------------
    def _is_invalid_prev(prev_doc, meeting_start_dt=None):
        if not prev_doc:
            return True
        stored_mid = (prev_doc.get("meeting_id") or prev_doc.get("calendar_event_id") or "")
        if str(stored_mid) and str(stored_mid) == str(meeting_id):
            logging.debug("Rejecting prev_doc because meeting_id/calendar_event_id matches current meeting")
            return True
        prev_end = prev_doc.get("end_time") or prev_doc.get("end") or prev_doc.get("last_summary_at") or prev_doc.get("created_at")
        prev_end_dt = _parse_iso_like(prev_end)
        if prev_end_dt and meeting_start_dt:
            prev_end_dt = prev_end_dt.astimezone(timezone.utc)
            meeting_start_dt = meeting_start_dt.astimezone(timezone.utc)
            if prev_end_dt >= meeting_start_dt:
                logging.debug("Rejecting prev_doc because prev_end >= meeting_start (%s >= %s)", prev_end_dt, meeting_start_dt)
                return True
        return False

    # If invalid, clear and attempt a robust PostBriefs fallback (client-side filtering)
    if _is_invalid_prev(prev_data, meeting_start_dt):
        logging.info("Previous candidate invalid or missing; attempting safe PostBriefs fallback")
        prev_data = None
        prev_meeting_id = None
        try:
            participant_email = normalized_participants[0] if normalized_participants else None
            if participant_email:
                briefs_ref = db.collection("users").document(user_email).collection("PostBriefs")
                # fallback ordering choices
                docs = []
                try:
                    docs = list(briefs_ref.order_by("end_time", direction=gc_firestore.Query.DESCENDING).limit(50).stream())
                except Exception:
                    try:
                        docs = list(briefs_ref.order_by("generated_at", direction=gc_firestore.Query.DESCENDING).limit(50).stream())
                    except Exception:
                        docs = list(briefs_ref.limit(50).stream())

                found = False
                for d in docs:
                    ddata = d.to_dict() or {}
                    emails_field = ddata.get("participants_emails") or ddata.get("participants") or ddata.get("attendees") or []
                    normalized = set()
                    if isinstance(emails_field, list):
                        for item in emails_field:
                            if isinstance(item, dict):
                                normalized.add(((item.get("email") or "")).lower())
                            else:
                                normalized.add((str(item or "")).lower())
                    elif isinstance(emails_field, dict):
                        e = _normalize_participant_emails(emails_field)
                        if e:
                            normalized.add(e)
                    elif isinstance(emails_field, str):
                        try:
                            parsed = json.loads(emails_field)
                            if isinstance(parsed, list):
                                for it in parsed:
                                    normalized.add(_normalize_participant_emails(it) or "")
                            else:
                                normalized.add(emails_field.lower())
                        except Exception:
                            for s in emails_field.split(","):
                                normalized.add(s.strip().lower())

                    if participant_email not in normalized:
                        continue

                    end_time_val = ddata.get("end_time") or ddata.get("end") or ddata.get("generated_at")
                    end_dt = _parse_iso_like(end_time_val)
                    if meeting_start_dt and end_dt and end_dt >= meeting_start_dt:
                        continue

                    prev_meeting_id = d.id
                    prev_data = ddata
                    logging.info("✅ Found valid previous PostBrief: %s for %s", prev_meeting_id, user_email)
                    found = True
                    break

                if not found:
                    logging.info("ℹ️ No previous PostBrief found before %s for %s (checked %d docs)", meeting_start_dt, user_email, len(docs))
            else:
                logging.debug("No participant email available to query PostBriefs fallback")
        except Exception:
            logging.exception("Error fetching safe previous PostBrief for %s", user_email)
    else:
        logging.debug("Using existing previous meeting id=%s", prev_meeting_id)

    # finally, pull summary/end-time values (if any)
    prev_summary = None
    prev_end_time = None
    if prev_data:
        prev_summary = prev_data.get("last_executive_summary") or prev_data.get("summary") or prev_data.get("summary_text")
        prev_end_time = prev_data.get("end_time") or prev_data.get("start_time") or prev_data.get("start") or prev_data.get("last_summary_at") or prev_data.get("created_at")

    logging.debug("prev_meeting_id=%s prev_summary_exists=%s prev_end_time=%s", prev_meeting_id, bool(prev_summary), prev_end_time)

    # -----------------------
    # 3) Gather email context + log each message to terminal
    # -----------------------
    all_email_contexts = []
    user_doc = db.collection("users").document(user_email).get()
    if not user_doc.exists:
        raise RuntimeError("User not found")
    token_data = user_doc.to_dict().get("gmail_tokens", {}) or {}

    creds = None
    try:
        creds = build_creds_and_refresh1(user_email, token_data)
    except Exception:
        logging.exception("Failed to build Gmail creds for %s", user_email)
        try:
            db.collection("users").document(user_email).update({"gmail_needs_reauth": True})
        except Exception:
            logging.exception("Failed to set gmail_needs_reauth flag")

    gmail_reauth_required = False

    # participants for iteration: prefer normalized list; but keep original structure for storage
    iter_participants = []
    # convert normalized emails into dict-like entries to match downstream code
    for e in normalized_participants:
        iter_participants.append({"email": e, "name": ""})

    for p in iter_participants:
        p_email = (p.get("email") or "").lower()
        if not p_email or "@" not in p_email:
            continue

        # compute days window using prev_end_time if available
        start_window_dt = _parse_iso_like(prev_end_time)
        days = 90
        if start_window_dt and meeting_start_dt:
            try:
                delta = meeting_start_dt - start_window_dt
                days = max(1, int(delta.total_seconds() // (60 * 60 * 24)) + 1)
            except Exception:
                days = 90

        if not creds:
            logging.debug("No Gmail creds for %s — skipping email fetch for %s", user_email, p_email)
            continue

        try:
            token_owner_email = token_data.get("google_email") or user_email
            logging.info("📬 Using Gmail mailbox: %s for fetching emails", token_owner_email)
            msgs = fetch_emails_between(creds, from_email=token_owner_email, to_email=p_email, max_results=20, days=days)
            logging.info("✅ Gmail fetch complete for %s ↔ %s | Found %d messages", token_owner_email, p_email, len(msgs) if msgs else 0)
            if msgs:
                all_email_contexts.append({"participant": p_email, "messages": msgs})
                logging.info("---- Gmail messages between %s <-> %s (found %d) ----", user_email, p_email, len(msgs))
                for i, m in enumerate(msgs, start=1):
                    subj = m.get("subject", "") or "(no subject)"
                    snippet = (m.get("snippet") or "")[:400]
                    body_excerpt = (m.get("body_excerpt") or "")[:1200].replace("\n", " ")
                    logging.info("MSG %d: Subject: %s", i, subj)
                    logging.info("     Snippet: %s", snippet)
                    logging.info("     Excerpt (truncated): %s", body_excerpt)
                logging.info("---- end messages for %s ----", p_email)
            else:
                logging.info("No Gmail messages found between %s and %s in last %d days", user_email, p_email, days)
        except Exception as e:
            msg = str(e) or ""
            if "invalid_scope" in msg or "invalid_grant" in msg:
                gmail_reauth_required = True
                logging.error("Gmail invalid scope/grant for %s — marking reauth needed", user_email)
                try:
                    db.collection("users").document(user_email).update({"gmail_needs_reauth": True})
                except Exception:
                    logging.exception("Failed to set gmail_needs_reauth flag")
                break
            else:
                logging.exception("Failed to fetch emails for %s <-> %s: %s", user_email, p_email, e)
                continue

    if gmail_reauth_required and not all_email_contexts:
        logging.info("Gmail reauth required for %s; continuing without email context", user_email)

    # Build combined parts for Gemini prompt
    combined_parts = []
    if prev_summary:
        combined_parts.append(f"Previous meeting summary:\n{prev_summary}\n")
    for ctx in all_email_contexts:
        combined_parts.append(f"Emails with {ctx['participant']} ({len(ctx['messages'])} messages):\n")
        for m in ctx["messages"]:
            combined_parts.append(f"- Subject: {m.get('subject','')}\n  Snippet: {m.get('snippet','')}\n  Excerpt: {m.get('body_excerpt','')[:500]}\n")

    if gmail_reauth_required and not all_email_contexts:
        combined_parts.append("[EMAIL CONTEXT UNAVAILABLE - user needs to re-auth Gmail]\n")

    combined_text = "\n\n".join(combined_parts) or "No recent email content."

    logging.info("===== Combined context to send to Gemini (truncated to 12000 chars) =====")
    logging.info("%s", combined_text[:12000])
    logging.info("===== End combined context =====")

    # Build prompt
    prompt_text = f"""
You are Briefdeck, an AI assistant that generates a short pre-brief for a meeting.

Meeting title: {meeting_doc.get('title')}
Meeting start: {meeting_start}
Participants: {', '.join(normalized_participants)}

Use the context below (previous meeting summary and email exchanges) to produce ONLY a JSON object with:
1) "executive_summary": 2–3 sentences.
2) "action_items": an array of up to 5 concise items.
3) "questions": an array of exactly 3 smart questions to ask during the meeting. (Always include this key, even if generic.)

Context:
{combined_text}

Return ONLY valid JSON, for example:
{{
  "executive_summary": "Summary text here.",
  "action_items": ["item1", "item2"],
  "questions": ["question1", "question2", "question3"]
}}
"""

    # -----------------------
    # 4) Call Gemini (or wrapper) - robust single-call + parsing flow
    # -----------------------
    executive_summary = ""
    action_items = []
    questions = []
    assistant_text = None
    parsed_json = None

    try:
        result_obj = enhance_with_gemini_prebrief(prompt_text, user_email, "prebrief_job", meeting_id)
        # wrapper might return a dict or text
        if isinstance(result_obj, dict):
            parsed_json = result_obj
            logging.debug("Wrapper returned dict directly")
        else:
            assistant_text = str(result_obj or "")
            parsed_json = _try_extract_json_candidates(assistant_text)
    except Exception:
        logging.exception("enhance_with_gemini_prebrief call failed")
        parsed_json = None

    # fallback HTTP call if wrapper didn't produce JSON and you have GEMINI_URL
    if parsed_json is None and (not assistant_text) and 'GEMINI_URL' in globals():
        try:
            import requests
            headers = {"Content-Type": "application/json"}
            payload = {"contents": [{"parts": [{"text": prompt_text}]}]}
            resp = requests.post(GEMINI_URL, params={"key": GEMINI_API_KEY}, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            try:
                assistant_text = data["candidates"][0]["content"]["parts"][0]["text"]
            except Exception:
                assistant_text = json.dumps(data)
            parsed_json = _try_extract_json_candidates(assistant_text)
        except Exception:
            logging.exception("Fallback Gemini HTTP call failed")

    if parsed_json and isinstance(parsed_json, dict):
        executive_summary, action_items, questions = _extract_prebrief(parsed_json)
    else:
        if assistant_text:
            exec_sum, actions, qs = _extract_prebrief(assistant_text)
            executive_summary = exec_sum or executive_summary
            action_items = actions or action_items
            questions = qs or questions

    # safe defaults + normalization
    if not executive_summary:
        executive_summary = "Auto prebrief generation produced no structured result."
    if not isinstance(action_items, list):
        try:
            action_items = list(action_items)
        except Exception:
            action_items = []
    if not isinstance(questions, list):
        questions = []

    # ensure 3 questions
    default_questions = [
        "What is the primary outcome we want from this meeting?",
        "Are there any immediate blockers to progress?",
        "Who will own the follow-ups after this meeting?"
    ]
    questions = [str(q).strip() for q in questions if str(q or "").strip()]
    if len(questions) >= 3:
        questions = questions[:3]
    else:
        for dq in default_questions:
            if len(questions) >= 3:
                break
            if dq not in questions:
                questions.append(dq)
        questions = questions[:3]

    
    join_url = ""
    if meeting_doc.get("join_url"):
        join_url = meeting_doc.get("join_url")

    if not join_url:
        raw = meeting_doc.get("raw") or meeting_doc.get("raw_event") or meeting_doc.get("google_raw_event")
        if raw and isinstance(raw, dict):
            try:
                join_url = extract_meeting_url(raw) or ""
            except Exception:
                join_url = ""
    if not join_url:
        join_url = meeting_doc.get("meetingLink") or meeting_doc.get("meeting_url") or meeting_doc.get("hangoutLink") or ""

    if not join_url and prev_data:
        join_url = prev_data.get("join_url") or prev_data.get("meeting_url") or prev_data.get("meetingLink") or ""


    # -----------------------
    # 5) Persist prebrief
    # -----------------------
    prebrief_doc = {
        "meeting_id": meeting_id,
        "title": meeting_doc.get("title"),
        "participants": raw_participants,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": executive_summary,
        "action_items": action_items,
        "questions": questions,
        "source_email_context_count": len(all_email_contexts),
        "join_url": join_url,
        "Context": combined_text,
        "prev_meeting_id": prev_meeting_id
    }

    try:
        db.collection("users").document(user_email).collection("PreBriefs").document(meeting_id).set(prebrief_doc, merge=True)
        logging.info("Prebrief saved for %s (meeting=%s)", user_email, meeting_id)
    except Exception:
        logging.exception("Failed to persist prebrief under PreBriefs for %s", user_email)

    # Update Bots under Connections/*/Bots/* heuristically
    try:
        connections_coll = db.collection("users").document(user_email).collection("Connections")
        SKIP_CONNECTION_IDS = {"prebrief_job", "postbrief_job", "pre_brief_job", "system", "_metadata"}

        for conn in connections_coll.stream():
            conn_id = conn.id
            if conn_id.endswith("_job"):
               logging.debug("Skipping internal prebrief_job connection %s", conn_id)
               continue

            try:
                conn_data = conn.to_dict() or {}
            except Exception:
                continue

            bots_coll = (
                db.collection("users")
                .document(user_email)
                .collection("Connections")
                .document(conn_id)
                .collection("Bots")
            )

            participants_emails_set = set(normalized_participants)

            for bot_doc in bots_coll.stream():
                try:
                    b = bot_doc.to_dict() or {}
                    matches = False
                    bot_participants = b.get("participants") or []
                    if isinstance(bot_participants, list):
                        for pp in bot_participants:
                            if isinstance(pp, dict):
                                if (pp.get("email") or "").lower() in participants_emails_set:
                                    matches = True
                                    break
                            elif isinstance(pp, str):
                                if pp.lower() in participants_emails_set:
                                    matches = True
                                    break
                    bot_title = (b.get("title") or "").strip().lower()
                    meeting_title = (meeting_doc.get("title") or "").strip().lower()
                    if bot_title and meeting_title and meeting_title in bot_title:
                        matches = True

                    if matches:
                        update_payload = {
                            "last_executive_summary": executive_summary,
                            "last_summary_at": datetime.now(timezone.utc).isoformat()
                        }
                        try:
                            bots_coll.document(bot_doc.id).update(update_payload)
                            logging.info("Updated Bot %s for user %s with prebrief", bot_doc.id, user_email)
                        except Exception:
                            logging.exception("Failed to update bot doc %s", bot_doc.id)
                except Exception:
                    logging.exception("Error inspecting bot doc %s for user %s", getattr(bot_doc, "id", "<unknown>"), user_email)
    except Exception:
        logging.exception("Error scanning Connections/*/Bots/* for user %s", user_email)

    return prebrief_doc



# ---------- helper to extract JSON from a possibly messy assistant_text ----------
import re, json, logging

def _extract_json_from_text(text):
    """
    Robustly extract a JSON object from model text.
    Tries all {...} blocks (non-greedy) and returns the first parseable
    JSON object that contains expected prebrief keys.
    """
    if not text:
        logging.debug("No text to parse")
        return None

    # find all {...} blocks (non-greedy)
    candidates = re.findall(r"\{.*?\}", text, flags=re.DOTALL)
    if not candidates:
        logging.debug("No JSON object found in text (len=%d)", len(text))
        return None

    logging.debug("Found %d JSON candidate blocks; trying to parse", len(candidates))

    expected_keys = {"executive_summary", "action_items", "questions", "summary", "prebrief"}
    for idx, candidate in enumerate(candidates, start=1):
        short = candidate[:500].replace("\n", " ")
        logging.debug("Attempting candidate %d (len=%d): %s", idx, len(candidate), short)

        # try raw parse
        try:
            parsed = json.loads(candidate)
            logging.debug("Candidate %d parsed as JSON", idx)
        except Exception as e:
            # try cleaning common artifacts and parse again
            cleaned = candidate.strip("` \n\r\t")
            try:
                parsed = json.loads(cleaned)
                logging.debug("Candidate %d parsed after cleaning", idx)
            except Exception as e2:
                logging.warning("Candidate %d JSON parse failed: %s | cleaned error: %s", idx, e, e2)
                continue

        # prefer objects that include our expected keys
        if isinstance(parsed, dict):
            if expected_keys.intersection(set(parsed.keys())):
                logging.debug("Candidate %d contains expected keys; returning parsed JSON", idx)
                return parsed
            else:
                # keep last-ditch parsed result if nothing else matches
                fallback = parsed
                logging.debug("Candidate %d parsed but missing expected keys", idx)
        else:
            logging.debug("Candidate %d parsed but is not a dict", idx)

    # if we get here, pick last successful parsed dict if any
    try:
        if 'parsed' in locals() and isinstance(parsed, dict):
            logging.debug("Returning last parsed JSON candidate (no expected keys found)")
            return parsed
    except Exception:
        pass

    logging.debug("No suitable JSON parsed from text")
    return None


def enhance_with_gemini_prebrief(text: str, user_email: str, job_tag: str, meeting_id: str, timeout: int = 60) -> dict:
    """
    Call Gemini for prebrief generation and return a parsed dict (if JSON found)
    or a dict containing the raw assistant text as 'executive_summary'.

    Returns shape (example):
    {
      "executive_summary": "...",
      "action_items": [...],           # optional
      "questions": [...]               # optional
    }
    """
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": f"""
You are a meeting assistant. Analyze the context below and return ONLY a valid JSON object with:
  - "executive_summary": short paragraph (2-3 sentences)
  - "action_items": array of up to 5 concise actionable items
  - "questions": array of exactly 3 smart questions (always included)

Context:
\"\"\"
{text}
\"\"\"

Return ONLY JSON, no markdown or commentary.
"""
                    }
                ]
            }
        ]
    }

    try:
        resp = requests.post(GEMINI_URL, headers=headers, params={"key": GEMINI_API_KEY}, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logging.exception("Gemini request failed for prebrief: %s", e)
        # Return fallback dict so caller still persists something reasonable
        return {"executive_summary": f"Gemini request failed: {e}", "action_items": [], "questions": []}

    # defensive extraction of assistant text
    assistant_text = None
    try:
        assistant_text = data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        try:
            assistant_text = json.dumps(data)
        except Exception:
            assistant_text = str(data)

    # Try to parse JSON from assistant_text using your helper
    parsed = None
    try:
        parsed = _extract_json_from_text(assistant_text)
    except Exception:
        parsed = None

    if isinstance(parsed, dict):
        # ensure expected keys exist (return as-is, caller will normalize)
        return parsed
    else:
        # fallback: return assistant_text as executive_summary
        return {
            "executive_summary": (assistant_text or "").strip(),
            "action_items": [],
            "questions": []
        }




@app.route("/debug_list_user_bots", methods=["POST"])
# debug endpoints — paste into your Flask app

@app.route("/debug_check_user_doc", methods=["POST"])
def debug_check_user_doc():
    """
    POST JSON: { "user_email": "hamzacham@gmail.com" }
    Verifies the top-level user document exists and returns selected fields.
    """
    try:
        p = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "invalid json"}), 400
    user_email = p.get("user_email")
    if not user_email:
        return jsonify({"error": "user_email required"}), 400

    doc_ref = db.collection("users").document(user_email)
    doc = doc_ref.get()
    if not doc.exists:
        return jsonify({"exists": False, "path": doc_ref.path}), 200
    data = doc.to_dict() or {}
    # return only a few keys to keep payload small
    keys = ["Connections", "calendar_watch", "gmail_tokens", "processed_events"]
    summary = {k: data.get(k) for k in keys if k in data}
    return jsonify({"exists": True, "path": doc_ref.path, "summary_keys": list(summary.keys()), "summary": summary}), 200






G_OAUTH_REVOKE = "https://oauth2.googleapis.com/revoke"

@app.route("/disconnect_google", methods=["POST"])
def disconnect_google():
    """
    Disconnect Google calendar / google_tokens only. Do NOT touch gmail_tokens.
    Steps:
      - verify Firebase ID token
      - locate user doc (try uid, then email doc id, then query)
      - optionally revoke google_tokens.refresh_token if present
      - delete google_tokens and calendar_watch fields (preserve gmail_tokens)
      - return the before/after snapshot for easy verification
    """
    try:
        auth_header = (request.headers.get("Authorization") or "").strip()
        if not auth_header.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Missing Authorization header"}), 401
        id_token = auth_header.split(" ", 1)[1].strip()

        # verify token
        decoded = firebase_auth.verify_id_token(id_token)
        uid = decoded.get("uid")
        email_from_token = decoded.get("email")

        # find user doc: try uid, then email-as-doc-id, then query by email/auth_uid
        user_ref = None
        if uid:
            cand = db.collection("users").document(uid)
            if cand.get().exists:
                user_ref = cand

        if user_ref is None and email_from_token:
            cand = db.collection("users").document(email_from_token)
            if cand.get().exists:
                user_ref = cand

        if user_ref is None and email_from_token:
            docs = list(db.collection("users").where("email", "==", email_from_token).limit(1).stream())
            if docs:
                user_ref = docs[0].reference

        if user_ref is None and uid:
            docs = list(db.collection("users").where("auth_uid", "==", uid).limit(1).stream())
            if docs:
                user_ref = docs[0].reference

        if user_ref is None:
            logging.warning("disconnect_google: user doc not found uid=%s email=%s", uid, email_from_token)
            return jsonify({"ok": False, "error": "User not found (no matching user doc)"}), 404

        # load user doc and show pre-update fields for debugging
        user_snap = user_ref.get()
        udata = user_snap.to_dict() or {}
        logging.info("disconnect_google: user_doc_id=%s found. pre-update keys=%s", user_ref.id, list(udata.keys()))

        # Optionally revoke refresh token (default: False to be safe)
        body = request.get_json(silent=True) or {}
        do_revoke = bool(body.get("revoke_refresh", False))

        # Prefer revoking google_tokens.refresh_token only (do not revoke gmail token)
        calendar_refresh = None
        if isinstance(udata.get("google_tokens"), dict):
            calendar_refresh = (
                udata["google_tokens"].get("refresh_token")
                or udata["google_tokens"].get("refresh")
                or udata["google_tokens"].get("calendar_refresh_token")
            )

        if do_revoke and calendar_refresh:
            try:
                resp = requests.post(G_OAUTH_REVOKE, params={"token": calendar_refresh}, timeout=8)
                if resp.status_code in (200, 204):
                    logging.info("disconnect_google: revoked calendar refresh token for user_doc=%s", user_ref.id)
                else:
                    logging.warning("disconnect_google: revoke returned %s: %s", resp.status_code, resp.text[:300])
            except Exception:
                logging.exception("disconnect_google: failed calling Google revoke endpoint")

        # Build update: remove google_tokens and calendar_watch but preserve gmail_tokens
        updates = {
            "google_tokens": firestore.DELETE_FIELD,
            "calendar_watch": firestore.DELETE_FIELD,
            "calendar_connected": False,
            "last_google_disconnect_at": datetime.now(timezone.utc).isoformat(),
        }

        # Try update and show post-update doc for verification
        try:
            user_ref.update(updates)
        except Exception:
            logging.exception("disconnect_google: failed to update user doc %s", user_ref.id)
            return jsonify({"ok": False, "error": "Failed to update user doc"}), 500

        # fetch after snapshot
        after_snap = user_ref.get()
        after_data = after_snap.to_dict() or {}
        logging.info("disconnect_google: update applied for user_doc=%s. post keys=%s", user_ref.id, list(after_data.keys()))

        # Return pre/post for quick verification (trim large fields)
        def trim(d):
            if not isinstance(d, dict):
                return d
            out = {}
            for k, v in d.items():
                if k in ("google_tokens", "gmail_tokens", "calendar_watch") and isinstance(v, dict):
                    out[k] = {kk: ("<redacted>" if kk.lower().find("token")>=0 or kk.lower().find("refresh")>=0 else vv) for kk, vv in v.items()}
                else:
                    out[k] = v
            return out

        return jsonify({
            "ok": True,
            "message": "Disconnected Google (google_tokens/calendar_watch removed). Gmail left intact.",
            "user_doc_id": user_ref.id,
            "before": trim(udata),
            "after": trim(after_data),
        }), 200

    except firebase_auth.InvalidIdTokenError:
        return jsonify({"ok": False, "error": "Invalid ID token"}), 401
    except Exception as e:
        logging.exception("disconnect_google failed: %s", e)
        return jsonify({"ok": False, "error": "internal error"}), 500



G_OAUTH_REVOKE = "https://oauth2.googleapis.com/revoke"

@app.route("/disconnect_gmail", methods=["POST"])
def disconnect_gmail():
    """
    Disconnect Gmail:
      - verifies Firebase ID token
      - finds user document (try uid then email)
      - optionally revoke refresh token from gmail_tokens
      - deletes gmail_tokens and sets gmail_connected False (keeps google_tokens intact)
    """
    try:
        auth_header = (request.headers.get("Authorization") or "").strip()
        if not auth_header.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Missing Authorization header"}), 401
        id_token = auth_header.split(" ", 1)[1].strip()

        decoded = firebase_auth.verify_id_token(id_token)
        uid = decoded.get("uid")
        email_from_token = decoded.get("email")

        # locate user doc (tries uid then email then fallback querying)
        user_ref = None
        if uid:
            cand = db.collection("users").document(uid)
            if cand.get().exists:
                user_ref = cand

        if user_ref is None and email_from_token:
            cand = db.collection("users").document(email_from_token)
            if cand.get().exists:
                user_ref = cand

        if user_ref is None:
            # last-resort query
            q = db.collection("users")
            if email_from_token:
                docs = list(q.where("email", "==", email_from_token).limit(1).stream())
                if docs:
                    user_ref = docs[0].reference
            if user_ref is None and uid:
                docs = list(db.collection("users").where("auth_uid", "==", uid).limit(1).stream())
                if docs:
                    user_ref = docs[0].reference

        if user_ref is None:
            logging.warning("disconnect_gmail: user doc not found for token uid=%s email=%s", uid, email_from_token)
            return jsonify({"ok": False, "error": "User not found (no matching user doc)"}), 404

        user_doc = user_ref.get()
        udata = user_doc.to_dict() or {}

        body = request.get_json(silent=True) or {}
        do_revoke = bool(body.get("revoke_refresh", True))

        # find refresh token candidates from gmail_tokens only
        refresh_token = None
        if isinstance(udata.get("gmail_tokens"), dict):
            refresh_token = udata["gmail_tokens"].get("refresh_token") or udata["gmail_tokens"].get("refresh")

        if do_revoke and refresh_token:
            try:
                resp = requests.post(G_OAUTH_REVOKE, params={"token": refresh_token}, timeout=8)
                if resp.status_code in (200, 204):
                    logging.info("Revoked gmail refresh token for user_doc=%s", user_ref.id)
                else:
                    logging.warning("Google revoke for gmail returned %s: %s", resp.status_code, resp.text[:300])
            except Exception:
                logging.exception("Failed to call Google revoke endpoint for gmail")

        # only delete gmail-specific fields, keep google_tokens (calendar) intact
        updates = {
            "gmail_tokens": firestore.DELETE_FIELD,
            "gmail_connected": False,
            "last_gmail_disconnect_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            user_ref.update(updates)
        except Exception:
            logging.exception("Failed to update user doc %s", user_ref.id)
            return jsonify({"ok": False, "error": "Failed to update user doc"}), 500

        logging.info("disconnect_gmail: completed for user_doc=%s", user_ref.id)
        return jsonify({"ok": True, "message": "Disconnected Gmail (tokens removed)"}), 200

    except firebase_auth.InvalidIdTokenError:
        return jsonify({"ok": False, "error": "Invalid ID token"}), 401
    except Exception as e:
        logging.exception("disconnect_gmail failed: %s", e)
        return jsonify({"ok": False, "error": "internal error"}), 500
    
    




def _extract_json_from_text(s: str) -> Optional[Dict[str, Any]]:
    if not s:
        return None
    s = s.strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    start = s.find('{')
    while start != -1:
        for end in range(len(s)-1, start, -1):
            if s[end] == '}':
                candidate = s[start:end+1]
                try:
                    return json.loads(candidate)
                except Exception:
                    continue
        start = s.find('{', start+1)
    return None

# ---------- Gemini wrapper (same as you had) ----------
def enhance_with_gemini_prebrief1(text: str, user_email: str, job_tag: str, meeting_id: str,
                                 regen_mode: str = "default", timeout: int = 60) -> dict:
    """
    Calls Gemini and requests a JSON-only prebrief. The regen_mode parameter
    drives subtle prompt variations (default/risks/short/probing).
    """
    headers = {"Content-Type": "application/json"}

    # safe normalisation of mode
    mode = (regen_mode or "default").lower()

    # Build a human-friendly mode instruction block
    mode_instructions = {
        "default": "Produce a balanced, neutral, professional pre-brief.",
        "risks": "Emphasize risks, concerns, blockers, potential failure points, security issues, and stakeholder impacts. Highlight what could go wrong and any urgent items.",
        "short": "Keep the entire output concise. Executive summary must be 1-2 sentences, and action items should be short fragments.",
        "probing": "Make the questions deeper and more probing — ask about assumptions, edge cases, unknowns, dependencies and things that expose uncertainty."
    }.get(mode, "Produce a balanced, neutral, professional pre-brief.")

    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": f"""
You are a meeting assistant. Analyze the context below and return ONLY a valid JSON object with these keys:
  - "executive_summary": short paragraph (2-3 sentences)
  - "action_items": array of up to 5 concise actionable items
  - "questions": array of exactly 5 smart questions

Style rule (apply exactly to the output):
{mode_instructions}

Context:
\"\"\"
{text}
\"\"\"

Return ONLY valid JSON (no markdown, no commentary). The top-level JSON must contain keys: executive_summary, action_items, questions.
"""
                    }
                ]
            }
        ]
    }

    params = {"key": GEMINI_API_KEY} if GEMINI_API_KEY else {}
    try:
        resp = requests.post(GEMINI_URL, headers=headers, params=params, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logging.exception("Gemini request failed for prebrief: %s", e)
        return {"executive_summary": f"Gemini request failed: {e}", "action_items": [], "questions": []}

    assistant_text = None
    try:
        assistant_text = data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        try:
            assistant_text = json.dumps(data)
        except Exception:
            assistant_text = str(data)

    parsed = _extract_json_from_text(assistant_text or "")
    if isinstance(parsed, dict):
        return {
            "executive_summary": parsed.get("executive_summary", "").strip(),
            "action_items": parsed.get("action_items") or [],
            "questions": parsed.get("questions") or []
        }
    else:
        return {
            "executive_summary": (assistant_text or "").strip(),
            "action_items": [],
            "questions": []
        }


# ---------- Build context helper (same pattern as before) ----------
def build_context_from_doc(doc_snapshot: Dict[str, Any]) -> str:
    data = dict(doc_snapshot)
    parts = []
    if data.get("title"):
        parts.append(f"Title: {data.get('title')}")
    if data.get("subject"):
        parts.append(f"Subject: {data.get('subject')}")
    if data.get("summary") or data.get("executive_summary"):
        parts.append("Existing summary:")
        parts.append(data.get("summary") or data.get("executive_summary"))
    if data.get("recent_snippets"):
        parts.append("Recent snippets:")
        parts.append("\n".join(data.get("recent_snippets")[:5]))
    if data.get("context_preview"):
        parts.append("Context preview:")
        parts.append(data.get("context_preview"))
    parts.append("Raw data snapshot:")
    parts.append(json.dumps(data, default=str)[:3000])
    return "\n\n".join(parts)


# ---------- New: decode Firebase ID token and return the token info ----------
def verify_firebase_token_from_header():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        abort(401, description="Authorization header missing or malformed")
    id_token = auth_header.split(" ", 1)[1].strip()
    try:
        decoded = firebase_auth.verify_id_token(id_token)
        # decoded contains: uid, email, email_verified, etc.
        return decoded
    except Exception as e:
        logging.exception("Failed to verify Firebase ID token: %s", e)
        abort(401, description="Invalid or expired Firebase ID token")


# ---------- Regenerate endpoint (now verifies ID token) ----------
@app.route("/api/regenerate_prebrief", methods=["POST"])
def regenerate_prebrief():
    # 1) Verify token and get identity
    token_info = verify_firebase_token_from_header()
    uid = token_info.get("uid")
    email = token_info.get("email")  # may be None if user has no email provider
    logging.info("Authenticated request for uid=%s email=%s", uid, email)

    # 2) parse payload
    payload = request.get_json(force=True)
    if not payload:
        return abort(400, description="Missing JSON payload")

    meeting_id = payload.get("meeting_id")
    regen_mode = payload.get("regen_mode", "default")
    job_tag = payload.get("job_tag", "regen")
    timeout = int(payload.get("timeout", 60))

    if not meeting_id:
        return abort(400, description="meeting_id required")

    # 3) Determine user key used in Firestore:
    # Prefer email if present (your screenshot uses email as doc id),
    # otherwise fallback to uid.
    user_key = email if email else uid
    if not user_key:
        return abort(400, description="Could not determine user key from token")

    # 4) locate the PreBrief document:
    doc_ref = db.collection("users").document(user_key).collection("PreBriefs").document(meeting_id)
    doc_snapshot = doc_ref.get()
    if not doc_snapshot.exists:
        # fallback: search by field meeting_id inside collection
        q = db.collection("users").document(user_key).collection("PreBriefs").where("meeting_id", "==", meeting_id).limit(1)
        results = list(q.stream())
        if not results:
            return abort(404, description="PreBrief document not found")
        doc_ref = results[0].reference
        doc_snapshot = results[0]

    data = doc_snapshot.to_dict() or {}

    # 5) build context and call Gemini
    context_text = build_context_from_doc(data)
    context_text += f"\n\nRegeneration mode: {regen_mode}"
    try:
        prebrief = enhance_with_gemini_prebrief1(context_text, user_key, job_tag, meeting_id, regen_mode, timeout=timeout)
    except Exception as e:
        logging.exception("Error calling Gemini wrapper: %s", e)
        return jsonify({"error": "gemini_call_failed", "details": str(e)}), 500

    # 6) persist prebrief into Firestore
        from datetime import datetime, timezone

    # Persist into Firestore under `prebrief` sub-object (use SERVER_TIMESTAMP)
    try:
        write_prebrief = {
            "executive_summary": prebrief.get("executive_summary", ""),
            "action_items": prebrief.get("action_items", []),
            "questions": prebrief.get("questions", []),
            "generated_at": firestore.SERVER_TIMESTAMP,  # server will set real timestamp
            "regen_mode": regen_mode
        }
        # write (merge so we don't clobber other top-level fields)
        doc_ref.set({"prebrief": write_prebrief}, merge=True)
    except Exception as e:
        logging.exception("Failed to write prebrief to Firestore: %s", e)
        return jsonify({"error": "firestore_write_failed", "details": str(e)}), 500

    # Read back the document so we can return JSON-serializable values
    try:
        fresh = doc_ref.get()
        fresh_data = fresh.to_dict() or {}
        fresh_pre = fresh_data.get("prebrief", {})

        # convert Firestore Timestamp to ISO string if present
        gen = fresh_pre.get("generated_at")
        if gen is not None:
            # Firestore Timestamp objects have a .to_datetime() method in the python client,
            # but there are a few types depending on versions — handle safely.
            try:
                # preferred: Firestore Timestamp -> datetime
                ts_dt = gen.to_datetime() if hasattr(gen, "to_datetime") else gen
            except Exception:
                # fallback: maybe it's already a python datetime
                ts_dt = gen

            try:
                # ensure timezone-aware ISO
                if isinstance(ts_dt, datetime):
                    if ts_dt.tzinfo is None:
                        ts_dt = ts_dt.replace(tzinfo=timezone.utc)
                    fresh_pre["generated_at"] = ts_dt.isoformat()
                else:
                    # last resort: string
                    fresh_pre["generated_at"] = str(ts_dt)
            except Exception:
                fresh_pre["generated_at"] = str(gen)
        else:
            # if missing, set our own timestamp string as fallback
            fresh_pre["generated_at"] = datetime.now(timezone.utc).isoformat()

        # ensure arrays exist
        fresh_pre["action_items"] = fresh_pre.get("action_items") or []
        fresh_pre["questions"] = fresh_pre.get("questions") or []

    except Exception as e:
        logging.exception("Failed to read back prebrief after write: %s", e)
        # still return best-effort payload (without generated_at)
        return jsonify({"ok": True, "prebrief": {
            "executive_summary": write_prebrief["executive_summary"],
            "action_items": write_prebrief["action_items"],
            "questions": write_prebrief["questions"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "regen_mode": regen_mode
        }})

    # Return the new prebrief to client (now JSON-serializable)
    return jsonify({"ok": True, "prebrief": fresh_pre})






# ---------------- ENTRY POINT ----------------
if __name__ == "__main__":
    app.run(port=10000, debug=True)

    