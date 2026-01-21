# 🚀 BriefDeck

**BriefDeck** is an intelligent meeting automation platform that records, transcribes, and summarizes your meetings using state-of-the-art AI. It seamlessly integrates with your Google Calendar to automatically join Zoom, Google Meet, and Microsoft Teams calls, providing you with actionable insights and follow-ups without you having to lift a finger.

---

## ✨ Key Features

- **📅 Automated Meeting Detection**: Monitors your Google Calendar and automatically schedules bots to join upcoming meetings.
- **🤖 Intelligent Bot Orchestration**: Uses the Attendee.dev API to deploy high-quality recording bots.
- **🎙️ AI Transcription**: Powered by Groq Whisper (Whisper-large-v3-turbo) for lightning-fast and accurate speech-to-text.
- **🧠 Generative Summarization**: Leverages Google's Gemini models to create concise executive summaries, extract action items, and identify key follow-ups.
- **📧 Gmail Integration**: (Optional) Connect your Gmail to fetch context and enhance meeting briefings.
- **📊 Meeting Library**: A centralized dashboard to manage your recordings, transcripts, and summaries.
- **💬 AI Chat**: Chat with your meeting documentation to quickly find answers or insights.

---

## 🛠️ Tech Stack

- **Backend**: Python, Flask
- **Database & Storage**: Firebase (Firestore, Storage)
- **AI/ML**: Google Gemini, Groq Whisper
- **Infrastructure**: Docker, Render (for deployment)
- **Integrations**: Google Calendar API, Gmail API, Attendee.dev

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Firebase Project with Firestore and Storage enabled
- Google Cloud Project with Calendar and Gmail APIs enabled
- Attendee.dev API Key
- Groq API Key
- Gemini API Key

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/briefdeck.git
   cd briefdeck
   ```

2. **Set up a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables**:
   Create an `aqa.env` file in the root directory and add the following:
   ```env
   SECRET_KEY=your_flask_secret_key
   FIREBASE_KEY='{"your_firebase_service_account_json": "..."}'
   STORAGE_BUCKET=your-app.firebasestorage.app
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   ATTENDEE_API_KEY=your_attendee_api_key
   GEMINI_API_KEY=your_gemini_api_key
   GROQ_API_KEY=your_groq_api_key
   ```

5. **Run the application**:
   ```bash
   python app.py
   ```

---

## 🏗️ Project Structure

- `app.py`: Main Flask application handling routes, webhooks, and core logic.
- `pages/`: HTML templates for the frontend.
- `assets/`: Static assets (CSS, JS, Images).
- `stt.py`: Speech-to-text utilities.
- `prebrief.py`: Logic for generating meeting pre-briefs.
- `google_calendar_server.py`: Helper script for calendar interactions.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
