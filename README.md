# SlideForge

SlideForge is a Flask web app that generates PowerPoint presentations using OpenAI GPT-3.5 Turbo and DALL·E 3.

## Features
- Generate slide decks from a topic prompt
- Choose color theme and user tier (free/paid)
- Free users: up to 3 slides, preview only, watermark
- Paid users: up to 30 slides, export to PPTX, no watermark

## Setup
1. Clone the repo
2. Install dependencies: `pip install -r requirements.txt`
3. Create `.env` from `.env.example` and add your OpenAI API key
4. Run: `python app.py`

## Technologies
- Flask
- python-pptx
- openai
- requests
- python-dotenv
- Bootstrap

---

**Note:** This is a demo/freemium app. For production, add authentication and payment logic.
