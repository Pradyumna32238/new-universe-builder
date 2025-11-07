You are an expert full-stack Python developer. 
Build a simple but expandable Flask web app called "Universe Builder" and prepare it for free deployment on Railway.

🔧 Requirements:
- Use Flask 3.x and Flask-SQLAlchemy.
- App lets users:
  1. Create fictional universes (title, description)
  2. Add characters linked to a universe (name, description)
  3. View universes and their characters
- Use SQLite for database (simple and portable)
- Use Jinja2 templates for HTML rendering.
- Include base.html, index.html, universe.html, and add_universe.html templates.
- Include a minimal CSS file in a static/ folder.
- Include a Procfile for Railway deployment using Gunicorn.
- Include a requirements.txt file listing Flask, Flask-SQLAlchemy, and Gunicorn.

💻 Flask Structure:
app.py
models.py
requirements.txt
Procfile
templates/
static/

📦 Deployment:
- App should run locally with `python app.py`
- Deploy with `gunicorn app:app` (for Railway)
- Ensure database initializes automatically with `db.create_all()`

🎨 Functionality:
- Homepage lists all universes
- Click universe → see details + characters
- “Add Universe” form to create new entries
- Basic navigation links

✅ Keep the code clean, modular, and commented.
✅ Make sure everything can run free on Railway with no paid dependencies.
✅ After generating the code, provide clear instructions for deploying to Railway.
