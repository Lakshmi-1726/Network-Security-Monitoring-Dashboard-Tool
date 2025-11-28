# Network Security Monitoring (Django)

## Overview
Web-based dashboard for monitoring simulated network events. Built with Django + SQLite.

## Requirements
- Python 3.8+
- pip
- Virtualenv (recommended)

## Setup
1. Create and activate a virtualenv:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate    # Windows
   ```

2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

3. Run migrations and create a superuser:
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

4. (Optional) Simulate sample events:
   ```bash
   python manage.py simulate_events --count 200
   ```

5. Run the development server:
   ```bash
   python manage.py runserver
   ```

6. Open http://127.0.0.1:8000/ and login or signup.
