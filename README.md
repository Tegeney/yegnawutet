# YegnaWutet - Ethiopian Student Management System

A comprehensive student management system designed for Ethiopian schools, featuring student authentication, grade management, and teacher-student communication.

## Features

- Student authentication with photo verification
- Grade management and reporting
- Teacher announcements
- Real-time chat between teachers and students
- Content access control
- Bilingual interface (Amharic/English)

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/yegnaWutet.git
cd yegnaWutet
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file with:
```
FLASK_SECRET_KEY=your_secret_key
ZYTE_API_KEY=your_zyte_api_key
DATABASE_URL=your_database_url  # Optional, defaults to SQLite
MASTER_PASSWORD=your_master_password  # For admin access
```

5. Initialize the database:
```bash
flask run
```

## Deployment

### Heroku Deployment
1. Create a Heroku account and install Heroku CLI
2. Login to Heroku:
```bash
heroku login
```

3. Create a new Heroku app:
```bash
heroku create your-app-name
```

4. Set environment variables:
```bash
heroku config:set FLASK_SECRET_KEY=your_secret_key
heroku config:set ZYTE_API_KEY=your_zyte_api_key
heroku config:set MASTER_PASSWORD=your_master_password
```

5. Deploy:
```bash
git push heroku main
```

### Other Platforms
The application can be deployed to any platform that supports Python/Flask applications. Key requirements:

- Python 3.8+
- PostgreSQL database (optional, defaults to SQLite)
- Environment variables configuration
- Static file serving capability

## Security Notes

1. Always change default passwords
2. Use strong secret keys
3. Configure proper database backup
4. Enable HTTPS in production
5. Keep dependencies updated

## License

This project is licensed under the MIT License - see the LICENSE file for details.
