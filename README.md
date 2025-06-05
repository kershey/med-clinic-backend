# Appointment System Backend

A FastAPI-based backend for a medical clinic appointment system.

## Project Structure

The project follows a domain-driven design with the following structure:

```
backend-fastapi/
├── src/                      # Source code
│   ├── auth/                 # Authentication domain
│   ├── appointments/         # Appointments domain
│   ├── patients/             # Patients domain
│   ├── doctors/              # Doctors domain
│   ├── core/                 # Core utilities
│   ├── config.py             # Application configuration
│   ├── database.py           # Database connection
│   ├── exceptions.py         # Global exception handling
│   └── main.py               # Main application entry point
├── tests/                    # Test suite
├── alembic/                  # Database migrations
├── requirements/             # Requirements files
├── .env.example              # Environment variables template
├── docker-compose.yml        # Docker Compose configuration
├── Dockerfile                # Docker configuration
└── README.md                 # Project documentation
```

## Setup

### Prerequisites

- Python 3.9+
- PostgreSQL
- Docker (optional)

### Local Development

1. Clone the repository:

   ```
   git clone <repository-url>
   cd backend-fastapi
   ```

2. Create a virtual environment:

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:

   ```
   pip install -r requirements/dev.txt
   ```

4. Create a `.env` file based on `.env.example`:

   ```
   cp .env.example .env
   ```

5. Update the `.env` file with your configuration.

6. Run the application:
   ```
   uvicorn src.main:app --reload
   ```

### Docker Development

1. Clone the repository:

   ```
   git clone <repository-url>
   cd backend-fastapi
   ```

2. Create a `.env` file based on `.env.example`:

   ```
   cp .env.example .env
   ```

3. Update the `.env` file with your configuration.

4. Start the Docker containers:
   ```
   docker-compose up -d
   ```

## API Documentation

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Testing

Run tests with pytest:

```
pytest
```

For test coverage:

```
coverage run -m pytest
coverage report
```

## Database Migrations

Create a new migration:

```
alembic revision --autogenerate -m "Description of changes"
```

Apply migrations:

```
alembic upgrade head
```

## 🔍 Overview

Java Medical Clinic is a comprehensive web-based system for streamlining patient-doctor interactions through online appointment scheduling, medical record tracking, queue management, secure payment handling, and real-time updates.

This repository contains the backend API built with FastAPI and PostgreSQL.

## 🚀 Features

- User authentication with JWT tokens
- Email verification via fastapi-mail
- Role-based access control (patient, doctor, staff, admin)
- RESTful API endpoints
- PostgreSQL database with SQLAlchemy ORM
- Comprehensive error handling
- Fully typed with Pydantic schemas

## 🛠️ Tech Stack

- **FastAPI**: Modern, fast web framework for building APIs
- **PostgreSQL**: Relational database
- **SQLAlchemy**: SQL toolkit and ORM
- **Pydantic**: Data validation and settings management
- **JWT**: Token-based authentication
- **FastAPI-Mail**: Email sending functionality
- **Uvicorn**: ASGI server

## 📋 Prerequisites

- Python 3.9+
- PostgreSQL
- SMTP server access for email verification

## 🔧 Installation & Setup

1. **Clone the repository**

```bash
git clone https://github.com/your-username/java-medical-clinic-backend.git
cd java-medical-clinic-backend
```

2. **Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Create a .env file**

Create a `.env` file in the root directory with the following variables:

```
# Database Settings
DATABASE_URL=postgresql://postgres:password@localhost:5432/java_medical_clinic

# JWT Settings
SECRET_KEY=your_secret_key_here_min_32_chars
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Email Settings
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_password
MAIL_FROM=your_email@example.com
MAIL_PORT=587
MAIL_SERVER=smtp.example.com
MAIL_STARTTLS=True
MAIL_SSL_TLS=False
USE_CREDENTIALS=True
VALIDATE_CERTS=True

# Frontend URL
FRONTEND_URL=http://localhost:3000
```

5. **Create the database**

```bash
# Access PostgreSQL
psql -U postgres

# Create the database
CREATE DATABASE java_medical_clinic;
```

6. **Run the application**

```bash
uvicorn app.api.main:app --reload
```

The API will be available at http://localhost:8000

## 📚 API Documentation

Once the application is running, you can access:

- Interactive API documentation: http://localhost:8000/docs
- Alternative API documentation: http://localhost:8000/redoc

## 🧪 Testing

Run the tests with pytest:

```bash
pytest
```

## 📊 Project Structure

```
backend-fastapi/
├── app/
│   ├── api/
│   │   ├── auth/
│   │   │   ├── jwt.py         # JWT token handling
│   │   │   └── password.py    # Password hashing
│   │   ├── models/            # SQLAlchemy models
│   │   │   └── user.py        # User model
│   │   ├── routes/            # API routes
│   │   │   └── auth.py        # Authentication routes
│   │   ├── schemas/           # Pydantic schemas
│   │   │   └── user.py        # User schemas
│   │   ├── utils/             # Utility functions
│   │   │   └──        # Email sending utilities
│   │   ├── config.py          # Application settings
│   │   ├── database.py        # Database configuration
│   │   ├── deps.py            # Dependencies
│   │   └── main.py            # FastAPI application
├── tests/                     # Unit tests
├── .env                       # Environment variables
├── .gitignore                 # Git ignore file
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
```

## 📝 License

This project is licensed under the MIT License.

## 👥 Contributors

- Your Name (@your-github-username)
