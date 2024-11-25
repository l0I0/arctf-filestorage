# FastAPI Secure File Storage System

A robust and secure file management system built with FastAPI, featuring JWT authentication, role-based access control, and secure file operations.

## 🚀 Features

- **Secure Authentication**
  - JWT-based authentication
  - HTTP-only cookie session management
  - Role-based access control (Admin/User)
  - OAuth2 scope-based authorization

- **File Management**
  - Secure file upload and storage
  - Per-user file management
  - File size and storage limits
  - Granular access control

- **Admin Features**
  - User management
  - Admin role assignment
  - System-wide file access
  - Storage monitoring

- **Security Features**
  - Password hashing with bcrypt
  - Secure token handling
  - File access verification
  - CORS protection

## 🛠️ Tech Stack

- **Backend**: FastAPI
- **Database**: PostgreSQL
- **Authentication**: JWT + OAuth2
- **Frontend**: Vue.js
- **Containerization**: Docker & Docker Compose

## 📋 Prerequisites

- Docker and Docker Compose
- Git

## 🔧 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd fastapi_jwt_auth
```

2. Build and start the containers:
```bash
docker-compose up --build
```

The application will be available at: http://localhost:8001

## 🔑 Initial Setup

An admin user will be automatically created on first startup with the following credentials:
- Username: admin
- Password: (check the logs for the generated password)

## 🌐 API Endpoints

### Authentication
- `POST /token` - Get authentication token
- `POST /register` - Register new user
- `POST /logout` - Logout user

### File Operations
- `POST /upload` - Upload file
- `GET /files` - List user's files
- `GET /download/{file_id}` - Download file
- `DELETE /files/{file_id}` - Delete file

### Admin Operations
- `GET /admin/users` - List all users
- `POST /admin/make-admin/{user_id}` - Make user an admin

## 🔒 Security Scopes

- `files:read` - Read access to files
- `files:write` - Upload and modify files
- `files:delete` - Delete files
- `admin` - Administrative access

## ⚙️ Configuration

Key configuration options in `app/core/config.py`:
- `MAX_FILE_SIZE`: Maximum file size (default: 1MB)
- `MAX_STORAGE_SIZE`: Maximum storage per user (default: 100MB)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Token expiration time (default: 30 minutes)

## 🐳 Docker Configuration

The application runs in three containers:
- `web`: FastAPI application
- `db`: PostgreSQL database
- `adminer`: Database management interface (available at http://localhost:8080)

## 📁 Project Structure

```
fastapi_jwt_auth/
├── app/
│   ├── api/
│   │   ├── auth.py
│   │   └── files.py
│   └── core/
│       ├── config.py
│       ├── security.py
│       └── deps.py
├── static/
├── templates/
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

## 🔐 Security Best Practices

- All passwords are hashed using bcrypt
- JWT tokens are stored in HTTP-only cookies
- File access is verified for each operation
- Admin operations require specific scopes
- CORS is configured for security

## 🧪 Testing

Run tests using:
```bash
docker-compose exec web pytest
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## 🐛 Known Issues

- None currently identified

## 📞 Support

For support, please open an issue in the GitHub repository.
