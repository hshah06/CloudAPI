# ☁️ Cloud-Native User Management API

A fully containerized, production-ready user management REST API built with **Spring Boot**, **PostgreSQL**, **AWS S3**, and **Docker**, featuring robust authentication, file uploads, and CI/CD with **GitHub Actions**.

---

## 🚀 Features

- ✅ User registration, login, and JWT-based authentication
- 📦 Profile image upload & storage on AWS S3
- 🔐 Role-based access control (ADMIN, USER, MODERATOR)
- 🧾 PostgreSQL with JPA/Hibernate integration
- 📊 Actuator endpoints for health and metrics
- 🐳 Fully dockerized with Docker & Docker Compose
- 🔄 CI/CD pipeline using GitHub Actions
- ☁️ Deployable to AWS ECS (ECR setup included)

---

## 🧱 Tech Stack

- **Java 17 + Spring Boot 3**
- **PostgreSQL**
- **AWS S3**
- **Docker + Docker Compose**
- **GitHub Actions**
- **JWT for authentication**
- **Spring Security & Validation**

---

## 🛠️ Getting Started

### 🔧 Requirements

- Java 17
- Docker & Docker Compose
- PostgreSQL (optional if using Docker)
- AWS credentials (for S3 support)

### 📦 Local Setup

```bash
# Clone the repo
git clone https://github.com/yourusername/user-management-api.git
cd user-management-api

# Build and run with Docker
docker-compose up --build
