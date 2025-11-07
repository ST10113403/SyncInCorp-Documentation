# Secure International Payments Portal
**Group Members:** Lungelo Duma, Mlondolozi Maphumulo , Minenhle Dladla.

A secure employee international payments portal built with React and Node.js, implementing industry-standard security practices to protect against common web vulnerabilities.

## Security Features

This application implements comprehensive security measures including:

- **Pre-created User Accounts**: No public registration to prevent unauthorized access
- **Password Security**: Bcrypt hashing with salting (10+ rounds) (Provos & Mazières, 1999)
- **Input Validation**: RegEx whitelisting for all user inputs (OWASP, 2021)
- **SSL/TLS Encryption**: All traffic served over HTTPS (Rescorla, 2018)
- **Attack Prevention**: Protection against SQL Injection, XSS, CSRF, DDoS, and Clickjacking (OWASP, 2021)
- **Continuous Security Scanning**: SonarQube integration via CircleCI (SonarSource, 2024)

## 📋 Table of Contents

- [Security Features](#-security-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Environment Configuration](#️-environment-configuration)
- [Running the Application](#-running-the-application)
- [Security Implementation](#-security-implementation)
- [CI/CD Pipeline](#-cicd-pipeline)
- [Testing](#-testing)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Changelog](#-changelog)
- [References](#references)


##  Prerequisites

Before you begin, ensure you have the following installed:

- Node.js (v18.x or higher) (OpenJS Foundation, 2024)
- npm or yarn
- MongoDB (v6.x or higher) (MongoDB Inc., 2024)
- Git
- SSL Certificate (for production) (Let's Encrypt, 2024)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/secure-payments-portal.git
cd secure-payments-portal
```

2. Install backend dependencies:
```bash
cd backend
npm install
```

3. Install frontend dependencies:
```bash
cd ../frontend
npm install
```

##  Environment Configuration

### Backend (.env)

Create a `.env` file in the `backend` directory:
```env
# Server Configuration
PORT=5000
NODE_ENV=production

# Database
MONGODB_URI=mongodb://localhost:27017/payments_db
DB_NAME=payments_portal

# Security
JWT_SECRET=your-super-secure-jwt-secret-key-min-256-bits
JWT_EXPIRY=1h
BCRYPT_ROUNDS=12

# SSL Certificates
SSL_KEY_PATH=/path/to/private-key.pem
SSL_CERT_PATH=/path/to/certificate.pem

# CORS
ALLOWED_ORIGINS=https://yourdomain.com

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX_REQUESTS=100
```

### Frontend (.env)

Create a `.env` file in the `frontend` directory:
```env
REACT_APP_API_URL=https://api.yourdomain.com
REACT_APP_ENVIRONMENT=production
```

## Running the Application

### Initial Setup (First Time Only)

Before running the application for the first time, complete these setup steps:

#### 1. Database Setup

Start MongoDB service:
```bash
# On Linux/macOS
sudo systemctl start mongod

# On Windows
net start MongoDB

# Or using Docker
docker run -d -p 27017:27017 --name mongodb mongo:6
```

Verify MongoDB is running:
```bash
mongosh --eval "db.version()"
```

#### 2. Create Initial Users

Since registration is disabled, create initial user accounts:
```bash
cd backend
npm run seed:users
```

Or create individual users:
```bash
node scripts/createUser.js --username admin --email admin@company.com --role admin
node scripts/createUser.js --username employee1 --email employee1@company.com --role employee
```

Default credentials (change immediately after first login):
- Username: `admin`
- Password: `Admin@123` (temporary password)

#### 3. SSL Certificate Setup

**For Development (Self-Signed Certificate):**
```bash
# Generate self-signed certificate
cd backend
mkdir -p ssl
openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes
```

**For Production:**

Use certificates from a trusted Certificate Authority (Let's Encrypt, 2024):
```bash
# Using Certbot for Let's Encrypt
sudo certbot certonly --standalone -d yourdomain.com
```

Update your `.env` file with certificate paths:
```env
SSL_KEY_PATH=/path/to/ssl/key.pem
SSL_CERT_PATH=/path/to/ssl/cert.pem
```

### Development Mode

#### Starting the Backend Server

1. Navigate to backend directory:
```bash
cd backend
```

2. Start development server with hot reload:
```bash
npm run dev
```

The backend server will start on `https://localhost:5000` (or configured PORT).

Expected output:
```
[INFO] Server starting...
[INFO] MongoDB connected successfully
[INFO] HTTPS Server running on port 5000
[INFO] Environment: development
```

#### Starting the Frontend Application

1. Open a new terminal window
2. Navigate to frontend directory:
```bash
cd frontend
```

3. Start React development server:
```bash
npm start
```

The application will automatically open in your browser at `http://localhost:3000` and will redirect to HTTPS.

Expected output:
```
Compiled successfully!

You can now view secure-payments-portal in the browser.

  Local:            http://localhost:3000
  On Your Network:  http://192.168.1.x:3000
```

#### Verifying the Application is Running

1. Open your browser to `https://localhost:3000`
2. Accept the self-signed certificate warning (development only)
3. You should see the login page
4. Login with credentials created during setup

### Production Mode

#### Backend Production Deployment

1. Navigate to backend directory:
```bash
cd backend
```

2. Build the application:
```bash
npm run build
```

3. Start the production server:
```bash
NODE_ENV=production npm start
```

For production deployment, use a process manager like PM2 (Unitech, 2024):
```bash
# Install PM2 globally
npm install -g pm2

# Start with PM2
pm2 start server.js --name "payment-portal-api"

# Configure PM2 to start on system boot
pm2 startup
pm2 save
```

Monitor the application:
```bash
pm2 status
pm2 logs payment-portal-api
pm2 monit
```

#### Frontend Production Deployment

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Create production build:
```bash
npm run build
```

This creates an optimized production build in the `build/` directory.

3. Serve the production build:

**Option A: Using serve package:**
```bash
npm install -g serve
serve -s build -l 3000
```

**Option B: Using nginx (recommended):**

Create nginx configuration file `/etc/nginx/sites-available/payment-portal`:
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/key.pem;
    ssl_protocols TLSv1.3 TLSv1.2;

    root /path/to/frontend/build;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass https://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Enable and restart nginx:
```bash
sudo ln -s /etc/nginx/sites-available/payment-portal /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Running with Docker (Alternative)

For containerized deployment:

#### 1. Build Docker Images
```bash
# Build backend image
cd backend
docker build -t payment-portal-backend .

# Build frontend image
cd ../frontend
docker build -t payment-portal-frontend .
```

#### 2. Run with Docker Compose

Create `docker-compose.yml` in project root:
```yaml
version: '3.8'

services:
  mongodb:
    image: mongo:6
    container_name: payment-portal-db
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db
    environment:
      - MONGO_INITDB_DATABASE=payments_portal

  backend:
    image: payment-portal-backend
    container_name: payment-portal-api
    ports:
      - "5000:5000"
    depends_on:
      - mongodb
    environment:
      - MONGODB_URI=mongodb://mongodb:27017/payments_db
      - NODE_ENV=production
    volumes:
      - ./backend/ssl:/app/ssl

  frontend:
    image: payment-portal-frontend
    container_name: payment-portal-web
    ports:
      - "3000:3000"
    depends_on:
      - backend
    environment:
      - REACT_APP_API_URL=https://localhost:5000

volumes:
  mongodb_data:
```

Start all services:
```bash
docker-compose up -d
```

Check service status:
```bash
docker-compose ps
docker-compose logs -f
```

### Troubleshooting Common Issues

#### Port Already in Use

If you get `EADDRINUSE` error:
```bash
# Find process using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or use different port in .env
PORT=5001
```

#### MongoDB Connection Failed
```bash
# Check MongoDB status
sudo systemctl status mongod

# Check MongoDB logs
sudo tail -f /var/log/mongodb/mongod.log

# Restart MongoDB
sudo systemctl restart mongod
```

#### SSL Certificate Errors in Development

For development, you can bypass SSL verification (not recommended for production):
```bash
# Set environment variable
export NODE_TLS_REJECT_UNAUTHORIZED=0

# Or in .env
NODE_TLS_REJECT_UNAUTHORIZED=0
```

#### Module Not Found Errors

Clear npm cache and reinstall:
```bash
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
```

### Health Checks

Verify all services are running correctly:
```bash
# Check backend health
curl -k https://localhost:5000/health

# Check frontend
curl http://localhost:3000

# Check MongoDB
mongosh --eval "db.adminCommand('ping')"
```

### Stopping the Application

**Development:**
- Press `Ctrl+C` in each terminal window running the servers

**Production with PM2:**
```bash
pm2 stop payment-portal-api
pm2 delete payment-portal-api
```

**Docker:**
```bash
docker-compose down
# To also remove volumes:
docker-compose down -v
```

## Security Implementation

### 1. User Management (No Registration)

Users must be created via admin scripts or direct database seeding to prevent unauthorized account creation and maintain strict access control (NIST, 2017):
```bash
cd backend
npm run seed:users
```

Administrators can create users with:
```javascript
node scripts/createUser.js --username employee123 --email employee@company.com
```

### 2. Password Security

Following NIST Digital Identity Guidelines (NIST, 2017) and industry best practices (Provos & Mazières, 1999):

- **Hashing**: Bcrypt with configurable salt rounds (default: 12)
- **Validation**: Minimum 8 characters, uppercase, lowercase, number, and special character
- **Storage**: Only hashed passwords stored in database
```javascript
// Example implementation
const hashedPassword = await bcrypt.hash(password, 12);
```

Bcrypt is preferred over other algorithms due to its adaptive nature and built-in protection against brute-force attacks (Provos & Mazières, 1999).

### 3. Input Whitelisting with RegEx

All inputs are validated using strict RegEx patterns to prevent injection attacks (OWASP, 2021). Input validation should follow a whitelist approach rather than blacklist to ensure only known-good data is accepted (OWASP, 2017):

| Field | Pattern | Description |
|-------|---------|-------------|
| Username | `^[a-zA-Z0-9_]{3,20}$` | Alphanumeric and underscore, 3-20 chars |
| Email | `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` | Valid email format |
| Account Number | `^[0-9]{10,12}$` | 10-12 digit numbers only |
| Amount | `^\d+(\.\d{1,2})?$` | Valid currency format |
| SWIFT Code | `^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$` | Valid SWIFT format (ISO 9362, 2022) |

### 4. SSL/TLS Configuration

The application enforces HTTPS in production following industry standards (Rescorla, 2018). TLS 1.3 is recommended as the minimum version for enhanced security (IETF, 2018):
```javascript
// Backend SSL setup
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync(process.env.SSL_KEY_PATH),
  cert: fs.readFileSync(process.env.SSL_CERT_PATH),
  minVersion: 'TLSv1.3' // Following IETF RFC 8446
};

https.createServer(options, app).listen(PORT);
```

Frontend redirects all HTTP to HTTPS in production builds. HTTP Strict Transport Security (HSTS) headers are implemented to prevent protocol downgrade attacks (Hodges et al., 2012).

### 5. Attack Prevention

#### SQL Injection
Following OWASP guidelines for injection prevention (OWASP, 2021):
- MongoDB parameterized queries
- Input sanitization with validator.js (Validator Contributors, 2024)
- NoSQL injection prevention with strict type checking

#### Cross-Site Scripting (XSS)
Implementation follows OWASP XSS Prevention Cheat Sheet (OWASP, 2023):
- Content Security Policy (CSP) headers (W3C, 2023)
- DOMPurify for sanitizing HTML (Heiderich et al., 2024)
- React's built-in XSS protection (Meta Platforms Inc., 2024)
- `dangerouslySetInnerHTML` avoided

#### Cross-Site Request Forgery (CSRF)
Protection mechanisms as recommended by OWASP (OWASP, 2021):
- CSRF tokens for state-changing operations
- SameSite cookie attributes (West, 2016)
- Origin header validation
- Double Submit Cookie pattern

#### DDoS Protection
Rate limiting implementation following best practices (NGINX Inc., 2023):
- Express rate limiting middleware
- Request throttling per IP address
- Timeout configurations
- Connection limits

#### Clickjacking
Prevention following OWASP recommendations (OWASP, 2021):
- X-Frame-Options: DENY header (Ross & Gondrom, 2013)
- Content-Security-Policy frame-ancestors directive (W3C, 2023)

**Security Headers Implementation:**
```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      frameAncestors: ["'none'"]
    }
  },
  xFrameOptions: { action: 'deny' }
}));
```

Helmet.js is used to set secure HTTP headers automatically (Helmetjs Contributors, 2024).

## CI/CD Pipeline

### CircleCI Configuration

The project includes automated security scanning with SonarQube following DevSecOps principles (NIST, 2022):
```yaml
# .circleci/config.yml
version: 2.1

orbs:
  sonarcloud: sonarsource/sonarcloud@1.1.1

jobs:
  build-and-test:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      - run: npm install
      - run: npm test
      - run: npm run lint
      
  sonarqube-scan:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      - sonarcloud/scan

workflows:
  main:
    jobs:
      - build-and-test
      - sonarqube-scan:
          requires:
            - build-and-test
```

### SonarQube Setup

SonarQube provides continuous inspection of code quality and security vulnerabilities (SonarSource, 2024):

1. Create a `sonar-project.properties` file:
```properties
sonar.projectKey=secure-payments-portal
sonar.organization=your-org
sonar.sources=src
sonar.exclusions=**/*.test.js,**/node_modules/**
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.coverage.exclusions=**/*.test.js
```

2. Configure CircleCI environment variables:
   - `SONAR_TOKEN`: Your SonarQube authentication token
   - `SONAR_HOST_URL`: Your SonarQube instance URL

3. View security hotspots and code smells in the SonarQube dashboard

Code smells, bugs, and security vulnerabilities are automatically detected based on industry standards and OWASP guidelines (SonarSource, 2024).

##  Testing

### Run Unit Tests
```bash
npm test
```

### Run Integration Tests
```bash
npm run test:integration
```

### Run Security Tests
```bash
npm run test:security
```

Security testing should include OWASP ZAP scanning and dependency vulnerability checks (OWASP, 2024).

### Generate Coverage Report
```bash
npm run test:coverage
```

## API Documentation

### Authentication Endpoints

**POST /api/auth/login**

Implements JWT authentication following RFC 7519 (Jones et al., 2015):
```json
{
  "username": "employee123",
  "password": "SecurePass123!"
}
```

Response:
```json
{
  "token": "jwt-token-here",
  "user": {
    "id": "user-id",
    "username": "employee123",
    "email": "employee@company.com"
  }
}
```

### Payment Endpoints

**POST /api/payments**

All financial data is validated against international standards (ISO 9362, 2022):
```json
{
  "recipientName": "John Doe",
  "accountNumber": "1234567890",
  "swiftCode": "ABCDUS33XXX",
  "amount": 1000.50,
  "currency": "USD"
}
```

**GET /api/payments**

Returns all payments for authenticated user (requires valid JWT token).

**GET /api/payments/:id**

Returns specific payment details with authorization check.

## Project Structure
```
secure-payments-portal/
├── backend/
│   ├── src/
│   │   ├── config/          # Configuration files
│   │   ├── controllers/     # Route controllers
│   │   ├── middleware/      # Authentication, validation
│   │   ├── models/          # Database models
│   │   ├── routes/          # API routes
│   │   ├── utils/           # Helper functions
│   │   └── validators/      # RegEx input validators
│   ├── scripts/             # Admin scripts
│   ├── tests/               # Test files
│   ├── .env.example         # Environment template
│   └── server.js            # Entry point
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── contexts/        # React contexts
│   │   ├── hooks/           # Custom hooks
│   │   ├── pages/           # Page components
│   │   ├── services/        # API services
│   │   ├── utils/           # Helper functions
│   │   └── validators/      # Input validation
│   └── .env.example
├── .circleci/
│   └── config.yml           # CI/CD configuration
├── sonar-project.properties # SonarQube config
└── README.md
```

## Additional Resources

- Github Link : 
- YouTube :


---

## Changelog

---

# In the Second Part of Developing Our International Payments System

## Features Not Fully Implemented

### Securing Data in Transit with SSL (Partially Implemented)

**Issue:** Although valid SSL certificates were generated for the frontend, the Node.js backend was initially not properly configured for SSL.

**Improvement:** Secure HTTPS communication was enforced throughout the project by implementing SSL/TLS configuration for the backend.

---

### Protection Against Attacks (Critically Deficient)

**Issue:** Important security features and safeguards, such as rate limitation, brute force defense, and secure API endpoints, were absent from the application.

**Improvement:** Introduced comprehensive middleware for security, such as Helmet.js for header configuration, Express Rate Limit and Express Brute for brute force protection, and strict CORS policies to enforce security.

---

### Password Security (Not Implemented)

**Issue:** There were no measures in place for securely handling passwords, including hashing, salting, or encryption.

**Improvement:** Implemented password hashing and salting using bcrypt, along with encryption before API transmission. Added password complexity requirements for enhanced security.

---

### Input Whitelisting (Partially Implemented)

**Issue:** Basic regex validation for input sanitization existed but was incomplete. There were gaps in protection against NoSQL injection and XSS attacks.

**Improvement:** Enhanced input validation by using express-validator, implemented mongo-sanitize for NoSQL injection protection, and added DOMPurify for XSS prevention.

---

### DevSecOps Pipeline (Not Implemented)

**Issue:** No CI/CD pipeline or security testing automation is in place.

**Improvement:** Implemented a CircleCI pipeline with automated security scanning, vulnerability testing (npm audit, Snyk), code linting (ESLint), and automated deployment processes.

---

## Improvements and Implementations

### SSL/TLS Implementation for Node.js Backend

**Changes Made:**

* Generated SSL certificates and configured the Node.js backend to support HTTPS communication using the `https` module.
* Enforced TLS 1.2+ as the minimum protocol version.
* Updated all frontend API calls to secure `https://` endpoints.
* Added proper certificate validation.

**Files Modified:**

* `server.js`: Configured the HTTPS server.
* `config/ssl.js`: New file to manage SSL certificates.
* `.env`: Added paths to SSL certificates.

---

### API Creation and Security Hardening

**Changes Made:**

* Developed a RESTful API layer using Express.js, including key endpoints like user registration, authentication, and profile management.
* Secured API endpoints with:

  * Helmet.js for security headers
  * Express Rate Limit and Express Brute for brute-force and rate-limiting protection
  * CORS for strict origin policy enforcement
  * Express Validator for input validation

**Files Created:**

* `routes/auth.js`, `routes/users.js`: User authentication and management routes.
* `middleware/security.js`: Security middleware.
* `middleware/rateLimiter.js`: Rate limiting configuration.

---

### Password Security Implementation

**Changes Made:**

* Implemented bcrypt for password hashing (work factor: 12) and added unique salt generation for each password.
* Encrypted passwords before API transmission using the crypto module.
* Applied password complexity rules: minimum 8 characters, at least one uppercase letter, one lowercase letter, one number, and one special character.
* Stored only hashed passwords in MongoDB for secure storage.

**Files Modified:**

* `utils/encryption.js`: Added encryption utilities.
* `utils/passwordHash.js`: Bcrypt password hashing.
* `models/User.js`: Updated schema to include password hashing hooks.
* `controllers/authController.js`: Updated authentication logic.

---

### Input Sanitization and Injection Protection

**Changes Made:**

* Enhanced frontend input validation using improved regex patterns.
* Applied server-side validation with express-validator.
* Added mongo-sanitize for preventing NoSQL injection.
* Used DOMPurify to sanitize user inputs and prevent XSS attacks.
* Parameterized MongoDB queries to mitigate injection risks.

**Protection Against:**

* SQL/NoSQL Injection
* Cross-Site Scripting (XSS)
* Command Injection
* Path Traversal
* LDAP Injection

**Files Modified:**

* `middleware/validation.js`: Input validation middleware.
* `utils/sanitize.js`: Input sanitization utilities.
* Controller files: Updated with sanitization logic.

---

### DevSecOps Pipeline Implementation (CircleCI)

**Changes Made:**

* Configured a CircleCI pipeline to automate testing and deployment, integrated with the project's GitHub repository.
* Integrated automated security scanning with tools such as npm audit (for dependency vulnerabilities), Snyk (for advanced security testing), and ESLint (for code quality and security linting).
* Added stages for testing, building, and deployment:

  * Code checkout
  * Dependency installation
  * Security scans
  * Unit and integration tests
  * Deployment to staging
  * Automated security tests
  * Deployment to production (on approval)

**Files Created:**

* `.github/workflows/security-pipeline.yml`: Main CircleCI configuration.
* `.github/workflows/dependency-scan.yml`: Scheduled dependency checks.
* `tests/security/`: Security test suite directory.

---

### Repository Cleanup

* Removed sensitive files from git history.
* Added comprehensive `.gitignore` to exclude unnecessary files.
* Removed unused dependencies.
* Organized the project structure for better maintainability.
* Updated documentation to reflect new security measures.

---

## References

CERT. (2022). *SEI CERT Coding Standards*. Software Engineering Institute, Carnegie Mellon University. Available at: https://wiki.sei.cmu.edu/confluence/display/seccode

Heiderich, M., Frosch, T., Holz, T., & Schwenk, J. (2024). *DOMPurify: A DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG*. GitHub. Available at: https://github.com/cure53/DOMPurify

Helmetjs Contributors. (2024). *Helmet: Help secure Express apps with various HTTP headers*. GitHub. Available at: https://helmetjs.github.io/

Hodges, J., Jackson, C., & Barth, A. (2012). *RFC 6797: HTTP Strict Transport Security (HSTS)*. Internet Engineering Task Force (IETF). Available at: https://tools.ietf.org/html/rfc6797

IETF. (2018). *RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3*. Internet Engineering Task Force. Available at: https://tools.ietf.org/html/rfc8446

ISO 9362. (2022). *Banking — Banking telecommunication messages — Business identifier code (BIC)*. International Organization for Standardization. Available at: https://www.iso.org/standard/60390.html

Jones, M., Bradley, J., & Sakimura, N. (2015). *RFC 7519: JSON Web Token (JWT)*. Internet Engineering Task Force (IETF). Available at: https://tools.ietf.org/html/rfc7519

Let's Encrypt. (2024). *Let's Encrypt: Free SSL/TLS Certificates*. Internet Security Research Group. Available at: https://letsencrypt.org/

Meta Platforms Inc. (2024). *React Documentation: Security*. Meta Open Source. Available at: https://react.dev/

MongoDB Inc. (2024). *MongoDB Documentation*. MongoDB Inc. Available at: https://docs.mongodb.com/

NGINX Inc. (2023). *Rate Limiting with NGINX and NGINX Plus*. F5 Networks Inc. Available at: https://www.nginx.com/blog/rate-limiting-nginx/

NIST. (2017). *NIST Special Publication 800-63B: Digital Identity Guidelines - Authentication and Lifecycle Management*. National Institute of Standards and Technology. Available at: https://doi.org/10.6028/NIST.SP.800-63b

NIST. (2022). *Secure Software Development Framework (SSDF) Version 1.1*. National Institute of Standards and Technology. Available at: https://doi.org/10.6028/NIST.CSWP.04232020

OpenJS Foundation. (2024). *Node.js Documentation*. OpenJS Foundation. Available at: https://nodejs.org/en/docs/

OWASP. (2017). *Input Validation Cheat Sheet*. Open Web Application Security Project. Available at: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

OWASP. (2021). *OWASP Top 10:2021*. Open Web Application Security Project. Available at: https://owasp.org/Top10/

OWASP. (2023). *Cross Site Scripting Prevention Cheat Sheet*. Open Web Application Security Project. Available at: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

OWASP. (2024). *OWASP ZAP: Zed Attack Proxy*. Open Web Application Security Project. Available at: https://www.zaproxy.org/

Provos, N., & Mazières, D. (1999). *A Future-Adaptable Password Scheme*. Proceedings of the 1999 USENIX Annual Technical Conference, pp. 81-91. Available at: https://www.usenix.org/legacy/events/usenix99/provos/provos.pdf

Rescorla, E. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*. RFC 8446, Internet Engineering Task Force (IETF). Available at: https://tools.ietf.org/html/rfc8446

Ross, D., & Gondrom, T. (2013). *RFC 7034: HTTP Header Field X-Frame-Options*. Internet Engineering Task Force (IETF). Available at: https://tools.ietf.org/html/rfc7034

SonarSource. (2024). *SonarQube Documentation: Continuous Code Quality and Security*. SonarSource S.A. Available at: https://docs.sonarqube.org/latest/

Unitech. (2024). *PM2 - Advanced Process Manager for Production Node.js Applications*. Available at: https://pm2.keymetrics.io/

Validator Contributors. (2024). *validator.js: A library of string validators and sanitizers*. GitHub. Available at: https://github.com/validatorjs/validator.js

W3C. (2023). *Content Security Policy Level 3*. World Wide Web Consortium. Available at: https://www.w3.org/TR/CSP3/

West, M. (2016). *Same-Site Cookies (draft-west-first-party-cookies-07)*. Internet Engineering Task Force. Available at: https://tools.ietf.org/html/draft-west-first-party-cookies-07

---









