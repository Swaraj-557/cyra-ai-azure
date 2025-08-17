"""
Cyra AI - Azure Production Server
Enterprise Cybersecurity Platform
Version: 4.0.0 - Azure Ready
"""

import asyncio
import json
import os
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import sqlite3
import uvicorn
from pathlib import Path

# Azure-specific configurations
AZURE_PORT = int(os.getenv('PORT', 8000))
AZURE_HOST = os.getenv('HOST', '0.0.0.0')
DEBUG_MODE = os.getenv('DEBUG', 'false').lower() == 'true'

# Logging configuration for Azure
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cyra_azure.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cyra AI - Enterprise Cybersecurity Platform",
    description="AI-Powered Cybersecurity Assistant for Enterprise",
    version="4.0.0",
    docs_url="/api/docs" if DEBUG_MODE else None,
    redoc_url="/api/redoc" if DEBUG_MODE else None
)

# CORS middleware for Azure
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Database setup
DB_PATH = "cyra_azure.db"

def init_database():
    """Initialize SQLite database for Azure deployment"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            company TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Chat history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT NOT NULL,
            response TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

# Pydantic models
class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    company: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ChatMessage(BaseModel):
    message: str

class PasswordRequest(BaseModel):
    length: Optional[int] = 16
    include_symbols: Optional[bool] = True

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self.disconnect(websocket)

manager = ConnectionManager()

# Utility functions
def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == hashed

def generate_session_token() -> str:
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def generate_secure_password(length: int = 16, include_symbols: bool = True) -> Dict[str, Any]:
    """Generate cryptographically secure password"""
    import string
    
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += "!@#$%^&*"
    
    password = ''.join(secrets.choice(chars) for _ in range(length))
    
    # Calculate strength
    strength_score = 0
    if any(c.islower() for c in password):
        strength_score += 1
    if any(c.isupper() for c in password):
        strength_score += 1
    if any(c.isdigit() for c in password):
        strength_score += 1
    if any(c in "!@#$%^&*" for c in password):
        strength_score += 1
    if length >= 16:
        strength_score += 1
    
    strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Excellent"]
    strength = strength_levels[min(strength_score, 4)]
    
    return {
        "password": password,
        "length": length,
        "strength": strength,
        "score": strength_score
    }

async def get_ai_response(message: str) -> str:
    """Generate AI response for cybersecurity queries"""
    message_lower = message.lower()
    
    # Cybersecurity-focused responses
    if any(word in message_lower for word in ['password', 'credential', 'authentication']):
        return """🔐 **Password Security Recommendations:**

• Use unique, complex passwords for each account
• Enable multi-factor authentication (MFA) wherever possible
• Consider using a password manager like 1Password or Bitwarden
• Regularly update passwords, especially for critical accounts
• Avoid using personal information in passwords

**Enterprise Best Practices:**
• Implement password policies with minimum complexity requirements
• Use Single Sign-On (SSO) solutions where possible
• Regular security awareness training for employees
• Monitor for credential breaches using tools like Have I Been Pwned"""

    elif any(word in message_lower for word in ['phishing', 'email', 'suspicious']):
        return """🎣 **Phishing Protection Guide:**

**Red Flags to Watch For:**
• Urgent or threatening language
• Requests for sensitive information
• Suspicious sender addresses
• Unexpected attachments or links
• Poor grammar and spelling

**Protection Strategies:**
• Verify sender identity through alternate channels
• Hover over links to check destinations
• Use email security solutions with advanced threat protection
• Implement DMARC, SPF, and DKIM records
• Regular phishing simulation training"""

    elif any(word in message_lower for word in ['malware', 'virus', 'trojan', 'ransomware']):
        return """🦠 **Malware Defense Strategy:**

**Immediate Actions:**
• Keep all software updated with latest security patches
• Use enterprise-grade antivirus with real-time protection
• Enable Windows Defender or equivalent on all endpoints
• Regular system backups to secure, offline locations

**Advanced Protection:**
• Implement endpoint detection and response (EDR) solutions
• Use application whitelisting where possible
• Network segmentation to limit malware spread
• Employee training on safe browsing and email practices
• Incident response plan for malware infections"""

    elif any(word in message_lower for word in ['network', 'firewall', 'intrusion']):
        return """🔥 **Network Security Essentials:**

**Firewall Configuration:**
• Enable and properly configure host-based firewalls
• Implement next-generation firewalls (NGFW) at network perimeter
• Regular rule reviews and optimization
• Log monitoring and analysis

**Network Protection:**
• Use VPN for remote access
• Implement network access control (NAC)
• Regular vulnerability scanning
• Intrusion detection and prevention systems (IDS/IPS)
• Network segmentation and zero-trust architecture"""

    elif any(word in message_lower for word in ['compliance', 'gdpr', 'hipaa', 'regulation']):
        return """📋 **Compliance Management:**

**Major Frameworks:**
• **GDPR**: Data protection for EU residents
• **HIPAA**: Healthcare information protection
• **SOX**: Financial reporting controls
• **PCI-DSS**: Payment card industry standards
• **ISO 27001**: Information security management

**Implementation Steps:**
• Conduct compliance gap analysis
• Implement required technical and administrative controls
• Regular compliance audits and assessments
• Staff training on compliance requirements
• Maintain proper documentation and evidence"""

    elif any(word in message_lower for word in ['incident', 'response', 'breach', 'emergency']):
        return """🚨 **Incident Response Framework:**

**Immediate Response (First 24 hours):**
1. **Identify** and contain the threat
2. **Isolate** affected systems
3. **Assess** the scope and impact
4. **Preserve** evidence for investigation
5. **Communicate** with stakeholders

**Recovery Process:**
• Eradicate the threat completely
• Restore systems from clean backups
• Implement additional monitoring
• Conduct post-incident review
• Update security measures based on lessons learned

**Preparation is Key:**
• Maintain an updated incident response plan
• Regular tabletop exercises
• 24/7 SOC monitoring capabilities"""

    elif any(word in message_lower for word in ['vulnerability', 'patch', 'update']):
        return """🔍 **Vulnerability Management:**

**Assessment Process:**
• Regular vulnerability scans (weekly/monthly)
• Penetration testing (quarterly/annually)
• Code security reviews for applications
• Third-party security assessments

**Patch Management:**
• Prioritize critical and high-severity patches
• Test patches in staging environment first
• Maintain patch deployment schedule
• Emergency patching procedures for zero-days

**Risk-Based Approach:**
• Focus on internet-facing and critical systems first
• Consider exploit availability and business impact
• Implement compensating controls when patching isn't immediate"""

    else:
        return f"""🛡️ **Cyra AI Enterprise Analysis**

I've analyzed your query: "{message}"

**General Cybersecurity Guidance:**
• Always follow the principle of least privilege
• Implement defense-in-depth strategies
• Regular security awareness training
• Maintain updated asset inventory
• Continuous monitoring and threat hunting

**Enterprise Recommendations:**
• Deploy Security Information and Event Management (SIEM)
• Implement Zero Trust architecture
• Regular security assessments and audits
• Incident response and business continuity planning
• Vendor risk management program

**Need Specific Help?** Ask me about:
• Password security and authentication
• Email security and phishing protection
• Malware defense strategies
• Network security and firewalls
• Compliance frameworks (GDPR, HIPAA, etc.)
• Incident response procedures
• Vulnerability management"""

# API Routes
@app.get("/", response_class=HTMLResponse)
async def get_homepage():
    """Serve the main enterprise interface"""
    try:
        with open("templates/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="""
        <html><head><title>Cyra AI - Loading...</title></head>
        <body style="background:#0f0f23;color:white;font-family:Arial;text-align:center;padding:100px;">
        <h1>🛡️ Cyra AI Enterprise</h1>
        <p>Deploying to Azure... Please wait.</p>
        <p>The application is starting up.</p>
        </body></html>
        """)

@app.post("/api/auth/register")
async def register_user(user: UserRegister):
    """Register new user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password and create user
        password_hash = hash_password(user.password)
        cursor.execute(
            "INSERT INTO users (name, email, password_hash, company) VALUES (?, ?, ?, ?)",
            (user.name, user.email, password_hash, user.company)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"New user registered: {user.email}")
        
        return {
            "success": True,
            "user": {
                "name": user.name,
                "email": user.email,
                "company": user.company,
                "avatar": user.name[0].upper()
            }
        }
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/auth/login")
async def login_user(user: UserLogin):
    """Login user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get user
        cursor.execute(
            "SELECT id, name, password_hash, company FROM users WHERE email = ? AND is_active = 1",
            (user.email,)
        )
        user_data = cursor.fetchone()
        
        if not user_data or not verify_password(user.password, user_data[2]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login
        cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_data[0],)
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"User logged in: {user.email}")
        
        return {
            "success": True,
            "user": {
                "name": user_data[1],
                "email": user.email,
                "company": user_data[3],
                "avatar": user_data[1][0].upper()
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.post("/api/chat")
async def chat_endpoint(chat: ChatMessage):
    """Chat with AI assistant"""
    try:
        response = await get_ai_response(chat.message)
        return {"response": response}
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return {"response": "I apologize, but I encountered an error. Please try again."}

@app.post("/api/password")
async def generate_password_endpoint(request: PasswordRequest = PasswordRequest()):
    """Generate secure password"""
    try:
        password_data = generate_secure_password(
            length=request.length,
            include_symbols=request.include_symbols
        )
        return password_data
    except Exception as e:
        logger.error(f"Password generation error: {e}")
        raise HTTPException(status_code=500, detail="Password generation failed")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time communication"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            # Get AI response
            response = await get_ai_response(message_data.get("message", ""))
            
            # Send response back
            await manager.send_personal_message(
                json.dumps({"response": response}),
                websocket
            )
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

@app.get("/api/health")
async def health_check():
    """Health check endpoint for Azure"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "4.0.0",
        "environment": "azure"
    }

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("Starting Cyra AI Azure Production Server v4.0.0")
    init_database()
    logger.info(f"Server starting on {AZURE_HOST}:{AZURE_PORT}")

# Mount static files
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except:
    logger.warning("Static directory not found, skipping mount")

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host=AZURE_HOST,
        port=AZURE_PORT,
        reload=DEBUG_MODE,
        log_level="info"
    )
