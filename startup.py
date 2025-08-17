#!/usr/bin/env python3
"""
Azure App Service Startup Script for Cyra AI
This script initializes the application for Azure deployment
"""

import os
import sys
import logging
from pathlib import Path

# Configure logging for Azure
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/home/LogFiles/application.log') if os.path.exists('/home/LogFiles') else logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def setup_azure_environment():
    """Configure Azure-specific environment settings"""
    
    # Set Azure environment variables
    os.environ.setdefault('AZURE_ENVIRONMENT', 'production')
    os.environ.setdefault('PORT', '8000')
    os.environ.setdefault('HOST', '0.0.0.0')
    
    # Database configuration for Azure
    if not os.environ.get('DATABASE_URL'):
        db_path = Path('/home/site/wwwroot/cyra_azure.db')
        os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'
    
    # Logging configuration
    os.environ.setdefault('LOG_LEVEL', 'INFO')
    
    # Security settings
    if not os.environ.get('SECRET_KEY'):
        logger.warning("SECRET_KEY not set - using default (CHANGE IN PRODUCTION)")
        os.environ['SECRET_KEY'] = 'azure-cyra-ai-production-key-change-this'
    
    # CORS settings for Azure
    os.environ.setdefault('CORS_ORIGINS', '*')
    
    logger.info("Azure environment configured successfully")

def create_required_directories():
    """Create necessary directories for Azure deployment"""
    
    directories = [
        '/home/site/wwwroot/logs',
        '/home/site/wwwroot/data',
        '/home/site/wwwroot/static',
        '/home/site/wwwroot/templates'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {directory}")

def initialize_database():
    """Initialize the database for Azure"""
    try:
        from app import init_db
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        # Don't fail startup if database init fails
        pass

def main():
    """Main startup function"""
    logger.info("Starting Cyra AI on Microsoft Azure...")
    
    try:
        # Setup Azure environment
        setup_azure_environment()
        
        # Create required directories
        create_required_directories()
        
        # Initialize database
        initialize_database()
        
        # Import and run the main application
        from app import app
        
        # Get port from Azure environment or default
        port = int(os.environ.get('PORT', 8000))
        host = os.environ.get('HOST', '0.0.0.0')
        
        logger.info(f"Cyra AI starting on {host}:{port}")
        logger.info("Azure deployment initialization complete")
        
        # For Azure App Service, we need to return the app object
        return app
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    app = main()
    
    # Run the application (for local testing)
    if os.environ.get('AZURE_ENVIRONMENT') != 'production':
        import uvicorn
        uvicorn.run(
            app, 
            host=os.environ.get('HOST', '0.0.0.0'),
            port=int(os.environ.get('PORT', 8000)),
            log_level=os.environ.get('LOG_LEVEL', 'info').lower()
        )
