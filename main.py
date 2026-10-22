"""
Main entry point for CTF & Bug Bounty Enumeration Tool
"""
import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ctf_tool.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import PyQt6
try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QIcon
    from ui.main_window import CTFEnumToolWindow
except ImportError as e:
    logger.error(f"PyQt6 not installed: {e}")
    print("Please install dependencies: pip install -r requirements.txt")
    sys.exit(1)


def main():
    """Main application entry point"""
    try:
        app = QApplication(sys.argv)
        
        # Create and show main window
        window = CTFEnumToolWindow()
        window.show()
        
        logger.info("Application started successfully")
        sys.exit(app.exec())
    
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        print(f"Error starting application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()