import logging
import os
from datetime import datetime

class TESLogger:
    LOG_FILE = "data/system.log"

    @staticmethod
    def setup():
        os.makedirs(os.path.dirname(TESLogger.LOG_FILE), exist_ok=True)
        logging.basicConfig(
            filename=TESLogger.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    @staticmethod
    def log(message, level="INFO"):
        if level == "INFO":
            logging.info(message)
        elif level == "ERROR":
            logging.error(message)
        elif level == "WARNING":
            logging.warning(message)
        
        # Also print to console
        print(f"[{level}] {message}")

    @staticmethod
    def get_recent_logs(n=20):
        if not os.path.exists(TESLogger.LOG_FILE):
            return []
        
        with open(TESLogger.LOG_FILE, 'r') as f:
            lines = f.readlines()
        
        # Parse lines to structured format if needed, but returning strings is fine for the UI
        return [line.strip() for line in lines[-n:]]
