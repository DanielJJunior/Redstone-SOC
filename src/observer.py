import time
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from src.alert_engine import AlertEngine
from src.detection_engine import DetectionEngine
from src.file_analyzer import FileAnalyzer
from src.hash_engine import HashEngine
analyzer = FileAnalyzer()
detector = DetectionEngine()
hash_engine = HashEngine()
alert_engine = AlertEngine()
from src.utils import format_size

# ==========================================
# Initialize Analyzer
# ==========================================

analyzer = FileAnalyzer()
detector = DetectionEngine()

# ==========================================
# Banner
# ==========================================

def print_banner():
    print("\n========================================")
    print("⛏️  REDSTONE SOC")
    print("========================================")


# ==========================================
# Observer Block
# ==========================================

class ObserverBlock(FileSystemEventHandler):

    def on_created(self, event):

        # Ignore folders
        if event.is_directory:
            return

        # Analyze file
        info = analyzer.analyze(event.src_path)
        sha256 = hash_engine.calculate_sha256(event.src_path)
        result = detector.analyze(info)

        alert_file = alert_engine.generate_alert(
        info,
        result,
        sha256)
        # Current detection time
        detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Display
        print_banner()

        print("👀 Observer Block Activated!\n")

        print(f"🕒 Detection : {detection_time}")
        print(f"📄 Name      : {info['name']}")
        print(f"📂 Extension : {info['extension']}")
        print(f"📦 Size      : {format_size(info['size'])}")
        print(f"🔐 SHA256    : {sha256[:16]}...")
        print(f"📍 Path      : {info['path']}")
        print(f"🗓️ Created   : {info['created']}")
        print(f"🚨 Status    : {result['status']}")
        print(f"⚠️ Severity : {result['severity']}")
        print(f"📄 Alert     : {alert_file}")
        print(f"💬 Reason    : {result['reason']}")

        print("\n========================================\n")


# ==========================================
# Start Observer
# ==========================================

def start_observer(path):

    event_handler = ObserverBlock()

    observer = Observer()

    observer.schedule(
        event_handler,
        path,
        recursive=False
    )

    observer.start()

    print("🟢 Redstone Observer is running...")
    print(f"📁 Monitoring folder: {path}")
    print("⏳ Waiting for new files...\n")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Stopping Redstone SOC...")
        observer.stop()

    observer.join()