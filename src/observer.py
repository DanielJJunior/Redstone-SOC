from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time


class ObserverBlock(FileSystemEventHandler):

    def on_created(self, event):

        if event.is_directory:
            return

        print("\n==============================")
        print("⛏️  Redstone SOC")
        print("==============================")
        print("👀 Observer Block detected a new file!")
        print(f"📄 File: {event.src_path}")
        print("==============================\n")


def start_observer(path):

    event_handler = ObserverBlock()

    observer = Observer()

    observer.schedule(event_handler, path, recursive=False)

    observer.start()

    print("🟢 Redstone Observer is running...")
    print(f"📁 Monitoring folder: {path}")

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()