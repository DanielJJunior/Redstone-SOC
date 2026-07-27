print('⛏️ Redstone SOC initialized successfully!')

from src.observer import start_observer

WATCH_FOLDER = "samples"

if __name__ == "__main__":

    start_observer(WATCH_FOLDER)