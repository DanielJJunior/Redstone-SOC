def format_size(size):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]

    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024

    return f"{size:.2f} PB"