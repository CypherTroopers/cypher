from pathlib import Path

INCLUDE_SUFFIXES = {
    ".go", ".md", ".txt",
    ".toml", ".yaml", ".yml",
    ".json", ".sh", ".pdf",
    ".html", ".htm"
}

EXCLUDE_DIRS = {
    ".git", "vendor", "build", "bin", "out",
    "__pycache__", ".idea", ".vscode"
}

def wanted(path: Path) -> bool:
    if any(part in EXCLUDE_DIRS for part in path.parts):
        return False
    return path.is_file() and path.suffix.lower() in INCLUDE_SUFFIXES
