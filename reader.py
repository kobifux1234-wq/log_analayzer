from pathlib import Path

def lists_for_file(path):
    file_log=Path(path)
    with open(file_log,'r')as f:
        return [row.split(',') for row in f]

def get_all_suspicious(file_path):
    pass




