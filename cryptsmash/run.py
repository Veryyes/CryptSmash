from pathlib import Path
import io
import os

import typer
from rich import print
from rich.progress import Progress
from rich.console import Console

from cryptsmash.utils import data_dir
from cryptsmash.xor import *

app = typer.Typer()
console = Console()

def input_file_checks(p:Path):
    if not p.exists():
        print("[red]{p} does not exist")
        return
    if not p.is_file():
        print("[red]{p} is must be a file")
        return

def f_size(f:IO):
    cur = f.tell()
    f.seek(0, io.SEEK_END)
    size = f.tell()
    f.seek(cur)

    return size


@app.command()
def xor(p: Path):
    input_file_checks(p)

    candidate_keys = set()

    with open(p, 'rb') as f:
        size = f_size(f)

        console.log("[bold green]Looking for XOR key in Plaintext NULL bytes")
        f.seek(0)
        candidate_keys |= set(key_in_nulls(f, size=size))
        console.log(f"Found {len(candidate_keys)} Total Candidate Keys")

        console.log("[bold green]XORing against File Headers")
        f.seek(0)
        headers = list()
        example_dir = os.path.join(data_dir(), "example_files")
        for filename in os.listdir(example_dir):
            filepath = os.path.join(example_dir, filename)
            with open(filepath, 'rb') as example_f:
                headers.append(example_f.read(2048))
        candidate_keys |= set(file_header_key_extract(f, headers))
        console.log(f"Found {len(candidate_keys)} Total Candidate Keys")

        

        console.log(f"Found {len(candidate_keys)} Number Of Keys.")
        print(sorted(candidate_keys, key=lambda x:len(x)))


def main():
    app()

if __name__ == "__main__":
    main()