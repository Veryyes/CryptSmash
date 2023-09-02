from pathlib import Path
import io

import typer
from rich import print
from rich.progress import Progress
from rich.console import Console

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
        found_keys = set(key_in_nulls(f, size=size))
        console.log(f"Found {len(found_keys)} Candidate Keys")
        candidate_keys |= found_keys

        


def main():
    app()

if __name__ == "__main__":
    main()