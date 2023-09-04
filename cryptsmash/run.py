from pathlib import Path
import os
import json
from typing import Union, IO

import typer
from typing_extensions import Annotated
from rich import print
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import IPython

from cryptsmash.utils import data_dir, byte_prob, f_size
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

@app.command()
def stats(
    input:Annotated[Path, typer.Argument(help="File to Calculate the Byte Distribution of")], 
    n:Annotated[int, typer.Option("-n", help="Top N most frequent bytes")]=10,
    output:Annotated[Path, typer.Option("-o", "--output", help="Output Statisics to a file (JSON)")]=None,    graph:Annotated[bool, typer.Option("-g", "--graph", help="Graph the Distribution")]=False,
):
    input_file_checks(input)
        
    with console.status(f"Calculating Byte Distribution of {input}") as status:
        freq_table = dict()
        with open(input, 'rb') as f:
            prob = byte_prob(f)
            for i, value in enumerate(prob):
                freq_table[i] = value

    if output is not None:
        with open(output, 'w') as f:
            json.dump(freq_table, f)

        console.log(f"Written to {output}")
    
    # Print Fancy freq_table
    top_n = sorted(freq_table.items(), key=lambda i:i[1], reverse=True)[:n]
    table = Table(title=f"{n} Most Frequent Bytes")
    table.add_column("Int")
    table.add_column("Hex")
    table.add_column("Frequency")
    table.add_column("Char")

    for byte, freq in top_n:
        if freq == 0:
            break
        table.add_row(str(byte), hex(byte), "{:.3f}".format(freq), chr(byte) if chr(byte).isprintable() else "")
    console.print(table)

    if graph:
        df = pd.DataFrame()
        df['x'] = list(range(256))
        df['w'] = list(prob)
        sns.histplot(df, x='x', weights='w', bins=256)
        plt.show()


@app.command()
def xor(
    p:Annotated[Path, typer.Argument(help="File Path to the XOR Encrypted File")],
    decrypt=False,
    verbose:Annotated[bool, typer.Option()]=True
):
    _xor(p, decrypt=decrypt, verbose=verbose)

def _xor(p: Union[Path, IO], decrypt=False, verbose=False):
    input_file_checks(p)

    candidate_keys = set()

    if isinstance(p, Path):
        f = open(p, 'rb')
    else:
        f = p

    size = f_size(f)

    ##################
    # Guess Key Size #
    ##################
    if verbose:
        console.log("[bold green] Calculating Possible Key Lengths")
    top_keys_lens = detect_key_length(f, max_key_len=64, n=None, verbose=verbose)

    if verbose:    
        table = Table(title=f"Top 10 Most Probably Key Lengths")
        table.add_column("Key Length")
        table.add_column("Probability")
        for key_len, prob in top_keys_lens[:10]:
            table.add_row(str(key_len), "{:.2f}%".format(prob*100))
        print(table)

    ####################
    # Check NULL Bytes #
    ####################
    if verbose:
        console.log("[bold green]Looking for XOR key in Plaintext NULL bytes")
    f.seek(0)
    candidate_keys |= set(key_in_nulls(f, size=size, verbose=verbose))
    if verbose:
        console.log(f"Found {len(candidate_keys)} Total Candidate Keys")

    ##########################################
    # Try File Headers as Partial Plain Text #
    ##########################################
    if verbose:
        console.log("[bold green]XORing against File Headers")
    f.seek(0)
    headers = list()
    example_dir = os.path.join(data_dir(), "example_files")
    for filename in os.listdir(example_dir):
        filepath = os.path.join(example_dir, filename)
        with open(filepath, 'rb') as example_f:
            headers.append(example_f.read(2048))
    candidate_keys |= set(file_header_key_extract(f, headers))
    if verbose:
        console.log(f"Found {len(candidate_keys)} Total Candidate Keys")

    ###################################
    # Language Frequency Based Attack #
    ###################################
    if verbose:
        console.log("[bold green]Statistical attack against English")
    f.seek(0)
    with open(os.path.join(data_dir(), "english_stats.json"), 'r') as sf:
        byte_distro = json.load(sf)
        # Nuance with Loading a Dict with Int as Keys
        for i in range(256):
            byte_distro[i] = byte_distro[str(i)]
            del byte_distro[str(i)]
        
        candidate_keys |= set(known_plaintext_statistical_attack(f, byte_distro))
    if verbose:
        console.log(f"Found {len(candidate_keys)} Total Candidate Keys")

    ##########################################
    # Rank Keys Based on Candidate Key Sizes #
    ##########################################
    key_weights = dict(top_keys_lens)
    ranked_keys = list()
    for key in candidate_keys:
        if len(key) in key_weights:
            ranked_keys.append((key, key_weights[len(key)]))

    ranked_keys = sorted(ranked_keys, key=lambda x:x[1], reverse=True)
    # if verbose:
    #     table = Table(title="Title Candidate Keys")
    #     table.add_column("Key (Bytes)")
    #     table.add_column("Score")
    #     for key, score in ranked_keys:
    #         table.add_row(repr(key), "{:2f}".format(score))
    #     print(table)

    if not decrypt:
        return

    #############################################
    # Attempt Decryption with all Keys and Rank #
    #############################################

def main():
    app()

if __name__ == "__main__":
    main()