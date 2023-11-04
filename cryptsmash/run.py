from pathlib import Path
import os
import json
from typing import Union, IO
from multiprocessing import Pool

import typer
from typing_extensions import Annotated
from rich import print
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import IPython

from cryptsmash.utils import *
from cryptsmash.plaintext import *
from cryptsmash.xor import *
from cryptsmash.xor import xor as xor_op

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
    known_prefix:Annotated[str, typer.Option("-kp", '--known-prefix', help="Known Plaintext Prefix")]=None,
    decrypt:Annotated[bool, typer.Option(help="Attempt Decryption With All Keys")]=True,
    verbose:Annotated[bool, typer.Option()]=True
):

    with open(p, 'rb') as f:
        # Get Key from Known Prefix if Avaliable
        prefix_key=None
        if known_prefix:
            known_prefix = bytes(known_prefix, 'ascii')
            prefix_key = xor_op(f.read(len(known_prefix)), known_prefix)
            f.seek(0)

        ##################
        # Guess Key Size #
        ##################
        if verbose:
            console.log("[bold green]Calculating Possible Key Lengths")
        top_keys_lens = detect_key_length(f, known_key_prefix=prefix_key, max_key_len=64, n=None, verbose=verbose)

        if verbose:    
            table = Table(title=f"Top 10 Most Probably Key Lengths")
            table.add_column("Key Length")
            table.add_column("Probability")
            for key_len, prob in top_keys_lens[:10]:
                table.add_row(str(key_len), "{:.2f}%".format(prob*100))
            print(table)

        ##########################
        # Handle Known Plaintext #
        ##########################
        key_prefix = None
        if known_prefix:
            
            f.seek(0)
            key_prefix, success = known_plaintext_prefix(f, known_prefix, top_keys_lens[:10])
            if success:
                # TODO prompt key, Ask user to continue digging
                keep_going = Prompt.ask(f"Found Key \"{key_prefix}\", Continue Analysis? (y/n)", choices=['y', 'n'], default='y')
                if keep_going == 'n':
                    console.log(key_prefix)
                    return
            # else:
            #     print(f"Found Partial Key: {key_prefix}")
        
    ranked_keys = _xor(p, top_keys_lens=top_keys_lens, verbose=verbose)

    if not decrypt:
        return

    #############################################
    # Attempt Decryption with all Keys and Rank #
    #############################################
    # All ASCII -> Good (But not Bad thing if it isnt)
    # Python Magic detects a non-data file -> Good
    # Language Score
    
    # if verbose:
        # Display Table
    table = Table(title="Plaintexts")
    table.add_column("Plain Text")
    table.add_column("Key")
    table.add_column("File Type")
    table.add_column("English Fitness Score")
    table.add_column("English Similarity Score")
    table.add_column("Printable Character %")
    table.add_column("Overall Score")

    with open(p, 'rb') as f:
        c_txt = f.read()

    results = list()
    with Pool() as p:
        with Progress() as progress:
            task_id = progress.add_task("Decrypting and Scoring...", total=len(ranked_keys))
            for result in p.imap(_xor_fitness, ((key, key_score, c_txt) for key, key_score in ranked_keys)):
                results.append(result)
                progress.advance(task_id)

    best_score = max(results, key=lambda x:x[6])
    
    # If a key starts with our found key_prefix, then push it up to the top of the list
    # i.e. rank it higher
    if key_prefix:
        for i in range(len(results)):
            if results[i][1].startswith(key_prefix):
                results[i][6] += best_score

    for i, res in enumerate(sorted(results, key=lambda x:x[6], reverse=True)):
        # Only show top 25 Percentile
        if i > len(results)//4:
            break

        table.add_row(
            repr(res[0][:24])[2:-1],
            repr(res[1])[2:-1],
            res[2][:16],
            "{:.2f}".format(res[3] * 1000),
            "{:.2f}".format(res[4]),
            "{:.2f}%".format(res[5]*100),
            "{:.2f}".format(res[6])
        )
    print(table)

def _xor_fitness(args):
    key, key_score, c_txt = args
    return fitness(key, key_score, c_txt, xor_op)
    

def _xor(p: Union[Path, IO], top_keys_lens, verbose=False):
    '''Tries to find the Key'''

    
    if isinstance(p, Path):
        input_file_checks(p)
        f = open(p, 'rb')
    else:
        f = p

    size = f_size(f)
    candidate_keys = set()

    ###################
    # All 1 Byte Keys #
    ###################
    if verbose:
        console.log("[bold green]Brute forcing all 1 Byte keys")
    candidate_keys |= set([int.to_bytes(x, length=1, byteorder='little') for x in range(255)])

    

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
    #     table = Table(title="Candidate Keys")
    #     table.add_column("Key (Bytes)")
    #     table.add_column("Score")
    #     for key, score in ranked_keys:
    #         table.add_row(repr(key), "{:2f}".format(score))
    #     print(table)

    if isinstance(p, Path):
        f.close()

    return ranked_keys


def main():
    app()

if __name__ == "__main__":
    main()