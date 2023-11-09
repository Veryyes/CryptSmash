from pathlib import Path
import json
from multiprocessing import Pool

import typer
from typing_extensions import Annotated
from rich import print
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

from cryptsmash.utils import *
from cryptsmash.plaintext import *
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
    known_prefix:Annotated[str, typer.Option("-kp", '--known-prefix', help="Known Plaintext Prefix")]=None,
    decrypt:Annotated[bool, typer.Option(help="Attempt Decryption With All Keys")]=True,
    verbose:Annotated[bool, typer.Option()]=True
):
    with open(p, 'rb') as f:
        ranked_keys, key_prefix = xor_smash(f, known_prefix, verbose, console)

        if not decrypt:
            return

        f.seek(0)
        c_text = f.read()

    #############################################
    # Attempt Decryption with all Keys and Rank #
    #############################################
    table = Table(title="Plaintexts")
    table.add_column("Plain Text")
    table.add_column("Key")
    table.add_column("File Type")
    table.add_column("English Fitness Score")
    table.add_column("English Similarity Score")
    table.add_column("Printable Character %")
    table.add_column("Overall Score")

    results = list()
    with Pool() as p:
        with Progress() as progress:
            task_id = progress.add_task("Decrypting and Scoring...", total=len(ranked_keys))
            for result in p.imap(xor_fitness, ((key, key_score, c_text) for key, key_score in ranked_keys)):
                results.append(result)
                progress.advance(task_id)

    best_score = max(results, key=lambda x:x[6])
    
    # If a key starts with our found key_prefix, then push it up to the top of the list
    # i.e. rank it higher
    if key_prefix:
        for i in range(len(results)):
            if results[i][1].startswith(key_prefix):
                # results[i][6] += best_score[6]
                results[i] = (*results[i][:6], results[i][6] + best_score[6])

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


def main():
    app()

if __name__ == "__main__":
    main()