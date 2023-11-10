from pathlib import Path
import json

import typer
from typing_extensions import Annotated
from rich import print
from rich.console import Console
from rich.table import Table
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

from cryptsmash.utils import *
from cryptsmash.plaintext import *
from cryptsmash.xor import xor_smash
from cryptsmash.xor import xor as xor_decrypt
from cryptsmash import baconian


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

# @app.command()
# def bacon(
#     p:Annotated[Path, typer.Argument(help="File Path to the Encrypted File")]
# ):
#     with open(p, 'r') as f:
#         plain = baconian.decrypt(f.read())
    

@app.command()
def xor(
    p:Annotated[Path, typer.Argument(help="File Path to the XOR Encrypted File")],
    known_prefix:Annotated[str, typer.Option("-kp", '--known-prefix', help="Known Plaintext Prefix")]=None,
    decrypt:Annotated[bool, typer.Option(help="Attempt Decryption With All Keys")]=True,
    verbose:Annotated[bool, typer.Option()]=True
):
    with open(p, 'rb') as f:
        keys, key_scores, key_prefix = xor_smash(f, known_prefix, verbose, console)

        if not decrypt:
            return

        f.seek(0)
        c_text = f.read()

    def prefix_on_top(scores):
        best_score = max(scores, key=lambda s: s.score)
        for score in scores:
            if score.key.startswith(key_prefix):
                score.score += best_score.score
        return scores

    ks = KeyScorer(c_text, xor_decrypt)
    if key_prefix:
        ks.score(keys, key_scores, prefix_on_top)
    else:
        ks.score(keys, key_scores)

    ks.print()


def main():
    app()

if __name__ == "__main__":
    main()