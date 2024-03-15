from pathlib import Path
import json
import string

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

from cryptsmash import xor as _xor
from cryptsmash import baconian as _baconian
from cryptsmash import railfence as _railfence
from cryptsmash import affine as _affine
from cryptsmash import substitution as _substitution
from cryptsmash import vigenere as _vigenere
from cryptsmash.detect import identify

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
def auto(
    p:Annotated[Path, typer.Argument(help="File Path to the Encrypted File")]
):
    with open(p, 'rb') as f:
        ctxt = f.read()

    info = identify(ctxt)
    _type = info[0]
    params = info[1:]

    if _type == "Baconian":
        pass
    elif _type == "Polybus":
        pass
    elif _type == "XOR":
        pass
    elif _type == "Vigenere":
        pass
    elif _type == "Transposition/Monoalphabetic Subtitution":
        pass

@app.command()
def detect(
    p:Annotated[Path, typer.Argument(help="File Path to the Encrypted File")]
):
    with open(p, 'rb') as f:
        ctxt = f.read()

    print(identify(ctxt))

@app.command()
def stats(
    input:Annotated[Path, typer.Argument(help="File to Calculate the Byte Distribution of")], 
    n:Annotated[int, typer.Option("-n", help="Top N most frequent bytes")]=10,
    output:Annotated[Path, typer.Option("-o", "--output", help="Output Statisics to a file (JSON)")]=None,    graph:Annotated[bool, typer.Option("-g", "--graph", help="Graph the Distribution")]=False,
):
    input_file_checks(input)
        
    with console.status(f"Calculating Byte Distribution of {input}") as status:
        byte_distrib = dict()
        with open(input, 'rb') as f:
            data = f.read()

        prob = byte_prob(data)
        for i, value in enumerate(prob):
            byte_distrib[i] = value

        # TODO serialization
        bigrams = ngram_prob(data, 2)
        for k in list(bigrams.keys()):
            bigrams[str(k, 'latin1')] = bigrams[k]
            del bigrams[k]

    if output is not None:
        with open(output, 'w') as f:
            json_data = {
                'byte_distrib' : byte_distrib,
                'bigrams': bigrams
            }
            json.dump(json_data, f)

        console.log(f"Written to {output}")
    
    # Print Fancy byte_distrib
    top_n = sorted(byte_distrib.items(), key=lambda i:i[1], reverse=True)[:n]
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
def baconian(
    p:Annotated[Path, typer.Argument(help="File Path to the Encrypted File")],
    symbol1:Annotated[str, typer.Option("--s1", help="First Symbol to use in the Baconian Encoding")]='A',
    symbol2:Annotated[str, typer.Option("--s2", help="Second Symbol to use in the Baconian Encoding")]='B'
):
    with open(p, 'r') as f:
        ctxt = f.read()
        print(_baconian.decrypt(ctxt, symb1=symbol1, symb2=symbol2))

@app.command()
def railfence(
    p:Annotated[Path, typer.Argument(help="File Path to the Encrypted File")],
    top_percent:Annotated[int, typer.Option("-p", "--percent", help="Only show the top p percent of results")]=25
):
    with open(p, 'r') as f:
        ctxt = f.read()

    keys = _railfence.smash(ctxt)
    ks = KeyScorer(ctxt, _railfence.decrypt)
    ks.score(keys)

    ks.print(top_percent=top_percent)

@app.command()
def affine(
    p:Annotated[Path, typer.Argument(help="File Path to the Encrypted File")],
    alphabet:Annotated[str, typer.Option("-a", "--alphabet", help="The alphabet to use (defaults to lower case ascii)")]=string.ascii_lowercase,
    top_percent:Annotated[int, typer.Option("-p", "--percent", help="Only show the top p percent of results")]=25
):
    with open(p, 'r') as f:
        ctxt = f.read().lower()

    keys = _affine.smash(None, alphabet)
    ks = KeyScorer(ctxt, _affine.decrypt)
    ks.score(keys)

    ks.print(top_percent=top_percent)

@app.command()
def substitution(
    p:Annotated[Path, typer.Argument(help="File Path to the Encrypted File")],
    alphabet:Annotated[str, typer.Option("-a", "--alphabet", help="The alphabet to use (defaults to lower case ascii)")]=string.ascii_lowercase,
    top_percent:Annotated[int, typer.Option("-p", "--percent", help="Only show the top p percent of results")]=25,
    crib:Annotated[str , typer.Option("-c", "--crib", help="Known Mapping of letters in the substitution e.g. (\'-c a,z,b,y,c,x\' maps a->z, b->y, and c->x)")]=None,
    delimiter:Annotated[str, typer.Option("-d", "--delimiter", help="Specify a different delimiter for the crib (-c, --crib) option (Default: \",\")")]=",",
    verbose:Annotated[bool, typer.Option()]=True,
):
    with open(p, 'r') as f:
        ctxt = f.read()

    if crib is not None:
        known = dict()
        crib = crib.split(delimiter)
        for i in range(0, len(crib), 2):
            known[crib[i]] = crib[i+1]

        crib = known

    keys = _substitution.smash(ctxt, alphabet, crib, verbose=verbose)
    ks = KeyScorer(ctxt, _substitution.decrypt)
    ks.score(keys)

    ks.print(top_percent=top_percent)


@app.command()
def vigenere(
    p:Annotated[Path, typer.Argument(help="File Path to the Encrypted File")],
    alphabet:Annotated[str, typer.Option("-a", "--alphabet", help="The alphabet to use (defaults to lower case ascii)")]=string.ascii_lowercase,
    top_percent:Annotated[int, typer.Option("-p", "--percent", help="Only show the top p percent of results")]=25,
):
    with open(p, 'r') as f:
        ctxt = f.read()

    keys = _vigenere.smash(ctxt, alphabet)
    ks = KeyScorer(ctxt,  _vigenere.decrypt)
    ks.score(keys)

    ks.print(top_percent=top_percent)

@app.command()
def xor(
    p:Annotated[Path, typer.Argument(help="File Path to the XOR Encrypted File")],
    known_prefix:Annotated[str, typer.Option("-kp", '--known-prefix', help="Known Plaintext Prefix")]=None,
    verbose:Annotated[bool, typer.Option()]=True,
    top_percent:Annotated[int, typer.Option("-p", "--percent", help="Only show the top p percent of results")]=25
):
    with open(p, 'rb') as f:
        ctxt = f.read()

    keys, key_scores, key_prefix = _xor.smash(ctxt, known_prefix, verbose, console)

    
    def prefix_on_top(scores):
        best_score = max(scores, key=lambda s: s.score)
        for score in scores:
            if score.key.startswith(key_prefix):
                score.score += best_score.score
        return scores

    ks = KeyScorer(ctxt, _xor.decrypt)
    if key_prefix:
        ks.score(keys, key_scores, prefix_on_top)
    else:
        ks.score(keys, key_scores)

    ks.print(top_percent=top_percent)


def main():
    app()

if __name__ == "__main__":
    main()