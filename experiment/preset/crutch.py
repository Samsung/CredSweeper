import itertools
import shutil
from pathlib import Path


def save(ext: str, scope: str, line: str, n: int):
    type_dir = Path("data")/ "00000000" / scope
    type_dir.mkdir(exist_ok=True,parents=True)
    with open(Path("data") / "00000000" / scope / f"00000000{ext}", "a") as f:
        f.write(f"{line}\n")
    with open(Path("meta") / "00000000.csv", "a") as f:
        f.write(f"{n},00000000,GitHub,00000000,"
                f"data/00000000/{scope}/00000000.{ext}"
                f",{n}:{n},F,F,,,F,F,,,,,0,0,F,F,F,Password\n")


def main():
    n = 1
    shutil.rmtree("data", ignore_errors=True)
    Path("data").mkdir()
    shutil.rmtree("meta", ignore_errors=True)
    Path("meta").mkdir()
    with open(Path("meta") / "00000000.csv", "w") as f:
        f.write("Id,FileID,Domain,RepoName,FilePath,LineStart:LineEnd,GroundTruth,WithWords,"
                "ValueStart,ValueEnd,InURL,InRuntimeParameter,CharacterSet,CryptographyKey,"
                "PredefinedPattern,VariableNameType,Entropy,Length,Base64Encode,HexEncode,URLEncode,Category\n")

    names = ["token", "password", "api", "secret", "key"]

    for x in names:
        line = f"{x}: impl AsRef<str>,"
        save(".rs", "src", line, n)
        n += 1
        line = f"let {x} = quote::quote! {{"
        save(".rs", "src", line, n)
        n += 1
        line = f"let {x} = x509_rx"
        save(".rs", "src", line, n)
        n += 1

    for x in itertools.combinations(names, 2):
        line = f"{x[0]}_{x[1]}: impl AsRef<str>,"
        save(".rs", "src", line, n)
        n += 1
        line = f"let {x[0]}_{x[1]} = quote::quote! {{"
        save(".rs", "src", line, n)
        n += 1
        line = f"let {x[0]}_{x[1]} = x509_rx"
        save(".rs", "src", line, n)
        n += 1


if __name__ == """__main__""":
    main()
