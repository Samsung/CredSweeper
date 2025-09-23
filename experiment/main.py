import pathlib
import random
import subprocess
from argparse import ArgumentParser

import numpy as np
import torch

from train import train

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-d",
                        "--data",
                        nargs="?",
                        help="CredData location",
                        dest="cred_data_location",
                        metavar="PATH",
                        required=True)
    parser.add_argument("-j",
                        "--jobs",
                        help="number of parallel processes to use (default: 4)",
                        default=4,
                        dest="jobs",
                        metavar="POSITIVE_INT")
    parser.add_argument("-e",
                        "--epochs",
                        help="maximal epochs to train (default: 100)",
                        default=100,
                        dest="epochs",
                        metavar="POSITIVE_INT")
    parser.add_argument("-b",
                        "--batch_size",
                        help="batch size (default: 256)",
                        default=256,
                        dest="batch_size",
                        metavar="POSITIVE_INT")
    parser.add_argument("--device",
                        help="The device(CPU or GPU) that will be used to train the model",
                        default="cpu",
                        type=str,
                        choices=["cpu", "cuda"],
                        dest="device")
    parser.add_argument("-p",
                        "--patience",
                        help="early stopping patience (default: 5)",
                        default=5,
                        dest="patience",
                        metavar="POSITIVE_INT")
    parser.add_argument("--doc", help="use doc target", dest="doc_target", action="store_true")
    parser.add_argument("--tuner", help="use parameter tuner", dest="use_tuner", action="store_true")
    parser.add_argument("--eval-full",
                        help="evaluate model for full dataset after train",
                        dest="eval_full",
                        action="store_true")
    args = parser.parse_args()

    fixed_seed = 20250124
    print(f"Fixed seed:{fixed_seed}")
    np.random.seed(fixed_seed)
    random.seed(fixed_seed)
    torch.manual_seed(fixed_seed)

    command = f"md5sum {pathlib.Path(__file__).parent.parent}/credsweeper/ml_model/ml_config.json"
    subprocess.check_call(command, shell=True, cwd=pathlib.Path(__file__).parent)
    command = f"md5sum {pathlib.Path(__file__).parent.parent}/credsweeper/ml_model/ml_model.onnx"
    subprocess.check_call(command, shell=True, cwd=pathlib.Path(__file__).parent)

    _model_file_name = train(
        cred_data_location=args.cred_data_location,
        jobs=int(args.jobs),
        epochs=int(args.epochs),
        device=str(args.device),
        batch_size=int(args.batch_size),
        patience=int(args.patience),
        doc_target=bool(args.doc_target),
        use_tuner=bool(args.use_tuner),
        eval_full=bool(args.eval_full),
    )
    print(f"\nYou can find your model in:\n{_model_file_name}")
