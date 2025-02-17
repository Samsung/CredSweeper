import hashlib
import os
import pathlib
import pickle
import random
import subprocess
from argparse import ArgumentParser
from datetime import datetime
from typing import List

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import f1_score, precision_score, recall_score, log_loss, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.utils import compute_class_weight

from experiment.plot import save_plot
from experiment.src.data_loader import read_detected_data, read_metadata, join_label, get_y_labels
from experiment.src.features import prepare_data
from experiment.src.lstm_model import MlModel
from experiment.src.model_config_preprocess import model_config_preprocess
from experiment.src.prepare_data import prepare_train_data, data_checksum


def evaluate_model(thresholds: dict,
                   model: nn.Module,
                   x_data: List[np.ndarray],
                   y_label: np.ndarray,
                   device,
                   batch_size=32):
    model.eval()
    predictions_proba = []

    dataset = TensorDataset(*[torch.tensor(x, dtype=torch.float32) for x in x_data])
    data_loader = DataLoader(dataset, batch_size=batch_size)

    with torch.no_grad():
        for batch in data_loader:
            x_tensors = [x.to(device) for x in batch]
            batch_preds = model(*x_tensors).cpu().numpy().ravel()
            predictions_proba.extend(batch_preds)

    predictions_proba = np.array(predictions_proba)

    for name, threshold in thresholds.items():
        predictions = (predictions_proba > threshold)
        accuracy = accuracy_score(y_label, predictions)
        precision = precision_score(y_label, predictions)
        recall = recall_score(y_label, predictions)
        loss = log_loss(y_label, predictions)
        f1 = f1_score(y_label, predictions)
        print(f"{name}: {threshold:0.6f}, "
              f"accuracy: {accuracy:0.6f}, "
              f"precision:{precision:0.6f}, "
              f"recall: {recall:0.6f}, "
              f"loss: {loss:0.6f}, "
              f"F1:{f1:0.6f}")


def main(cred_data_location: str,
         jobs: int,
         epochs: int,
         batch_size: int,
         patience: int,
         doc_target: bool,
         use_tuner: bool = False) -> str:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Use device: {device}")

    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")

    dir_path = pathlib.Path("results")
    os.makedirs(dir_path, exist_ok=True)

    print(f"Train model on data from {cred_data_location}")
    prepare_train_data(cred_data_location, jobs, doc_target)

    # detected data means which data is passed to ML validator of credsweeper after filters with RuleName
    cred_data_location_path = pathlib.Path(cred_data_location) / "data"
    detected_data = read_detected_data(f"results/detected_data.{data_checksum(cred_data_location_path)}.json")
    print(f"CredSweeper detected {len(detected_data)} credentials without ML")
    # all markup data
    meta_data = read_metadata(f"{cred_data_location}/meta")
    print(f"Metadata markup: {len(meta_data)} items")

    df_all = join_label(detected_data, meta_data, cred_data_location)
    # raise RuntimeError("TestDbg")
    # to prevent extra memory consumption - delete unnecessary objects
    del detected_data
    del meta_data

    # workaround for CI step
    for i in range(3):
        # there are 2 times possible fails due ml config was updated
        try:
            thresholds = model_config_preprocess(df_all, doc_target)
            break
        except RuntimeError as exc:
            if "RESTART:" in str(exc):
                continue
            else:
                raise
    else:
        raise RuntimeError("Something went wrong")

    print(f"Common dataset: {len(df_all)} items")
    df_all = df_all.drop_duplicates(subset=["line", "variable", "value", "path", "ext"])
    print(f"Common dataset: {len(df_all)} items after drop duplicates")

    # random split
    lucky_number = random.randint(1, 1 << 32)
    print(f"Lucky number: {lucky_number}")
    df_train, df_test = train_test_split(df_all, test_size=0.15, random_state=lucky_number)
    len_df_train = len(df_train)
    print(f"Train size: {len_df_train}")
    len_df_test = len(df_test)
    print(f"Test size: {len_df_test}")

    print(f"Prepare full data")
    x_full_line, x_full_variable, x_full_value, x_full_features = prepare_data(df_all)
    y_full = get_y_labels(df_all)
    del df_all

    print(f"Prepare train data")
    x_train_line, x_train_variable, x_train_value, x_train_features = prepare_data(df_train)
    print("x_train_value dtype ", x_train_value.dtype)  # dbg
    print("x_train_features dtype", x_train_features.dtype)  # dbg
    y_train = get_y_labels(df_train)
    print("y_train dtype", y_train.dtype)  # dbg
    del df_train

    print(f"Class-1 prop on train: {np.mean(y_train):.4f}")

    classes = np.unique(y_train)
    class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    max_weight = max(class_weights)
    class_weights = [weight / max_weight for weight in class_weights]
    print(f"y_train size:{len(y_train)}, 0: {np.count_nonzero(y_train == 0)}, 1: {np.count_nonzero(y_train == 1)}")
    class_weight = dict(zip(classes, class_weights))
    print(f"class_weight: {class_weight}")  # information about class weights

    print(f"Prepare test data")
    x_test_line, x_test_variable, x_test_value, x_test_features = prepare_data(df_test)
    y_test = get_y_labels(df_test)
    print(f"Class-1 prop on test: {np.mean(y_test):.4f}")
    del df_test

    hp_dict = {
        "value_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.41),
        "line_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.41),
        "variable_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.46),
        "dense_a_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.2),
        "dense_b_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.18),
    }
    history = {
        "loss": [],
        "val_loss": [],
        "accuracy": [],
        "val_accuracy": [],
        "precision": [],
        "val_precision": [],
        "recall": [],
        "val_recall": []
    }

    x_train = [x_train_line, x_train_variable, x_train_value, x_train_features]
    x_test = [x_test_line, x_test_variable, x_test_value, x_test_features]

    param_kwargs = {k: v[1] for k, v in hp_dict.items()}

    print(f"Model is trained with params from dict:{param_kwargs}")

    # repeat train step to obtain actual history chart
    ml_model = MlModel(x_full_line.shape, x_full_variable.shape, x_full_value.shape, x_full_features.shape,
                       param_kwargs).to(device)

    optimizer = optim.Adam(ml_model.parameters(), lr=0.001)
    criterion = nn.BCELoss()

    print(f"Create pytorch train and test datasets...")
    train_dataset = TensorDataset(*[torch.tensor(x, dtype=torch.float32) for x in x_train],
                                  torch.tensor(y_train, dtype=torch.float32))
    test_dataset = TensorDataset(*[torch.tensor(x, dtype=torch.float32) for x in x_test],
                                 torch.tensor(y_test, dtype=torch.float32))
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=2)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, num_workers=2)

    best_loss = float('inf')
    patience_counter = 0
    for epoch in range(epochs):
        ml_model.train()
        running_loss, correct, total = 0.0, 0, 0
        all_preds, all_labels = [], []
        for batch in train_loader:
            x_tensors = [x.to(device) for x in batch[:-1]]
            y_batch = batch[-1].to(device)
            optimizer.zero_grad()
            outputs = ml_model(*x_tensors).squeeze()
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
            correct += (outputs.round() == y_batch).sum().item()
            total += y_batch.numel()
            all_preds.extend(outputs.cpu().detach().numpy())
            all_labels.extend(y_batch.cpu().numpy())

        train_loss = running_loss / len(train_loader)
        train_acc = correct / total
        train_precision = precision_score(all_labels, np.array(all_preds) > 0.5, zero_division=0)
        train_recall = recall_score(all_labels, np.array(all_preds) > 0.5, zero_division=0)
        history["loss"].append(train_loss)
        history["accuracy"].append(train_acc)
        history["precision"].append(train_precision)
        history["recall"].append(train_recall)

        ml_model.eval()
        val_loss, correct, total = 0.0, 0, 0
        all_preds, all_labels = [], []
        with torch.no_grad():
            for batch in test_loader:
                x_tensors = [x.to(device) for x in batch[:-1]]
                y_batch = batch[-1].to(device)
                outputs = ml_model(*x_tensors).squeeze()
                loss = criterion(outputs, y_batch)
                val_loss += loss.item()
                correct += (outputs.round() == y_batch).sum().item()
                total += y_batch.numel()
                all_preds.extend(outputs.cpu().detach().numpy())
                all_labels.extend(y_batch.cpu().numpy())

        val_loss /= len(test_loader)
        val_acc = correct / total
        val_precision = precision_score(all_labels, np.array(all_preds) > 0.5, zero_division=0)
        val_recall = recall_score(all_labels, np.array(all_preds) > 0.5, zero_division=0)
        history["val_loss"].append(val_loss)
        history["val_accuracy"].append(val_acc)
        history["val_precision"].append(val_precision)
        history["val_recall"].append(val_recall)

        print(
            f"Epoch [{epoch+1}/{epochs}] - Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}, Acc: {train_acc:.4f}, Val Acc: {val_acc:.4f}, Prec: {train_precision:.4f}, Val Prec: {val_precision:.4f}, Rec: {train_recall:.4f}, Val Rec: {val_recall:.4f}"
        )

        if val_loss < best_loss:
            best_loss = val_loss
            print(f"New Lowest loss: {best_loss:.6f}")
            best_epoch = epoch + 1
            torch.save(ml_model.state_dict(), dir_path / f"{current_time}.best_model.pth")
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print("Early stopping triggered")
                break

    ml_model.load_state_dict(torch.load(dir_path / f"{current_time}.best_model.pth"))

    print(f"Validate results on the train subset. Size: {len(y_train)} {np.mean(y_train):.4f}")
    evaluate_model(thresholds, ml_model, [x_train_line, x_train_variable, x_train_value, x_train_features], y_train,
                   device, batch_size)
    del x_train_line
    del x_train_variable
    del x_train_value
    del x_train_features
    del y_train

    print(f"Validate results on the test subset. Size: {len(y_test)} {np.mean(y_test):.4f}")
    evaluate_model(thresholds, ml_model, [x_test_line, x_test_variable, x_test_value, x_test_features], y_test, device,
                   batch_size)
    del x_test_line
    del x_test_variable
    del x_test_value
    del x_test_features
    del y_test

    print(f"Validate results on the full set. Size: {len(y_full)} {np.mean(y_full):.4f}")
    evaluate_model(thresholds, ml_model, [x_full_line, x_full_variable, x_full_value, x_full_features], y_full, device,
                   batch_size)
    del x_full_line
    del x_full_variable
    del x_full_value
    del x_full_features
    del y_full

    onnx_model_file = pathlib.Path(__file__).parent.parent / "credsweeper" / "ml_model" / "ml_model.onnx"

    # Convert the model to onnx
    batch_idx = {0: "batch_size"}
    dynamic_axes = {
        "line_input": batch_idx,
        "variable_input": batch_idx,
        "value_input": batch_idx,
        "feature_input": batch_idx,
        "output": batch_idx,
    }

    x_tensors = tuple(torch.tensor([x[0]], dtype=torch.float32).to(device) for x in x_test)

    with torch.no_grad():
        torch.onnx.export(ml_model,
                          x_tensors,
                          onnx_model_file,
                          input_names=list(dynamic_axes.keys())[:4],
                          output_names=list(dynamic_axes.keys())[4:],
                          dynamic_axes=dynamic_axes)
        print(f"ONNX model export to {onnx_model_file}")

    del x_test
    del x_tensors

    with open(onnx_model_file, "rb") as f:
        onnx_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"ml_model.onnx:{onnx_md5}")

    with open(pathlib.Path(__file__).parent.parent / "credsweeper" / "ml_model" / "ml_config.json", "rb") as f:
        config_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"ml_config.json:{config_md5}")

    with open(dir_path / f"{current_time}.history.pickle", "wb") as f:
        pickle.dump(history, f)

    save_plot(stamp=current_time,
              title=f"batch:{batch_size} train:{len_df_train} test:{len_df_test} weights:{class_weights}",
              history=history,
              dir_path=dir_path,
              best_epoch=int(best_epoch),
              info=f"ml_config.json:{config_md5} ml_model.onnx:{onnx_md5} best_epoch:{best_epoch}")

    return str(onnx_model_file)


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
    parser.add_argument("-p",
                        "--patience",
                        help="early stopping patience (default: 5)",
                        default=5,
                        dest="patience",
                        metavar="POSITIVE_INT")
    parser.add_argument("--doc", help="use doc target", dest="doc_target", action="store_true")
    parser.add_argument("--tuner", help="use parameter tuner", dest="use_tuner", action="store_true")
    args = parser.parse_args()

    fixed_seed = 20250124
    print(f"Fixed seed:{fixed_seed}")
    np.random.seed(fixed_seed)
    random.seed(fixed_seed)

    # to keep the hash in log and verify
    command = f"md5sum {pathlib.Path(__file__).parent.parent}/credsweeper/ml_model/ml_config.json"
    subprocess.check_call(command, shell=True, cwd=pathlib.Path(__file__).parent)
    command = f"md5sum {pathlib.Path(__file__).parent.parent}/credsweeper/ml_model/ml_model.onnx"
    subprocess.check_call(command, shell=True, cwd=pathlib.Path(__file__).parent)

    print(args)  # dbg
    _model_file_name = main(cred_data_location=args.cred_data_location,
                            jobs=int(args.jobs),
                            epochs=int(args.epochs),
                            batch_size=int(args.batch_size),
                            patience=int(args.patience),
                            doc_target=bool(args.doc_target),
                            use_tuner=bool(args.use_tuner))
    # print in last line the name
    print(f"\nYou can find your model in:\n{_model_file_name}")
