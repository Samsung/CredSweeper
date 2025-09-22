import hashlib
import os
import pathlib
import pickle
import random
import subprocess
from argparse import ArgumentParser
from datetime import datetime
from typing import List, Dict

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import f1_score, precision_score, recall_score, log_loss, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.utils import compute_class_weight
import optuna
from optuna.samplers import GridSampler
from optuna.pruners import NopPruner

from plot import save_plot
from src.ml_model import MlModel
from src.data_loader import read_detected_data, read_metadata, join_label, get_y_labels
from src.features import prepare_data
from src.model_config_preprocess import model_config_preprocess
from src.prepare_data import prepare_train_data, data_checksum

GPU_SAMPLE_LIMIT = 1024
DEFAULT_LEARNING_RATE = 0.0005


def objective(trial, train_loader: DataLoader, test_loader: DataLoader, model_inputs_size: List[tuple],
              hp: Dict[str, tuple]):
    best_val_loss = trial.study.user_attrs["best_val_loss"]
    epochs = trial.study.user_attrs["epochs"]
    device = trial.study.user_attrs["device"]
    best_model_path = trial.study.user_attrs["best_model_path"]
    params = {}
    for param_name, ((low, high, step), default) in hp.items():
        params[param_name] = trial.suggest_float(param_name, low, high, step=step)

    model = MlModel(*model_inputs_size, params).to(device)
    optimizer = optim.Adam(model.parameters(), lr=DEFAULT_LEARNING_RATE)
    criterion = nn.BCELoss()

    best_loss = float('inf')
    patience_counter = 0

    if device.type == "cuda" and GPU_SAMPLE_LIMIT < train_loader.batch_size:
        accumulation_steps = (train_loader.batch_size + GPU_SAMPLE_LIMIT - 1) // GPU_SAMPLE_LIMIT
    else:
        accumulation_steps = 1

    for epoch in range(epochs):
        model.train()
        for batch in train_loader:
            x_tensors = [x.to(device) for x in batch[:-1]]
            y_batch = batch[-1].to(device)
            batch_size = y_batch.shape[0]
            sub_batch_size = max(1, batch_size // accumulation_steps)
            optimizer.zero_grad()
            for i in range(accumulation_steps):
                start = i * sub_batch_size
                end = (i + 1) * sub_batch_size if i < accumulation_steps - 1 else batch_size
                inputs_sub = [tens[start:end] for tens in x_tensors]
                labels_sub = y_batch[start:end]
                outputs = model(*inputs_sub).squeeze()
                loss = criterion(outputs, labels_sub) / accumulation_steps
                loss.backward()
            optimizer.step()

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for batch in test_loader:
                x_tensors = [x.to(device) for x in batch[:-1]]
                y_batch = batch[-1].to(device)
                batch_size = y_batch.shape[0]
                sub_batch_size = max(1, batch_size // accumulation_steps)
                for i in range(accumulation_steps):
                    start = i * sub_batch_size
                    end = (i + 1) * sub_batch_size if i < accumulation_steps - 1 else batch_size
                    inputs_sub = [tens[start:end] for tens in x_tensors]
                    labels_sub = y_batch[start:end]
                    outputs = model(*inputs_sub).squeeze()
                    loss = criterion(outputs, labels_sub) / accumulation_steps
                    val_loss += loss.item()
        val_loss /= len(test_loader)
        trial.report(val_loss, epoch)
        if val_loss < best_loss:
            best_loss = val_loss
            patience_counter = 0
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                trial.study.set_user_attr("best_val_loss", best_val_loss)
                torch.save(model.state_dict(), best_model_path)
        else:
            patience_counter += 1
        if patience_counter >= 5:
            break
        if trial.should_prune():
            raise optuna.TrialPruned()

    return best_loss


def evaluate_model(thresholds: dict,
                   model: torch.nn.Module,
                   x_data: List[np.ndarray],
                   y_label: np.ndarray,
                   device,
                   batch_size=256):
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
         device: str,
         patience: int,
         doc_target: bool,
         use_tuner: bool = False) -> str:
    if device == "cpu":
        device = torch.device("cpu")
    elif device == "cuda" and torch.cuda.is_available():
        device = torch.device("cuda")
    else:
        raise ValueError(f"Device {device} not supported or not available")

    print(f"Use device: {device}")
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")

    dir_path = pathlib.Path("results")
    os.makedirs(dir_path, exist_ok=True)

    print(f"Train model on data from {cred_data_location}")
    prepare_train_data(cred_data_location, jobs, doc_target)

    cred_data_location_path = pathlib.Path(cred_data_location) / "data"
    detected_data = read_detected_data(f"results/detected_data.{data_checksum(cred_data_location_path)}.json")
    print(f"CredSweeper detected {len(detected_data)} credentials without ML")
    meta_data = read_metadata(f"{cred_data_location}/meta")
    print(f"Metadata markup: {len(meta_data)} items")

    df_all = join_label(detected_data, meta_data, cred_data_location)
    del detected_data
    del meta_data

    for i in range(3):
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
    print("x_train_value dtype ", x_train_value.dtype)
    print("x_train_features dtype", x_train_features.dtype)
    y_train = get_y_labels(df_train)
    print("y_train dtype", y_train.dtype)
    del df_train

    print(f"Class-1 prop on train: {np.mean(y_train):.4f}")
    classes = np.unique(y_train)
    class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    max_weight = max(class_weights)
    class_weights = [weight / max_weight for weight in class_weights]
    print(f"y_train size:{len(y_train)}, 0: {np.count_nonzero(y_train == 0)}, 1: {np.count_nonzero(y_train == 1)}")
    class_weight = dict(zip(classes, class_weights))
    print(f"class_weight: {class_weight}")

    print(f"Prepare test data")
    x_test_line, x_test_variable, x_test_value, x_test_features = prepare_data(df_test)
    y_test = get_y_labels(df_test)
    print(f"Class-1 prop on test: {np.mean(y_test):.4f}")
    del df_test

    hp_dict = {
        "value_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.41),
        "line_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.3),
        "variable_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.31),
        "dense_a_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.45),
        "dense_b_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.3),
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
    x_full = [x_full_line, x_full_variable, x_full_value, x_full_features]

    print(f"Create pytorch train and test datasets...")
    train_dataset = TensorDataset(*[torch.tensor(x, dtype=torch.float32) for x in x_train],
                                  torch.tensor(y_train, dtype=torch.float32))
    test_dataset = TensorDataset(*[torch.tensor(x, dtype=torch.float32) for x in x_test],
                                 torch.tensor(y_test, dtype=torch.float32))
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=2)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, num_workers=2)

    inputs_size = [x_full_line.shape, x_full_variable.shape, x_full_value.shape, x_full_features.shape]

    if use_tuner:
        print(f"Start model train with optimization")
        search_space = {}
        for param_name, ((low, high, step), default) in hp_dict.items():
            search_space[param_name] = list(np.arange(low, high + step, step))
        study = optuna.create_study(sampler=GridSampler(search_space), pruner=NopPruner(), direction="minimize")
        study.set_user_attr("best_val_loss", float("inf"))
        study.set_user_attr("epochs", epochs)
        study.set_user_attr("device", device)
        study.set_user_attr("best_model_path", str(dir_path / f"{current_time}.trials.best_model.pth"))
        study.optimize(lambda trial: objective(trial, train_loader, test_loader, inputs_size, hp_dict), n_trials=10)
        param_kwargs = study.best_params
        print(f"Best hyperparameters: {param_kwargs}")
        df_trials = study.trials_dataframe()
        df_trials.to_csv(dir_path / f"{current_time}_trials_df.csv", sep=';')
    else:
        param_kwargs = {param_name: default for param_name, ((low, high, step), default) in hp_dict.items()}

    print(f"Model will be trained using the following params:{param_kwargs}")
    ml_model = MlModel(*inputs_size, param_kwargs).to(device)
    optimizer = optim.Adam(ml_model.parameters(), lr=DEFAULT_LEARNING_RATE)
    criterion = nn.BCELoss()

    best_loss = float('inf')
    best_epoch = 1
    patience_counter = 0

    if device.type == "cuda" and GPU_SAMPLE_LIMIT < batch_size:
        accumulation_steps = (batch_size + GPU_SAMPLE_LIMIT - 1) // GPU_SAMPLE_LIMIT
    else:
        accumulation_steps = 1

    for epoch in range(epochs):
        ml_model.train()
        running_loss, correct, total = 0.0, 0, 0
        all_preds, all_labels = [], []
        for b_idx, batch in enumerate(train_loader, start=1):
            x_tensors = [x.to(device) for x in batch[:-1]]
            y_batch = batch[-1].to(device)
            optimizer.zero_grad()
            bs = y_batch.shape[0]
            sub_bs = max(1, bs // accumulation_steps)
            preds_collect = []
            for i in range(accumulation_steps):
                s = i * sub_bs
                e = (i + 1) * sub_bs if i < accumulation_steps - 1 else bs
                inputs_sub = [t[s:e] for t in x_tensors]
                labels_sub = y_batch[s:e]
                outputs = ml_model(*inputs_sub).squeeze()
                preds_collect.append(outputs.detach())
                loss = criterion(outputs, labels_sub) / accumulation_steps
                running_loss += loss.item()
                loss.backward()
            optimizer.step()
            batch_outputs = torch.cat(preds_collect, dim=0)
            correct += (batch_outputs.round() == y_batch).sum().item()
            total += y_batch.numel()
            all_preds.extend(batch_outputs.cpu().numpy())
            all_labels.extend(y_batch.cpu().numpy())
            iter_acc = (batch_outputs.round() == y_batch).float().mean().item()
            iter_prec = precision_score(y_batch.cpu().numpy(), (batch_outputs.cpu().numpy() > 0.5), zero_division=0)
            iter_rec = recall_score(y_batch.cpu().numpy(), (batch_outputs.cpu().numpy() > 0.5), zero_division=0)
            print(f"iter {epoch+1}.{b_idx} loss:{running_loss/b_idx:.4f} acc:{iter_acc:.4f} prec:{iter_prec:.4f} rec:{iter_rec:.4f}")

        train_loss = running_loss / len(train_loader)
        train_acc = correct / total
        train_prec = precision_score(all_labels, np.array(all_preds) > 0.5, zero_division=0)
        train_rec = recall_score(all_labels, np.array(all_preds) > 0.5, zero_division=0)
        history["loss"].append(train_loss)
        history["accuracy"].append(train_acc)
        history["precision"].append(train_prec)
        history["recall"].append(train_rec)

        ml_model.eval()
        val_loss, correct, total = 0.0, 0, 0
        all_preds, all_labels = [], []
        with torch.no_grad():
            for batch in test_loader:
                x_tensors = [x.to(device) for x in batch[:-1]]
                y_batch = batch[-1].to(device)
                bs = y_batch.shape[0]
                sub_bs = max(1, bs // accumulation_steps)
                preds_collect = []
                for i in range(accumulation_steps):
                    s = i * sub_bs
                    e = (i + 1) * sub_bs if i < accumulation_steps - 1 else bs
                    inputs_sub = [t[s:e] for t in x_tensors]
                    labels_sub = y_batch[s:e]
                    outputs = ml_model(*inputs_sub).squeeze()
                    preds_collect.append(outputs.detach())
                    loss = criterion(outputs, labels_sub) / accumulation_steps
                    val_loss += loss.item()
                val_outputs = torch.cat(preds_collect, dim=0)
                correct += (val_outputs.round() == y_batch).sum().item()
                total += y_batch.numel()
                all_preds.extend(val_outputs.cpu().numpy())
                all_labels.extend(y_batch.cpu().numpy())

        val_loss /= len(test_loader)
        val_acc = correct / total
        val_prec = precision_score(all_labels, np.array(all_preds) > 0.5, zero_division=0)
        val_rec = recall_score(all_labels, np.array(all_preds) > 0.5, zero_division=0)
        history["val_loss"].append(val_loss)
        history["val_accuracy"].append(val_acc)
        history["val_precision"].append(val_prec)
        history["val_recall"].append(val_rec)

        print(f"Epoch [{epoch+1}/{epochs}]:")
        print(f"\tTrain - Loss: {train_loss:.4f}, Acc: {train_acc:.4f}, Prec: {train_prec:.4f}, Rec: {train_rec:.4f}")
        print(f"\tValidation - Loss: {val_loss:.4f}, Acc: {val_acc:.4f}, Prec: {val_prec:.4f}, Rec: {val_rec:.4f}")

        if val_loss < best_loss:
            best_loss = val_loss
            best_epoch = epoch + 1
            torch.save(ml_model.state_dict(), dir_path / f"{current_time}.best_model.pth")
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print("Early stopping triggered")
                break

    ml_model.load_state_dict(torch.load(dir_path / f"{current_time}.best_model.pth", map_location=device))

    print(f"Validate results on the train subset. Size: {len(y_train)} {np.mean(y_train):.4f}")
    evaluate_model(thresholds, ml_model, x_train, y_train, device, batch_size)

    print(f"Validate results on the test subset. Size: {len(y_test)} {np.mean(y_test):.4f}")
    evaluate_model(thresholds, ml_model, x_test, y_test, device, batch_size)

    print(f"Validate results on the full set. Size: {len(y_full)} {np.mean(y_full):.4f}")
    evaluate_model(thresholds, ml_model, x_full, y_full, device, batch_size)

    onnx_model_file = pathlib.Path(__file__).parent.parent / "credsweeper" / "ml_model" / "ml_model.onnx"
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
        torch.onnx.export(
            ml_model,
            x_tensors,
            onnx_model_file,
            input_names=list(dynamic_axes.keys())[:4],
            output_names=list(dynamic_axes.keys())[4:],
            dynamic_axes=dynamic_axes,
            opset_version=13
        )
        print(f"ONNX model export to {onnx_model_file}")

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

    print(args)
    _model_file_name = main(cred_data_location=args.cred_data_location,
                            jobs=int(args.jobs),
                            epochs=int(args.epochs),
                            device=str(args.device),
                            batch_size=int(args.batch_size),
                            patience=int(args.patience),
                            doc_target=bool(args.doc_target),
                            use_tuner=bool(args.use_tuner))
    print(f"\nYou can find your model in:\n{_model_file_name}")
