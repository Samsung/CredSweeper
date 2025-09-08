import random

import numpy as np
from colorama import Fore, Style
from sklearn.ensemble import RandomForestClassifier


def disagreement_ratio(sample_preds):
    """% of trees that differ from the majority vote"""
    if np.issubdtype(sample_preds.dtype, np.integer):
        # Classification: majority vote disagreement
        majority = np.bincount(sample_preds).argmax()
        return np.mean(sample_preds != majority)
    else:
        # Regression (or float outputs): relative spread (std / range)
        # Higher = more disagreement
        value_range = np.ptp(sample_preds)  # max - min
        return np.std(sample_preds) / value_range if value_range != 0 else 0.0


def disagreement_check(df_all, x_full_features, y_full, jobs=1):
    """Checks samples for controversial markup - experimental toxicology"""
    clf = RandomForestClassifier(verbose=0,
                                 n_estimators=1000,
                                 max_depth=6,
                                 random_state=random.randint(1, 0xffffffff),
                                 n_jobs=jobs)
    clf.fit(x_full_features, y_full)
    # Predict probabilities
    proba = clf.predict_proba(x_full_features)  # shape: (n_samples, n_classes)
    # Find last confident predictions (max probability close to 0.5 for binary case)
    max_proba = proba.max(axis=1)
    uncertainty = 1 - max_proba  # higher = more uncertain
    # Threshold for controversy (e.g., top 10 most uncertain)
    top_k = 100
    most_controversial_idx = np.argsort(-uncertainty)[:top_k]
    # controversial_samples["true_label"] = df_all.iloc[most_controversial_idx]
    # controversial_samples["predicted_label"] = clf.predict(df_all.iloc[most_controversial_idx])
    # controversial_samples["confidence"] = max_proba[most_controversial_idx]
    # Predictions from each tree
    tree_predictions = np.array(
        [tree.predict(x_full_features) for tree in clf.estimators_])  # shape: (n_trees, n_samples)
    disagreement = np.apply_along_axis(disagreement_ratio, 0, tree_predictions)
    print(Fore.LIGHTMAGENTA_EX + '#' * 120 + Style.RESET_ALL, flush=True)
    for n in most_controversial_idx:
        fore_style = Fore.LIGHTGREEN_EX if df_all.iloc[n]["GroundTruth"] else Fore.LIGHTRED_EX
        print(f"{str(n)} "
              + fore_style +
              f" {str(disagreement[n])} "
              f" {str(clf.predict(x_full_features[[n]])[0])} "
              f" {str(df_all.iloc[[n]].to_dict())} "
              + Style.RESET_ALL,
               flush=True)
