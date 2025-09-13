from typing import Dict, Any, List

from tests import SAMPLES_POST_CRED_COUNT, SAMPLES_IN_DEEP_3, SAMPLES_FILTERED_COUNT, SAMPLES_IN_DOC, \
    NEGLIGIBLE_ML_THRESHOLD, SAMPLES_REGEX_COUNT

DATA_TEST_CFG: List[Dict[str, Any]] = [{
    "__cred_count": SAMPLES_IN_DOC,
    "pool_count": 1,
    "thrifty": False,
    "sort_output": True,
    "subtext": True,
    "json_filename": "doc.json",
    "doc": True,
    "ml_threshold": NEGLIGIBLE_ML_THRESHOLD
}, {
    "__cred_count": SAMPLES_REGEX_COUNT,
    "pool_count": 1,
    "thrifty": True,
    "sort_output": True,
    "json_filename": "no_filters_no_ml.json",
    "use_filters": False,
    "ml_threshold": 0
}, {
    "__cred_count": SAMPLES_FILTERED_COUNT,
    "pool_count": 1,
    "thrifty": True,
    "sort_output": True,
    "json_filename": "no_ml.json",
    "ml_threshold": 0
}, {
    "__cred_count": SAMPLES_POST_CRED_COUNT,
    "pool_count": 2,
    "thrifty": True,
    "sort_output": True,
    "json_filename": "output.json"
}, {
    "__cred_count": SAMPLES_IN_DEEP_3 + 9,
    "pool_count": 2,
    "thrifty": True,
    "sort_output": True,
    "json_filename": "depth_3_pedantic.json",
    "pedantic": True,
    "depth": 3
}]
