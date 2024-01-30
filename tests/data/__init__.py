from typing import Dict, Any, List

from tests import SAMPLES_POST_CRED_COUNT, SAMPLES_IN_DEEP_3, SAMPLES_CRED_COUNT, SAMPLES_IN_DOC

DATA_TEST_CFG: List[Dict[str, Any]] = [{
    "__cred_count": SAMPLES_CRED_COUNT,
    "sort_output": True,
    "json_filename": "ml_threshold.json",
    "ml_threshold": 0.0000001
}, {
    "__cred_count": SAMPLES_POST_CRED_COUNT,
    "sort_output": True,
    "json_filename": "output.json"
}]
