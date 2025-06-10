from typing import List

from credsweeper.credentials.candidate import Candidate


def augment_candidates(candidates: List[Candidate], new_candidates: List[Candidate]):
    """
    Augments candidates with new_candidates if value of line data is not present in the candidates

    Args:
        candidates: [IN/OUT] list of candidates to be augmented
        new_candidates: [IN] list with new candidates

    """

    if not new_candidates:
        return
    found_values = set(line_data.value for candidate in candidates  #
                       for line_data in candidate.line_data_list)
    for new_candidate in new_candidates:
        for line_data in new_candidate.line_data_list:
            if line_data.value not in found_values:
                candidates.append(new_candidate)
                break
