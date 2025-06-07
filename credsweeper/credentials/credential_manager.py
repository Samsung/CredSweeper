import logging
from multiprocessing import Manager
from typing import List, Dict, Tuple

from credsweeper.credentials.candidate import Candidate
from credsweeper.credentials.candidate_group_generator import CandidateGroupGenerator, CandidateKey

logger = logging.getLogger(__name__)


class CredentialManager:
    """The manager allows you to store, add and delete separate credit candidates."""

    def __init__(self) -> None:
        self.candidates: List[Candidate] = list(Manager().list())

    def clear_credentials(self) -> None:
        """Clear credential candidates stored in the manager."""
        self.candidates.clear()

    def len_credentials(self) -> int:
        """Get number of credential candidates stored in the manager.

        Return:
            Non-negative integer

        """
        return len(self.candidates)

    def get_credentials(self) -> List[Candidate]:
        """Get all credential candidates stored in the manager.

        Return:
            List with all Candidate objects stored in manager

        """
        return self.candidates

    def set_credentials(self, candidates: List[Candidate]) -> None:
        """Remove all current credentials candidates from the manager and add new credentials.

        Args:
            candidates: List with candidates to replace current candidates in the manager

        """
        self.candidates = candidates

    def add_credential(self, candidate: Candidate) -> None:
        """Add credential candidate to the manager.

        Args:
            candidate: credential candidate to be added

        """
        self.candidates.append(candidate)

    def remove_credential(self, candidate: Candidate) -> None:
        """Remove credential candidate from the manager.

        Args:
            candidate: credential candidate to be removed

        """
        self.candidates.remove(candidate)

    def purge_duplicates(self) -> int:
        """Purge duplicates candidates which may appear in overlaps during long line scan.

        Returns: number of removed duplicates
        """
        candidates_dict: Dict[Tuple[str, str, str, int, int, int, int, int, int, int], Candidate] = {}
        before = len(self.candidates)
        for i in self.candidates:
            ld = i.line_data_list[0]
            candidate_key = (
                i.rule_name,  #
                ld.path,  #
                ld.info,  #
                ld.line_pos,  #
                ld.variable_start,  #
                ld.variable_end,  #
                ld.separator_start,  #
                ld.separator_end,  #
                ld.value_start,  #
                ld.value_end)
            if candidate_key in candidates_dict:
                # check precisely - compare with the values
                candidate_dict = candidates_dict[candidate_key]
                if not candidate_dict.compare(i):
                    ld_ = candidate_dict.line_data_list[0]
                    logger.warning(f"check {ld_.variable, ld_.value} and {ld.variable, ld.value}")
            else:
                candidates_dict[candidate_key] = i
        self.candidates = list(candidates_dict.values())
        after = len(self.candidates)
        return before - after

    def group_credentials(self) -> CandidateGroupGenerator:
        """Join candidates that reference same secret value in the same line.

        Candidate can belong to two groups in the same time if it has more than one LineData object inside

        Return:
            Contain dictionary of [path, line_num, value] -> credential candidates list

        """
        groups = CandidateGroupGenerator()
        for credential_candidate in self.get_credentials():
            for line_data in credential_candidate.line_data_list[:1]:
                # Match by file path+line num+value. Value required so two different credentials still be
                #  processed independently
                candidate_key = CandidateKey(line_data)
                if candidate_key in groups:
                    groups[candidate_key].append(credential_candidate)
                else:
                    groups[candidate_key] = [credential_candidate]
        return groups
