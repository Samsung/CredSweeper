from multiprocessing import Manager
from typing import List

from credsweeper.credentials import Candidate
from credsweeper.credentials.candidate_group_generator import CandidateGroupGenerator, CandidateKey


class CredentialManager:
    """The manager allows you to store, add and delete separate credit candidates.

    Parameters:
        candidates: list of credential candidates

    """

    def __init__(self) -> None:
        self.candidates: List[Candidate] = list(Manager().list())

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
                if candidate_key not in groups:
                    groups[candidate_key] = list()
                groups[candidate_key].append(credential_candidate)
        return groups
