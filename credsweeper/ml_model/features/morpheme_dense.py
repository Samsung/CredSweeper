from credsweeper.common import static_keyword_checklist
from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class MorphemeDense(Feature):
    """Feature calculates morphemes density for a value"""

    def extract(self, candidate: Candidate) -> float:
        if value := candidate.line_data_list[0].value.lower():
            morphemes_counter = 0
            for morpheme in static_keyword_checklist.morpheme_set:
                if morpheme in value:
                    morphemes_counter += 1
            # normalization: minimal morpheme length is 3
            return 3.0 * morphemes_counter / len(value)
        else:
            # empty value case
            return 0.0
