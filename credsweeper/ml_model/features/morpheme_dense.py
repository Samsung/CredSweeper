from credsweeper.common import static_keyword_checklist
from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class MorphemeDense(Feature):
    """Feature calculates morphemes density for a value"""

    def extract(self, candidate: Candidate) -> float:
        density = 0.0
        if value := candidate.line_data_list[0].value.lower():
            morphemes_length = 0
            for morpheme in static_keyword_checklist.morpheme_set:
                morpheme_pos = value.find(morpheme)
                if 0 <= morpheme_pos:
                    morpheme_len = len(morpheme)
                    while 0 <= morpheme_pos:
                        morphemes_length += morpheme_len
                        morpheme_pos += morpheme_len
                        morpheme_pos = value.find(morpheme, morpheme_pos)
            # normalization: minimal morpheme length is 3
            density = morphemes_length / len(value)
            if 1.0 < density:
                # overlap morpheme case
                density = 1.0
        return density
