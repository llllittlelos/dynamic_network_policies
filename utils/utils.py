# utils/utils.py

from collections import namedtuple

ScoreTypes = namedtuple("ScoreTypes",
                        ["global_score", "container_score", "security_context_score",
                         "access_score", "pod_score", "volume_score"])
score_types = ScoreTypes(global_score="globalScore", container_score="containerScore",
                         security_context_score="securityContextScore", access_score="accessScore",
                         pod_score="podScore", volume_score="volumeScore")
