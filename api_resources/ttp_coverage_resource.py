from dataclasses import dataclass

from flask import request
from flask_restful import Resource

from core_module.analysis import run_ttp_coverage_metric
from output_module.cyrce_output import ValueVar


@dataclass
class MitreAttackControl:
    label: str
    score: float
    ttps: []


@dataclass
class ttpCoverageRequest:
    controls: [MitreAttackControl]
    action: None


@dataclass
class ttpCoverageResponse:
    success: bool
    ttpCoverage: ValueVar

    def reprJSON(self):
        return dict(
            ttpCoverage=self.ttpCoverage.reprJSON()
        )


class TtpCoverageResource(Resource):
    def post(self):
        json_data = request.json
        ttpCoverageInput = self.jsonToInput(json_data)
        ttp_output = run_ttp_coverage_metric(ttpInput=ttpCoverageInput)
        return ttpCoverageResponse(success=True, ttpCoverage=ValueVar(value=ttp_output['threat_coverage'],
                                                                      confidenceInterval=ttp_output['confidence_interval'],
                                                                      variance=ttp_output['var'])).reprJSON()

    def jsonToInput(self, data):
        controls: [MitreAttackControl] = []

        for item in data['controls']:
            controls.append(
                MitreAttackControl(
                    label=item['label'],
                    score=item['score'],
                    ttps=item['ttps']
                )
            )
        if 'action' in data.keys():
            action = data['action']
        else:
            action = 'malware'

        return ttpCoverageRequest(
            controls=controls, action=action
        )
