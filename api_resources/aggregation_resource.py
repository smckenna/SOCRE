import json

from flask import request
from flask_restful import Resource

from aggregation_module.aggregation_input import AggregationInput, RiskValues
from aggregation_module.run_aggregation import runAggregation


class RiskAggregationResource(Resource):

    def post(self):
        json_data = request.json
        aggregationInput = self.jsonToInput(json_data)
        response = runAggregation(aggregationInput)
        return response.reprJSON()

    def jsonToInput(self, json_data):
        risk_values = RiskValues(
            values=json_data['riskValues'],
            weights=json_data['weights']
        )

        return AggregationInput(
            risk_values=risk_values)
