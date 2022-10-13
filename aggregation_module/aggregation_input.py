class RiskValues:
    def __init__(self, values: list, weights: list):
        self.values = values
        if len(weights) == 0:
            self.weights = [1] * len(values)
        elif len(weights) != len(values):
            self.weights = [1] * len(values)
        else:
            self.weights = weights


class AggregationInput:

    def __init__(self, risk_values: RiskValues):
        self.risk_values = risk_values
