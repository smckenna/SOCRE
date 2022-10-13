class ValueVar:
    def __init__(self, value: float, variance: float, confidenceInterval: float):
        self.value = value
        self.confidenceInterval = confidenceInterval
        self.variance = variance

    def __str__(self) -> str:
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join('%s=%s' % item for item in vars(self).items())
        )

    def reprJSON(self):
        return dict(value=self.value, variance=self.variance, confidenceInterval=self.confidenceInterval)


class AggregationOutput:
    def __str__(self) -> str:
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join('\n%s=%s' % item for item in vars(self).items())
        )

    def __init__(self,
                 overallRisk: ValueVar,
                 overallRiskLevel: ValueVar,
                 ):
        self.overallRisk = overallRisk
        self.overallRiskLevel = overallRiskLevel

    def reprJSON(self):
        return dict(overallRisk=self.overallRisk.reprJSON(),
                    overallRiskLevel=self.overallRiskLevel.reprJSON()
                    )
