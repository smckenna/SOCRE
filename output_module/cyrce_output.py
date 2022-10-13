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


class CyrceOutput:
    def __str__(self) -> str:
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join('\n%s=%s' % item for item in vars(self).items())
        )

    def __init__(self,
                 overallInherentLikelihood: ValueVar,
                 overallResidualLikelihood: ValueVar,
                 overallInherentImpact: ValueVar,
                 overallResidualImpact: ValueVar,
                 overallInherentRiskLevel: ValueVar,
                 overallResidualRiskLevel: ValueVar,
                 attackSurface: float,
                 threatActorCapacity: float,
                 threatLevel: float,
                 attackMotivators: float,
                 priorAttackProbability: float,
                 attackProbability: float,
                 exploitability: float,
                 vulnerability: float,
                 directImpact: float,
                 indirectImpact: float
                 ):
        self.indirectImpact = indirectImpact
        self.directImpact = directImpact
        self.attackMotivators = attackMotivators
        self.priorAttackProbability = priorAttackProbability
        self.attackProbability = attackProbability
        self.threatActorCapacity = threatActorCapacity
        self.threatLevel = threatLevel
        self.attackSurface = attackSurface
        self.exploitability = exploitability
        self.vulnerability = vulnerability
        self.overallInherentRiskLevel = overallInherentRiskLevel
        self.overallResidualRiskLevel = overallResidualRiskLevel
        self.overallInherentImpact = overallInherentImpact
        self.overallResidualImpact = overallResidualImpact
        self.overallInherentLikelihood = overallInherentLikelihood
        self.overallResidualLikelihood = overallResidualLikelihood

    def reprJSON(self):
        return dict(overallInherentLikelihood=self.overallInherentLikelihood.reprJSON(),
                    overallResidualLikelihood=self.overallResidualLikelihood.reprJSON(),
                    overallInherentImpact=self.overallInherentImpact.reprJSON(),
                    overallResidualImpact=self.overallResidualImpact.reprJSON(),
                    overallInherentRiskLevel=self.overallInherentRiskLevel.reprJSON(),
                    overallResidualRiskLevel=self.overallResidualRiskLevel.reprJSON(),
                    attackSurface=self.attackSurface,
                    threatActorCapacity=self.threatActorCapacity,
                    threatLevel=self.threatLevel,
                    priorAttackProbability=self.priorAttackProbability,
                    attackProbability=self.attackProbability,
                    attackMotivators=self.attackMotivators,
                    exploitability=self.exploitability,
                    vulnerability=self.vulnerability,
                    directImpact=self.directImpact,
                    indirectImpact=self.indirectImpact
                    )
