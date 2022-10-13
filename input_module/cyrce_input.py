from config import THREAT_ACTOR_CAPACITY_VALUES, THREAT_ACTOR_CAPACITY_WEIGHTS


class AttackMotivators:
    def __init__(self, appeal: float, targeting: float, reward: float, perceivedDefenses: float):
        self.appeal = appeal / 5.
        self.targeting = targeting / 5.
        self.reward = reward / 5.
        self.perceivedDefenses = perceivedDefenses / 5.


class AttackSurface:
    def __init__(self, awareness: float, opportunity: float):
        self.awareness = awareness / 5.
        self.opportunity = opportunity / 5.


class Exploitability:
    def __init__(self, easeOfExploit: float):
        self.easeOfExploit = easeOfExploit / 5.


class ThreatActorInput:
    def __init__(self, determination: str, resources: str, sophistication: str):
        # TODO make it so if they only know type, then pass that and the other 3 are populated based on type
        self.sophistication = THREAT_ACTOR_CAPACITY_VALUES['sophistication'][sophistication]
        self.resources = THREAT_ACTOR_CAPACITY_VALUES['api_resources'][resources]
        self.determination = THREAT_ACTOR_CAPACITY_VALUES['determination'][determination]
        self.sophisticationWeight = THREAT_ACTOR_CAPACITY_WEIGHTS['sophistication']
        self.resourcesWeight = THREAT_ACTOR_CAPACITY_WEIGHTS['api_resources']
        self.determinationWeight = THREAT_ACTOR_CAPACITY_WEIGHTS['determination']


class DirectImpact:
    def __init__(self, initialResponseCost: float, productivityLoss: float, safety: float, replacementCosts: float):
        self.replacementCosts = (replacementCosts - 1) / 4.
        self.safety = (safety - 1) / 4.
        self.productivityLoss = (productivityLoss - 1) / 4.
        self.initialResponseCost = (initialResponseCost - 1) / 4.


class IndirectImpact:
    def __init__(self, competitiveAdvantageLoss: float, finesAndJudgements: float, reputationDamage: float,
                 secondaryResponseCost: float):
        self.competitiveAdvantageLoss = (competitiveAdvantageLoss - 1) / 4.
        self.finesAndJudgements = (finesAndJudgements - 1) / 4.
        self.reputationDamage = (reputationDamage - 1) / 4.
        self.secondaryResponseCost = (secondaryResponseCost - 1) / 4.


class Impact:
    def __init__(self, directImpact: DirectImpact, indirectImpact: IndirectImpact):
        self.directImpact = directImpact
        self.indirectImpact = indirectImpact


class Scenario:
    def __init__(self, attackAction: str, attackThreatType: str, attackTarget: str, attackLossType: str,
                 attackIndustry: str, attackGeography: str, orgSize: str):
        self.attackAction = attackAction
        self.attackTarget = attackTarget
        self.attackLossType = attackLossType
        self.attackIndustry = attackIndustry
        self.attackGeography = attackGeography
        self.attackThreatType = attackThreatType
        self.orgSize = orgSize


class IDAM:
    def __init__(self, IDAM1: float, IDAM2: float, IDAM3: float, IDAM4: float, IDAM5: float, IDAM6: float,
                 value: float):
        self.IDAM6 = IDAM6
        self.IDAM5 = IDAM5
        self.IDAM4 = IDAM4
        self.IDAM3 = IDAM3
        self.IDAM2 = IDAM2
        self.IDAM1 = IDAM1
        self.value = value


class IDBE:
    def __init__(self, value: float, IDBE1: float, IDBE2: float, IDBE3: float, IDBE4: float, IDBE5: float):
        self.value = value
        self.IDBE1 = IDBE1
        self.IDBE2 = IDBE2
        self.IDBE3 = IDBE3
        self.IDBE4 = IDBE4
        self.IDBE5 = IDBE5


class IDGV:
    def __init__(self, value: float, IDGV1: float, IDGV2: float, IDGV3: float, IDGV4: float):
        self.IDGV3 = IDGV3
        self.IDGV2 = IDGV2
        self.IDGV1 = IDGV1
        self.value = value
        self.IDGV4 = IDGV4


class IDRA:
    def __init__(self, IDRA1: float, IDRA2: float, IDRA3: float, IDRA4: float, IDRA5: float, IDRA6: float,
                 value: float):
        self.IDRA6 = IDRA6
        self.IDRA5 = IDRA5
        self.IDRA4 = IDRA4
        self.IDRA3 = IDRA3
        self.IDRA2 = IDRA2
        self.IDRA1 = IDRA1
        self.value = value


class IDRM:
    def __init__(self, value: float, IDRM1: float, IDRM2: float, IDRM3: float):
        self.value = value
        self.IDRM1 = IDRM1
        self.IDRM2 = IDRM2
        self.IDRM3 = IDRM3


class IDSC:
    def __init__(self, value: float, IDSC1: float, IDSC2: float, IDSC3: float, IDSC4: float, IDSC5: float):
        self.IDSC5 = IDSC5
        self.IDSC4 = IDSC4
        self.IDSC3 = IDSC3
        self.IDSC2 = IDSC2
        self.IDSC1 = IDSC1
        self.value = value


class CsfIdentify:
    def __init__(self, value, IDAM: IDAM, IDBE: IDBE, IDGV: IDGV,
                 IDRA: IDRA, IDRM: IDRM,
                 IDSC: IDSC):
        self.value = value
        self.IDRM = IDRM
        self.IDRA = IDRA
        self.IDGV = IDGV
        self.IDBE = IDBE
        self.IDAM = IDAM
        self.IDSC = IDSC


class PRPT:
    def __init__(self, value: float, PRPT1: float, PRPT2: float, PRPT3: float, PRPT4: float, PRPT5: float):
        self.PRPT5 = PRPT5
        self.PRPT4 = PRPT4
        self.PRPT3 = PRPT3
        self.PRPT2 = PRPT2
        self.PRPT1 = PRPT1
        self.value = value


class PRMA:
    def __init__(self, value: float, PRMA1: float, PRMA2: float):
        self.PRMA2 = PRMA2
        self.PRMA1 = PRMA1
        self.value = value


class PRIP:
    def __init__(self, value: float, PRIP1: float, PRIP2: float, PRIP3: float, PRIP4: float, PRIP5: float, PRIP6: float,
                 PRIP7: float, PRIP8: float,
                 PRIP9: float, PRIP10: float, PRIP11: float, PRIP12: float):
        self.PRIP12 = PRIP12
        self.PRIP11 = PRIP11
        self.PRIP10 = PRIP10
        self.PRIP9 = PRIP9
        self.PRIP8 = PRIP8
        self.PRIP7 = PRIP7
        self.PRIP6 = PRIP6
        self.PRIP5 = PRIP5
        self.PRIP4 = PRIP4
        self.PRIP3 = PRIP3
        self.PRIP2 = PRIP2
        self.PRIP1 = PRIP1
        self.value = value


class PRDS:
    def __init__(self, value: float, PRDS1: float, PRDS2: float, PRDS3: float, PRDS4: float, PRDS5: float, PRDS6: float,
                 PRDS7: float, PRDS8: float):
        self.PRDS8 = PRDS8
        self.PRDS7 = PRDS7
        self.PRDS6 = PRDS6
        self.PRDS5 = PRDS5
        self.PRDS4 = PRDS4
        self.PRDS3 = PRDS3
        self.PRDS2 = PRDS2
        self.PRDS1 = PRDS1
        self.value = value


class PRAT:
    def __init__(self, value: float, PRAT1: float, PRAT2: float, PRAT3: float, PRAT4: float, PRAT5: float):
        self.PRAT5 = PRAT5
        self.PRAT4 = PRAT4
        self.PRAT3 = PRAT3
        self.PRAT2 = PRAT2
        self.PRAT1 = PRAT1
        self.value = value


class PRAC:
    def __init__(self, value: float, PRAC1: float, PRAC2: float, PRAC3: float, PRAC4: float, PRAC5: float, PRAC6: float,
                 PRAC7: float):
        self.PRAC7 = PRAC7
        self.PRAC6 = PRAC6
        self.PRAC5 = PRAC5
        self.PRAC4 = PRAC4
        self.PRAC3 = PRAC3
        self.PRAC2 = PRAC2
        self.PRAC1 = PRAC1
        self.value = value


class CsfProtect:
    def __init__(self, value: float, PRAC: PRAC, PRAT: PRAT, PRDS: PRDS, PRIP: PRIP, PRMA: PRMA, PRPT: PRPT):
        self.PRPT = PRPT
        self.PRMA = PRMA
        self.PRIP = PRIP
        self.PRDS = PRDS
        self.PRAT = PRAT
        self.PRAC = PRAC
        self.value = value


class DEDP:
    def __init__(self, value: float, DEDP1: float, DEDP2: float, DEDP3: float, DEDP4: float, DEDP5: float):
        self.DEDP5 = DEDP5
        self.DEDP4 = DEDP4
        self.DEDP3 = DEDP3
        self.DEDP2 = DEDP2
        self.DEDP1 = DEDP1
        self.value = value


class DECM:
    def __init__(self, value: float, DECM1: float, DECM2: float, DECM3: float, DECM4: float, DECM5: float, DECM6: float,
                 DECM7: float, DECM8: float):
        self.DECM8 = DECM8
        self.DECM7 = DECM7
        self.DECM6 = DECM6
        self.DECM5 = DECM5
        self.DECM4 = DECM4
        self.DECM3 = DECM3
        self.DECM2 = DECM2
        self.DECM1 = DECM1
        self.value = value


class DEAE:
    def __init__(self, value: float, DEAE1: float, DEAE2: float, DEAE3: float, DEAE4: float, DEAE5: float):
        self.DEAE5 = DEAE5
        self.DEAE4 = DEAE4
        self.DEAE3 = DEAE3
        self.DEAE2 = DEAE2
        self.DEAE1 = DEAE1
        self.value = value


class CsfDetect:
    def __init__(self, value: float, DEAE: DEAE, DECM: DECM, DEDP: DEDP):
        self.DEDP = DEDP
        self.DECM = DECM
        self.DEAE = DEAE
        self.value = value


class RSRP:
    def __init__(self, value: float, RSRP1: float):
        self.RSRP1 = RSRP1
        self.value = value


class RSCO:
    def __init__(self, value: float, RSCO1: float, RSCO2: float, RSCO3: float, RSCO4: float, RSCO5: float):
        self.RSCO5 = RSCO5
        self.RSCO4 = RSCO4
        self.RSCO3 = RSCO3
        self.RSCO2 = RSCO2
        self.RSCO1 = RSCO1
        self.value = value


class RSAN:
    def __init__(self, value: float, RSAN1: float, RSAN2: float, RSAN3: float, RSAN4: float, RSAN5: float):
        self.RSAN5 = RSAN5
        self.RSAN4 = RSAN4
        self.RSAN3 = RSAN3
        self.RSAN2 = RSAN2
        self.RSAN1 = RSAN1
        self.value = value


class RSMI:
    def __init__(self, value: float, RSMI1: float, RSMI2: float, RSMI3: float):
        self.RSMI3 = RSMI3
        self.RSMI2 = RSMI2
        self.RSMI1 = RSMI1
        self.value = value


class RSIM:
    def __init__(self, value: float, RSIM1: float, RSIM2: float):
        self.RSIM2 = RSIM2
        self.RSIM1 = RSIM1
        self.value = value


class CsfRespond:
    def __init__(self, value: float, RSRP: RSRP, RSCO: RSCO, RSAN: RSAN, RSMI: RSMI, RSIM: RSIM):
        self.RSIM = RSIM
        self.RSMI = RSMI
        self.RSAN = RSAN
        self.RSCO = RSCO
        self.RSRP = RSRP
        self.value = value


class RCRP:
    def __init__(self, value: float, RCRP1: float):
        self.RCRP1 = RCRP1
        self.value = value


class RCIM:
    def __init__(self, value: float, RCIM1: float, RCIM2: float):
        self.RCIM2 = RCIM2
        self.RCIM1 = RCIM1
        self.value = value


class RCCO:
    def __init__(self, value: float, RCCO1: float, RCCO2: float, RCCO3: float):
        self.RCCO3 = RCCO3
        self.RCCO2 = RCCO2
        self.RCCO1 = RCCO1
        self.value = value


class CsfRecover:
    def __init__(self, value: float, RCRP: RCRP, RCIM: RCIM, RCCO: RCCO):
        self.RCCO = RCCO
        self.RCIM = RCIM
        self.RCRP = RCRP
        self.value = value


class CsfFunction:
    def __init__(self, identify: CsfIdentify, protect: CsfProtect, detect: CsfDetect, respond: CsfRespond,
                 recover: CsfRecover):
        self.recover = recover
        self.respond = respond
        self.detect = detect
        self.protect = protect
        self.identify = identify


class CyrceCsfInput:

    def __init__(self,
                 attackMotivators: AttackMotivators,
                 attackSurface: AttackSurface,
                 exploitability: Exploitability,
                 threatActorInput: ThreatActorInput,
                 impact: Impact,
                 csf: CsfFunction, scenario: Scenario):
        self.impact = impact
        self.threatActorInput = threatActorInput
        self.attackSurface = attackSurface
        self.exploitability = exploitability
        self.attackMotivators = attackMotivators
        self.csf = csf
        self.scenario = scenario


class Cyrce80053Input:

    def __init__(self, attackMotivators: AttackMotivators):
        self.attackMotivators = attackMotivators


class CyrceTtpCoverageInput:

    def __init__(self, foo):
        self.foo = foo
