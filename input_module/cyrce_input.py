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
        self.resources = THREAT_ACTOR_CAPACITY_VALUES['resources'][resources]
        self.determination = THREAT_ACTOR_CAPACITY_VALUES['determination'][determination]
        self.sophisticationWeight = THREAT_ACTOR_CAPACITY_WEIGHTS['sophistication']
        self.resourcesWeight = THREAT_ACTOR_CAPACITY_WEIGHTS['resources']
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


class AC_1:
    def __init__(self, value: float):
        self.value = value


class AC_2:
    def __init__(self, value: float):
        self.value = value


class AC_3:
    def __init__(self, value: float):
        self.value = value


class AC_4:
    def __init__(self, value: float):
        self.value = value


class AC_5:
    def __init__(self, value: float):
        self.value = value


class AC_6:
    def __init__(self, value: float):
        self.value = value


class AC_7:
    def __init__(self, value: float):
        self.value = value


class AC_8:
    def __init__(self, value: float):
        self.value = value


class AC_10:
    def __init__(self, value: float):
        self.value = value


class AC_11:
    def __init__(self, value: float):
        self.value = value


class AC_12:
    def __init__(self, value: float):
        self.value = value


class AC_14:
    def __init__(self, value: float):
        self.value = value


class AC_17:
    def __init__(self, value: float):
        self.value = value


class AC_18:
    def __init__(self, value: float):
        self.value = value


class AC_19:
    def __init__(self, value: float):
        self.value = value


class AC_20:
    def __init__(self, value: float):
        self.value = value


class AC_21:
    def __init__(self, value: float):
        self.value = value


class AC_22:
    def __init__(self, value: float):
        self.value = value


class AT_1:
    def __init__(self, value: float):
        self.value = value


class AT_2:
    def __init__(self, value: float):
        self.value = value


class AT_3:
    def __init__(self, value: float):
        self.value = value


class AT_4:
    def __init__(self, value: float):
        self.value = value


class AU_1:
    def __init__(self, value: float):
        self.value = value


class AU_2:
    def __init__(self, value: float):
        self.value = value


class AU_3:
    def __init__(self, value: float):
        self.value = value


class AU_4:
    def __init__(self, value: float):
        self.value = value


class AU_5:
    def __init__(self, value: float):
        self.value = value


class AU_6:
    def __init__(self, value: float):
        self.value = value


class AU_7:
    def __init__(self, value: float):
        self.value = value


class AU_8:
    def __init__(self, value: float):
        self.value = value


class AU_9:
    def __init__(self, value: float):
        self.value = value


class AU_10:
    def __init__(self, value: float):
        self.value = value


class AU_11:
    def __init__(self, value: float):
        self.value = value


class AU_12:
    def __init__(self, value: float):
        self.value = value


class CA_1:
    def __init__(self, value: float):
        self.value = value


class CA_2:
    def __init__(self, value: float):
        self.value = value


class CA_3:
    def __init__(self, value: float):
        self.value = value


class CA_5:
    def __init__(self, value: float):
        self.value = value


class CA_6:
    def __init__(self, value: float):
        self.value = value


class CA_7:
    def __init__(self, value: float):
        self.value = value


class CA_8:
    def __init__(self, value: float):
        self.value = value


class CA_9:
    def __init__(self, value: float):
        self.value = value


class CM_1:
    def __init__(self, value: float):
        self.value = value


class CM_2:
    def __init__(self, value: float):
        self.value = value


class CM_3:
    def __init__(self, value: float):
        self.value = value


class CM_4:
    def __init__(self, value: float):
        self.value = value


class CM_5:
    def __init__(self, value: float):
        self.value = value


class CM_6:
    def __init__(self, value: float):
        self.value = value


class CM_7:
    def __init__(self, value: float):
        self.value = value


class CM_8:
    def __init__(self, value: float):
        self.value = value


class CM_9:
    def __init__(self, value: float):
        self.value = value


class CM_10:
    def __init__(self, value: float):
        self.value = value


class CM_11:
    def __init__(self, value: float):
        self.value = value


class CM_12:
    def __init__(self, value: float):
        self.value = value


class CP_1:
    def __init__(self, value: float):
        self.value = value


class CP_2:
    def __init__(self, value: float):
        self.value = value


class CP_3:
    def __init__(self, value: float):
        self.value = value


class CP_4:
    def __init__(self, value: float):
        self.value = value


class CP_6:
    def __init__(self, value: float):
        self.value = value


class CP_7:
    def __init__(self, value: float):
        self.value = value


class CP_8:
    def __init__(self, value: float):
        self.value = value


class CP_9:
    def __init__(self, value: float):
        self.value = value


class CP_10:
    def __init__(self, value: float):
        self.value = value


class IA_1:
    def __init__(self, value: float):
        self.value = value


class IA_2:
    def __init__(self, value: float):
        self.value = value


class IA_3:
    def __init__(self, value: float):
        self.value = value


class IA_4:
    def __init__(self, value: float):
        self.value = value


class IA_5:
    def __init__(self, value: float):
        self.value = value


class IA_6:
    def __init__(self, value: float):
        self.value = value


class IA_7:
    def __init__(self, value: float):
        self.value = value


class IA_8:
    def __init__(self, value: float):
        self.value = value


class IA_11:
    def __init__(self, value: float):
        self.value = value


class IA_12:
    def __init__(self, value: float):
        self.value = value


class IR_1:
    def __init__(self, value: float):
        self.value = value


class IR_2:
    def __init__(self, value: float):
        self.value = value


class IR_3:
    def __init__(self, value: float):
        self.value = value


class IR_4:
    def __init__(self, value: float):
        self.value = value


class IR_5:
    def __init__(self, value: float):
        self.value = value


class IR_6:
    def __init__(self, value: float):
        self.value = value


class IR_7:
    def __init__(self, value: float):
        self.value = value


class IR_8:
    def __init__(self, value: float):
        self.value = value


class MA_1:
    def __init__(self, value: float):
        self.value = value


class MA_2:
    def __init__(self, value: float):
        self.value = value


class MA_3:
    def __init__(self, value: float):
        self.value = value


class MA_4:
    def __init__(self, value: float):
        self.value = value


class MA_5:
    def __init__(self, value: float):
        self.value = value


class MA_6:
    def __init__(self, value: float):
        self.value = value


class MP_1:
    def __init__(self, value: float):
        self.value = value


class MP_2:
    def __init__(self, value: float):
        self.value = value


class MP_3:
    def __init__(self, value: float):
        self.value = value


class MP_4:
    def __init__(self, value: float):
        self.value = value


class MP_5:
    def __init__(self, value: float):
        self.value = value


class MP_6:
    def __init__(self, value: float):
        self.value = value


class MP_7:
    def __init__(self, value: float):
        self.value = value


class PE_1:
    def __init__(self, value: float):
        self.value = value


class PE_2:
    def __init__(self, value: float):
        self.value = value


class PE_3:
    def __init__(self, value: float):
        self.value = value


class PE_4:
    def __init__(self, value: float):
        self.value = value


class PE_5:
    def __init__(self, value: float):
        self.value = value


class PE_6:
    def __init__(self, value: float):
        self.value = value


class PE_8:
    def __init__(self, value: float):
        self.value = value


class PE_9:
    def __init__(self, value: float):
        self.value = value


class PE_10:
    def __init__(self, value: float):
        self.value = value


class PE_11:
    def __init__(self, value: float):
        self.value = value


class PE_12:
    def __init__(self, value: float):
        self.value = value


class PE_13:
    def __init__(self, value: float):
        self.value = value


class PE_14:
    def __init__(self, value: float):
        self.value = value


class PE_15:
    def __init__(self, value: float):
        self.value = value


class PE_16:
    def __init__(self, value: float):
        self.value = value


class PE_17:
    def __init__(self, value: float):
        self.value = value


class PE_18:
    def __init__(self, value: float):
        self.value = value


class PL_1:
    def __init__(self, value: float):
        self.value = value


class PL_2:
    def __init__(self, value: float):
        self.value = value


class PL_4:
    def __init__(self, value: float):
        self.value = value


class PL_8:
    def __init__(self, value: float):
        self.value = value


class PL_10:
    def __init__(self, value: float):
        self.value = value


class PL_11:
    def __init__(self, value: float):
        self.value = value


class PS_1:
    def __init__(self, value: float):
        self.value = value


class PS_2:
    def __init__(self, value: float):
        self.value = value


class PS_3:
    def __init__(self, value: float):
        self.value = value


class PS_4:
    def __init__(self, value: float):
        self.value = value


class PS_5:
    def __init__(self, value: float):
        self.value = value


class PS_6:
    def __init__(self, value: float):
        self.value = value


class PS_7:
    def __init__(self, value: float):
        self.value = value


class PS_8:
    def __init__(self, value: float):
        self.value = value


class PS_9:
    def __init__(self, value: float):
        self.value = value


class RA_1:
    def __init__(self, value: float):
        self.value = value


class RA_2:
    def __init__(self, value: float):
        self.value = value


class RA_3:
    def __init__(self, value: float):
        self.value = value


class RA_5:
    def __init__(self, value: float):
        self.value = value


class RA_7:
    def __init__(self, value: float):
        self.value = value


class RA_9:
    def __init__(self, value: float):
        self.value = value


class SA_1:
    def __init__(self, value: float):
        self.value = value


class SA_2:
    def __init__(self, value: float):
        self.value = value


class SA_3:
    def __init__(self, value: float):
        self.value = value


class SA_4:
    def __init__(self, value: float):
        self.value = value


class SA_5:
    def __init__(self, value: float):
        self.value = value


class SA_8:
    def __init__(self, value: float):
        self.value = value


class SA_9:
    def __init__(self, value: float):
        self.value = value


class SA_10:
    def __init__(self, value: float):
        self.value = value


class SA_11:
    def __init__(self, value: float):
        self.value = value


class SA_15:
    def __init__(self, value: float):
        self.value = value


class SA_16:
    def __init__(self, value: float):
        self.value = value


class SA_17:
    def __init__(self, value: float):
        self.value = value


class SA_21:
    def __init__(self, value: float):
        self.value = value


class SA_22:
    def __init__(self, value: float):
        self.value = value


class SC_1:
    def __init__(self, value: float):
        self.value = value


class SC_2:
    def __init__(self, value: float):
        self.value = value


class SC_3:
    def __init__(self, value: float):
        self.value = value


class SC_4:
    def __init__(self, value: float):
        self.value = value


class SC_5:
    def __init__(self, value: float):
        self.value = value


class SC_7:
    def __init__(self, value: float):
        self.value = value


class SC_8:
    def __init__(self, value: float):
        self.value = value


class SC_10:
    def __init__(self, value: float):
        self.value = value


class SC_12:
    def __init__(self, value: float):
        self.value = value


class SC_13:
    def __init__(self, value: float):
        self.value = value


class SC_15:
    def __init__(self, value: float):
        self.value = value


class SC_17:
    def __init__(self, value: float):
        self.value = value


class SC_18:
    def __init__(self, value: float):
        self.value = value


class SC_20:
    def __init__(self, value: float):
        self.value = value


class SC_21:
    def __init__(self, value: float):
        self.value = value


class SC_22:
    def __init__(self, value: float):
        self.value = value


class SC_23:
    def __init__(self, value: float):
        self.value = value


class SC_24:
    def __init__(self, value: float):
        self.value = value


class SC_28:
    def __init__(self, value: float):
        self.value = value


class SC_39:
    def __init__(self, value: float):
        self.value = value


class SI_1:
    def __init__(self, value: float):
        self.value = value


class SI_2:
    def __init__(self, value: float):
        self.value = value


class SI_3:
    def __init__(self, value: float):
        self.value = value


class SI_4:
    def __init__(self, value: float):
        self.value = value


class SI_5:
    def __init__(self, value: float):
        self.value = value


class SI_6:
    def __init__(self, value: float):
        self.value = value


class SI_7:
    def __init__(self, value: float):
        self.value = value


class SI_8:
    def __init__(self, value: float):
        self.value = value


class SI_10:
    def __init__(self, value: float):
        self.value = value


class SI_11:
    def __init__(self, value: float):
        self.value = value


class SI_12:
    def __init__(self, value: float):
        self.value = value


class SI_16:
    def __init__(self, value: float):
        self.value = value


class SR_1:
    def __init__(self, value: float):
        self.value = value


class SR_2:
    def __init__(self, value: float):
        self.value = value


class SR_3:
    def __init__(self, value: float):
        self.value = value


class SR_5:
    def __init__(self, value: float):
        self.value = value


class SR_6:
    def __init__(self, value: float):
        self.value = value


class SR_8:
    def __init__(self, value: float):
        self.value = value


class SR_9:
    def __init__(self, value: float):
        self.value = value


class SR_10:
    def __init__(self, value: float):
        self.value = value


class SR_11:
    def __init__(self, value: float):
        self.value = value


class SR_12:
    def __init__(self, value: float):
        self.value = value


class AC:
    def __init__(self, value: float, AC_1: float, AC_2: float, AC_3: float, AC_4: float, AC_5: float, AC_6: float,
                 AC_7: float, AC_8: float, AC_10: float, AC_11: float, AC_12: float, AC_14: float, AC_17: float,
                 AC_18: float, AC_19: float, AC_20: float, AC_21: float, AC_22: float):
        self.value = value
        self.AC_1 = AC_1
        self.AC_2 = AC_2
        self.AC_3 = AC_3
        self.AC_4 = AC_4
        self.AC_5 = AC_5
        self.AC_6 = AC_6
        self.AC_7 = AC_7
        self.AC_8 = AC_8
        self.AC_10 = AC_10
        self.AC_11 = AC_11
        self.AC_12 = AC_12
        self.AC_14 = AC_14
        self.AC_17 = AC_17
        self.AC_18 = AC_18
        self.AC_19 = AC_19
        self.AC_20 = AC_20
        self.AC_21 = AC_21
        self.AC_22 = AC_22


class AT:
    def __init__(self, value: float, AT_1: float, AT_2: float, AT_3: float, AT_4: float):
        self.value = value
        self.AT_1 = AT_1
        self.AT_2 = AT_2
        self.AT_3 = AT_3
        self.AT_4 = AT_4


class AU:
    def __init__(self, value: float, AU_1: float, AU_2: float, AU_3: float, AU_4: float, AU_5: float, AU_6: float,
                 AU_7: float, AU_8: float, AU_9: float, AU_10: float, AU_11: float, AU_12: float):
        self.value = value
        self.AU_1 = AU_1
        self.AU_2 = AU_2
        self.AU_3 = AU_3
        self.AU_4 = AU_4
        self.AU_5 = AU_5
        self.AU_6 = AU_6
        self.AU_7 = AU_7
        self.AU_8 = AU_8
        self.AU_9 = AU_9
        self.AU_10 = AU_10
        self.AU_11 = AU_11
        self.AU_12 = AU_12


class CA:
    def __init__(self, value: float, CA_1: float, CA_2: float, CA_3: float, CA_5: float, CA_6: float, CA_7: float,
                 CA_8: float, CA_9: float):
        self.value = value
        self.CA_1 = CA_1
        self.CA_2 = CA_2
        self.CA_3 = CA_3
        self.CA_5 = CA_5
        self.CA_6 = CA_6
        self.CA_7 = CA_7
        self.CA_8 = CA_8
        self.CA_9 = CA_9


class CM:
    def __init__(self, value: float, CM_1: float, CM_2: float, CM_3: float, CM_4: float, CM_5: float, CM_6: float,
                 CM_7: float, CM_8: float, CM_9: float, CM_10: float, CM_11: float, CM_12: float):
        self.value = value
        self.CM_1 = CM_1
        self.CM_2 = CM_2
        self.CM_3 = CM_3
        self.CM_4 = CM_4
        self.CM_5 = CM_5
        self.CM_6 = CM_6
        self.CM_7 = CM_7
        self.CM_8 = CM_8
        self.CM_9 = CM_9
        self.CM_10 = CM_10
        self.CM_11 = CM_11
        self.CM_12 = CM_12


class CP:
    def __init__(self, value: float, CP_1: float, CP_2: float, CP_3: float, CP_4: float, CP_6: float, CP_7: float,
                 CP_8: float, CP_9: float, CP_10: float):
        self.value = value
        self.CP_1 = CP_1
        self.CP_2 = CP_2
        self.CP_3 = CP_3
        self.CP_4 = CP_4
        self.CP_6 = CP_6
        self.CP_7 = CP_7
        self.CP_8 = CP_8
        self.CP_9 = CP_9
        self.CP_10 = CP_10


class IA:
    def __init__(self, value: float, IA_1: float, IA_2: float, IA_3: float, IA_4: float, IA_5: float, IA_6: float,
                 IA_7: float, IA_8: float, IA_11: float, IA_12: float):
        self.value = value
        self.IA_1 = IA_1
        self.IA_2 = IA_2
        self.IA_3 = IA_3
        self.IA_4 = IA_4
        self.IA_5 = IA_5
        self.IA_6 = IA_6
        self.IA_7 = IA_7
        self.IA_8 = IA_8
        self.IA_11 = IA_11
        self.IA_12 = IA_12


class IR:
    def __init__(self, value: float, IR_1: float, IR_2: float, IR_3: float, IR_4: float, IR_5: float, IR_6: float,
                 IR_7: float, IR_8: float):
        self.value = value
        self.IR_1 = IR_1
        self.IR_2 = IR_2
        self.IR_3 = IR_3
        self.IR_4 = IR_4
        self.IR_5 = IR_5
        self.IR_6 = IR_6
        self.IR_7 = IR_7
        self.IR_8 = IR_8


class MA:
    def __init__(self, value: float, MA_1: float, MA_2: float, MA_3: float, MA_4: float, MA_5: float, MA_6: float):
        self.value = value
        self.MA_1 = MA_1
        self.MA_2 = MA_2
        self.MA_3 = MA_3
        self.MA_4 = MA_4
        self.MA_5 = MA_5
        self.MA_6 = MA_6


class MP:
    def __init__(self, value: float, MP_1: float, MP_2: float, MP_3: float, MP_4: float, MP_5: float, MP_6: float,
                 MP_7: float):
        self.value = value
        self.MP_1 = MP_1
        self.MP_2 = MP_2
        self.MP_3 = MP_3
        self.MP_4 = MP_4
        self.MP_5 = MP_5
        self.MP_6 = MP_6
        self.MP_7 = MP_7


class PE:
    def __init__(self, value: float, PE_1: float, PE_2: float, PE_3: float, PE_4: float, PE_5: float, PE_6: float,
                 PE_8: float, PE_9: float, PE_10: float, PE_11: float, PE_12: float, PE_13: float, PE_14: float,
                 PE_15: float, PE_16: float, PE_17: float, PE_18: float):
        self.value = value
        self.PE_1 = PE_1
        self.PE_2 = PE_2
        self.PE_3 = PE_3
        self.PE_4 = PE_4
        self.PE_5 = PE_5
        self.PE_6 = PE_6
        self.PE_8 = PE_8
        self.PE_9 = PE_9
        self.PE_10 = PE_10
        self.PE_11 = PE_11
        self.PE_12 = PE_12
        self.PE_13 = PE_13
        self.PE_14 = PE_14
        self.PE_15 = PE_15
        self.PE_16 = PE_16
        self.PE_17 = PE_17
        self.PE_18 = PE_18


class PL:
    def __init__(self, value: float, PL_1: float, PL_2: float, PL_4: float, PL_8: float, PL_10: float, PL_11: float):
        self.value = value
        self.PL_1 = PL_1
        self.PL_2 = PL_2
        self.PL_4 = PL_4
        self.PL_8 = PL_8
        self.PL_10 = PL_10
        self.PL_11 = PL_11


class PS:
    def __init__(self, value: float, PS_1: float, PS_2: float, PS_3: float, PS_4: float, PS_5: float, PS_6: float,
                 PS_7: float, PS_8: float, PS_9: float):
        self.value = value
        self.PS_1 = PS_1
        self.PS_2 = PS_2
        self.PS_3 = PS_3
        self.PS_4 = PS_4
        self.PS_5 = PS_5
        self.PS_6 = PS_6
        self.PS_7 = PS_7
        self.PS_8 = PS_8
        self.PS_9 = PS_9


class RA:
    def __init__(self, value: float, RA_1: float, RA_2: float, RA_3: float, RA_5: float, RA_7: float, RA_9: float):
        self.value = value
        self.RA_1 = RA_1
        self.RA_2 = RA_2
        self.RA_3 = RA_3
        self.RA_5 = RA_5
        self.RA_7 = RA_7
        self.RA_9 = RA_9


class SA:
    def __init__(self, value: float, SA_1: float, SA_2: float, SA_3: float, SA_4: float, SA_5: float, SA_8: float,
                 SA_9: float, SA_10: float, SA_11: float, SA_15: float, SA_16: float, SA_17: float, SA_21: float,
                 SA_22: float):
        self.value = value
        self.SA_1 = SA_1
        self.SA_2 = SA_2
        self.SA_3 = SA_3
        self.SA_4 = SA_4
        self.SA_5 = SA_5
        self.SA_8 = SA_8
        self.SA_9 = SA_9
        self.SA_10 = SA_10
        self.SA_11 = SA_11
        self.SA_15 = SA_15
        self.SA_16 = SA_16
        self.SA_17 = SA_17
        self.SA_21 = SA_21
        self.SA_22 = SA_22


class SC:
    def __init__(self, value: float, SC_1: float, SC_2: float, SC_3: float, SC_4: float, SC_5: float, SC_7: float,
                 SC_8: float, SC_10: float, SC_12: float, SC_13: float, SC_15: float, SC_17: float, SC_18: float,
                 SC_20: float, SC_21: float, SC_22: float, SC_23: float, SC_24: float, SC_28: float, SC_39: float):
        self.value = value
        self.SC_1 = SC_1
        self.SC_2 = SC_2
        self.SC_3 = SC_3
        self.SC_4 = SC_4
        self.SC_5 = SC_5
        self.SC_7 = SC_7
        self.SC_8 = SC_8
        self.SC_10 = SC_10
        self.SC_12 = SC_12
        self.SC_13 = SC_13
        self.SC_15 = SC_15
        self.SC_17 = SC_17
        self.SC_18 = SC_18
        self.SC_20 = SC_20
        self.SC_21 = SC_21
        self.SC_22 = SC_22
        self.SC_23 = SC_23
        self.SC_24 = SC_24
        self.SC_28 = SC_28
        self.SC_39 = SC_39


class SI:
    def __init__(self, value: float, SI_1: float, SI_2: float, SI_3: float, SI_4: float, SI_5: float, SI_6: float,
                 SI_7: float, SI_8: float, SI_10: float, SI_11: float, SI_12: float, SI_16: float):
        self.value = value
        self.SI_1 = SI_1
        self.SI_2 = SI_2
        self.SI_3 = SI_3
        self.SI_4 = SI_4
        self.SI_5 = SI_5
        self.SI_6 = SI_6
        self.SI_7 = SI_7
        self.SI_8 = SI_8
        self.SI_10 = SI_10
        self.SI_11 = SI_11
        self.SI_12 = SI_12
        self.SI_16 = SI_16


class SR:
    def __init__(self, value: float, SR_1: float, SR_2: float, SR_3: float, SR_5: float, SR_6: float, SR_8: float,
                 SR_9: float, SR_10: float, SR_11: float, SR_12: float):
        self.value = value
        self.SR_1 = SR_1
        self.SR_2 = SR_2
        self.SR_3 = SR_3
        self.SR_5 = SR_5
        self.SR_6 = SR_6
        self.SR_8 = SR_8
        self.SR_9 = SR_9
        self.SR_10 = SR_10
        self.SR_11 = SR_11
        self.SR_12 = SR_12


class Nist80053_:
    def __init__(self, AT: AT,  RA: RA, ):
        self.AT = AT
        self.RA = RA


class Nist80053:
    def __init__(self, AC: AC, AT: AT, AU: AU, CA: CA, CM: CM, CP: CP, IA: IA, IR: IR, MA: MA, MP: MP, PE: PE,
                 PL: PL, PS: PS, RA: RA, SA: SA, SC: SC, SI: SI, SR: SR):
        self.AC = AC
        self.AT = AT
        self.AU = AU
        self.CA = CA
        self.CM = CM
        self.CP = CP
        self.IA = IA
        self.IR = IR
        self.MA = MA
        self.MP = MP
        self.PE = PE
        self.PL = PL
        self.PS = PS
        self.RA = RA
        self.SA = SA
        self.SC = SC
        self.SI = SI
        self.SR = SR


class CyrceInput:

    def __init__(self,
                 attackMotivators: AttackMotivators,
                 attackSurface: AttackSurface,
                 exploitability: Exploitability,
                 threatActorInput: ThreatActorInput,
                 impact: Impact, scenario: Scenario,
                 csf: CsfFunction, nist80053: Nist80053):
        self.impact = impact
        self.threatActorInput = threatActorInput
        self.attackSurface = attackSurface
        self.exploitability = exploitability
        self.attackMotivators = attackMotivators
        self.csf = csf
        self.nist80053 = nist80053
        self.scenario = scenario


class CyrceTtpCoverageInput:

    def __init__(self, foo):
        self.foo = foo
