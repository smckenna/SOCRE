import networkx as nx
from flask import request
from flask_restful import Resource
import os

from input_module.cyrce_input import CyrceInput, CyrceTtpCoverageInput, \
    AttackMotivators, Exploitability, AttackSurface, ThreatActorInput, Scenario, DirectImpact, Impact, IndirectImpact, \
    CsfFunction, CsfIdentify, CsfProtect, CsfDetect, CsfRespond, CsfRecover, \
    IDAM, IDBE, IDGV, IDRA, IDRM, IDSC, PRAC, PRAT, PRDS, PRIP, PRMA, \
    PRPT, DEAE, DECM, DEDP, RSRP, RSCO, RSAN, RSMI, RSIM, RCRP, RCIM, RCCO, Nist80053, \
    AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PL, PE, PS, RA, SA, SC, SI, SR

from core_module.model_main import run_cyrce
from core_module.analysis import run_ttp_coverage_metric

graph = nx.read_graphml(os.path.join(os.path.dirname(__file__), '../model_resources/enterprise_network_model.graphml'))
bbn_file = os.path.join(os.path.dirname(__file__), '../scenario_module/scenario_bbn.json')


# class Cyrce80053Resource(Resource):
#
#     def post(self):
#         json_data = request.json
#         cyrce_80053_input = self.json_to_input(json_data)
#         response = run_cyrce('80053', cyrce_80053_input, graph, bbn_file)
#         return response.reprJSON()
#
#     def json_to_input(self, json_data):
#         attackMotivators = AttackMotivators(
#             appeal=json_data['attackMotivators']['appeal'],
#             targeting=json_data['attackMotivators']['targeting'],
#             reward=json_data['attackMotivators']['reward'],
#             perceivedDefenses=json_data['attackMotivators']['perceivedDefenses']
#         )
#         return Cyrce80053Input(
#             attackMotivators=attackMotivators)


class CyrceResource(Resource):

    def post(self):
        json_data = request.json
        cyrce_input = self.json_to_input(json_data)
        response = run_cyrce('csf', cyrce_input, graph, bbn_file)
        return response.reprJSON()

    def json_to_input(self, json_data):
        attackMotivators = AttackMotivators(
            appeal=json_data['attackMotivators']['appeal'],
            targeting=json_data['attackMotivators']['targeting'],
            reward=json_data['attackMotivators']['reward'],
            perceivedDefenses=json_data['attackMotivators']['perceivedDefenses']
        )
        exploitability = Exploitability(
            easeOfExploit=json_data['exploitability']['easeOfExploit']
        )
        attackSurface = AttackSurface(
            awareness=json_data['attackSurface']['awareness'],
            opportunity=json_data['attackSurface']['opportunity']
        )
        threatActorInput = ThreatActorInput(
            determination=json_data['threatActor']['determination'],
            resources=json_data['threatActor']['resources'],
            sophistication=json_data['threatActor']['sophistication']
        )
        directImpact = DirectImpact(
            initialResponseCost=json_data['directImpact']['initialResponseCost'],
            productivityLoss=json_data['directImpact']['productivityLoss'],
            replacementCosts=json_data['directImpact']['replacementCosts'],
            safety=json_data['directImpact']['safety']
        )
        indirectImpact = IndirectImpact(
            competitiveAdvantageLoss=json_data['indirectImpact']['competitiveAdvantageLoss'],
            finesAndJudgements=json_data['indirectImpact']['finesAndJudgements'],
            reputationDamage=json_data['indirectImpact']['reputationDamage'],
            secondaryResponseCost=json_data['indirectImpact']['secondaryResponseCost']
        )
        impact = Impact(
            directImpact=directImpact,
            indirectImpact=indirectImpact
        )
        scenario = Scenario(
            attackAction=json_data['scenario']['attackAction'],
            attackThreatType=json_data['scenario']['attackThreatType'],
            attackTarget=json_data['scenario']['attackTarget'],
            attackLossType=json_data['scenario']['attackLossType'],
            attackIndustry=json_data['scenario']['attackIndustry'],
            attackGeography=json_data['scenario']['attackGeography'],
            orgSize=json_data['scenario']['orgSize']
        )
        identify = CsfIdentify(
            value=json_data['csf']['identify']['value'],
            IDAM=IDAM(
                value=json_data['csf']['identify']['ID.AM']['value'],
                IDAM1=json_data['csf']['identify']['ID.AM']['ID.AM-1'],
                IDAM2=json_data['csf']['identify']['ID.AM']['ID.AM-2'],
                IDAM3=json_data['csf']['identify']['ID.AM']['ID.AM-3'],
                IDAM4=json_data['csf']['identify']['ID.AM']['ID.AM-4'],
                IDAM5=json_data['csf']['identify']['ID.AM']['ID.AM-5'],
                IDAM6=json_data['csf']['identify']['ID.AM']['ID.AM-6']
            ),
            IDBE=IDBE(
                value=json_data['csf']['identify']['ID.BE']['value'],
                IDBE1=json_data['csf']['identify']['ID.BE']['ID.BE-1'],
                IDBE2=json_data['csf']['identify']['ID.BE']['ID.BE-2'],
                IDBE3=json_data['csf']['identify']['ID.BE']['ID.BE-3'],
                IDBE4=json_data['csf']['identify']['ID.BE']['ID.BE-4'],
                IDBE5=json_data['csf']['identify']['ID.BE']['ID.BE-5']
            ),
            IDGV=IDGV(
                value=json_data['csf']['identify']['ID.GV']['value'],
                IDGV1=json_data['csf']['identify']['ID.GV']['ID.GV-1'],
                IDGV2=json_data['csf']['identify']['ID.GV']['ID.GV-2'],
                IDGV3=json_data['csf']['identify']['ID.GV']['ID.GV-3'],
                IDGV4=json_data['csf']['identify']['ID.GV']['ID.GV-4']
            ),
            IDRA=IDRA(
                value=json_data['csf']['identify']['ID.RA']['value'],
                IDRA1=json_data['csf']['identify']['ID.RA']['ID.RA-1'],
                IDRA2=json_data['csf']['identify']['ID.RA']['ID.RA-2'],
                IDRA3=json_data['csf']['identify']['ID.RA']['ID.RA-3'],
                IDRA4=json_data['csf']['identify']['ID.RA']['ID.RA-4'],
                IDRA5=json_data['csf']['identify']['ID.RA']['ID.RA-5'],
                IDRA6=json_data['csf']['identify']['ID.RA']['ID.RA-6']
            ),
            IDRM=IDRM(
                value=json_data['csf']['identify']['ID.RM']['value'],
                IDRM1=json_data['csf']['identify']['ID.RM']['ID.RM-1'],
                IDRM2=json_data['csf']['identify']['ID.RM']['ID.RM-2'],
                IDRM3=json_data['csf']['identify']['ID.RM']['ID.RM-3']
            ),
            IDSC=IDSC(
                value=json_data['csf']['identify']['ID.SC']['value'],
                IDSC1=json_data['csf']['identify']['ID.SC']['ID.SC-1'],
                IDSC2=json_data['csf']['identify']['ID.SC']['ID.SC-2'],
                IDSC3=json_data['csf']['identify']['ID.SC']['ID.SC-3'],
                IDSC4=json_data['csf']['identify']['ID.SC']['ID.SC-4'],
                IDSC5=json_data['csf']['identify']['ID.SC']['ID.SC-5']
            )
        )
        protect = CsfProtect(
            value=json_data['csf']['protect']['value'],
            PRAC=PRAC(
                value=json_data['csf']['protect']['PR.AC']['value'],
                PRAC1=json_data['csf']['protect']['PR.AC']['PR.AC-1'],
                PRAC2=json_data['csf']['protect']['PR.AC']['PR.AC-2'],
                PRAC3=json_data['csf']['protect']['PR.AC']['PR.AC-3'],
                PRAC4=json_data['csf']['protect']['PR.AC']['PR.AC-4'],
                PRAC5=json_data['csf']['protect']['PR.AC']['PR.AC-5'],
                PRAC6=json_data['csf']['protect']['PR.AC']['PR.AC-6'],
                PRAC7=json_data['csf']['protect']['PR.AC']['PR.AC-7']
            ),
            PRAT=PRAT(
                value=json_data['csf']['protect']['PR.AT']['value'],
                PRAT1=json_data['csf']['protect']['PR.AT']['PR.AT-1'],
                PRAT2=json_data['csf']['protect']['PR.AT']['PR.AT-2'],
                PRAT3=json_data['csf']['protect']['PR.AT']['PR.AT-3'],
                PRAT4=json_data['csf']['protect']['PR.AT']['PR.AT-4'],
                PRAT5=json_data['csf']['protect']['PR.AT']['PR.AT-5']
            ),
            PRDS=PRDS(
                value=json_data['csf']['protect']['PR.DS']['value'],
                PRDS1=json_data['csf']['protect']['PR.DS']['PR.DS-1'],
                PRDS2=json_data['csf']['protect']['PR.DS']['PR.DS-2'],
                PRDS3=json_data['csf']['protect']['PR.DS']['PR.DS-3'],
                PRDS4=json_data['csf']['protect']['PR.DS']['PR.DS-4'],
                PRDS5=json_data['csf']['protect']['PR.DS']['PR.DS-5'],
                PRDS6=json_data['csf']['protect']['PR.DS']['PR.DS-6'],
                PRDS7=json_data['csf']['protect']['PR.DS']['PR.DS-7'],
                PRDS8=json_data['csf']['protect']['PR.DS']['PR.DS-8']
            ),
            PRIP=PRIP(
                value=json_data['csf']['protect']['PR.IP']['value'],
                PRIP1=json_data['csf']['protect']['PR.IP']['PR.IP-1'],
                PRIP2=json_data['csf']['protect']['PR.IP']['PR.IP-2'],
                PRIP3=json_data['csf']['protect']['PR.IP']['PR.IP-3'],
                PRIP4=json_data['csf']['protect']['PR.IP']['PR.IP-4'],
                PRIP5=json_data['csf']['protect']['PR.IP']['PR.IP-5'],
                PRIP6=json_data['csf']['protect']['PR.IP']['PR.IP-6'],
                PRIP7=json_data['csf']['protect']['PR.IP']['PR.IP-7'],
                PRIP8=json_data['csf']['protect']['PR.IP']['PR.IP-8'],
                PRIP9=json_data['csf']['protect']['PR.IP']['PR.IP-9'],
                PRIP10=json_data['csf']['protect']['PR.IP']['PR.IP-10'],
                PRIP11=json_data['csf']['protect']['PR.IP']['PR.IP-11'],
                PRIP12=json_data['csf']['protect']['PR.IP']['PR.IP-12']
            ),
            PRMA=PRMA(
                value=json_data['csf']['protect']['PR.MA']['value'],
                PRMA1=json_data['csf']['protect']['PR.MA']['PR.MA-1'],
                PRMA2=json_data['csf']['protect']['PR.MA']['PR.MA-2']
            ),
            PRPT=PRPT(
                value=json_data['csf']['protect']['PR.PT']['value'],
                PRPT1=json_data['csf']['protect']['PR.PT']['PR.PT-1'],
                PRPT2=json_data['csf']['protect']['PR.PT']['PR.PT-2'],
                PRPT3=json_data['csf']['protect']['PR.PT']['PR.PT-3'],
                PRPT4=json_data['csf']['protect']['PR.PT']['PR.PT-4'],
                PRPT5=json_data['csf']['protect']['PR.PT']['PR.PT-5']
            )
        )
        detect = CsfDetect(
            value=json_data['csf']['detect']['value'],
            DEAE=DEAE(
                value=json_data['csf']['detect']['DE.AE']['value'],
                DEAE1=json_data['csf']['detect']['DE.AE']['DE.AE-1'],
                DEAE2=json_data['csf']['detect']['DE.AE']['DE.AE-2'],
                DEAE3=json_data['csf']['detect']['DE.AE']['DE.AE-3'],
                DEAE4=json_data['csf']['detect']['DE.AE']['DE.AE-4'],
                DEAE5=json_data['csf']['detect']['DE.AE']['DE.AE-5']
            ),
            DECM=DECM(
                value=json_data['csf']['detect']['DE.CM']['value'],
                DECM1=json_data['csf']['detect']['DE.CM']['DE.CM-1'],
                DECM2=json_data['csf']['detect']['DE.CM']['DE.CM-2'],
                DECM3=json_data['csf']['detect']['DE.CM']['DE.CM-3'],
                DECM4=json_data['csf']['detect']['DE.CM']['DE.CM-4'],
                DECM5=json_data['csf']['detect']['DE.CM']['DE.CM-5'],
                DECM6=json_data['csf']['detect']['DE.CM']['DE.CM-6'],
                DECM7=json_data['csf']['detect']['DE.CM']['DE.CM-7'],
                DECM8=json_data['csf']['detect']['DE.CM']['DE.CM-8']
            ),
            DEDP=DEDP(
                value=json_data['csf']['detect']['DE.DP']['value'],
                DEDP1=json_data['csf']['detect']['DE.DP']['DE.DP-1'],
                DEDP2=json_data['csf']['detect']['DE.DP']['DE.DP-2'],
                DEDP3=json_data['csf']['detect']['DE.DP']['DE.DP-3'],
                DEDP4=json_data['csf']['detect']['DE.DP']['DE.DP-4'],
                DEDP5=json_data['csf']['detect']['DE.DP']['DE.DP-5']
            )
        )

        respond = CsfRespond(
            value=json_data['csf']['respond']['value'],
            RSRP=RSRP(
                value=json_data['csf']['respond']['RS.RP']['value'],
                RSRP1=json_data['csf']['respond']['RS.RP']['RS.RP-1']
            ),
            RSCO=RSCO(
                value=json_data['csf']['respond']['RS.CO']['value'],
                RSCO1=json_data['csf']['respond']['RS.CO']['RS.CO-1'],
                RSCO2=json_data['csf']['respond']['RS.CO']['RS.CO-2'],
                RSCO3=json_data['csf']['respond']['RS.CO']['RS.CO-3'],
                RSCO4=json_data['csf']['respond']['RS.CO']['RS.CO-4'],
                RSCO5=json_data['csf']['respond']['RS.CO']['RS.CO-5']
            ),
            RSAN=RSAN(
                value=json_data['csf']['respond']['RS.AN']['value'],
                RSAN1=json_data['csf']['respond']['RS.AN']['RS.AN-1'],
                RSAN2=json_data['csf']['respond']['RS.AN']['RS.AN-2'],
                RSAN3=json_data['csf']['respond']['RS.AN']['RS.AN-3'],
                RSAN4=json_data['csf']['respond']['RS.AN']['RS.AN-4'],
                RSAN5=json_data['csf']['respond']['RS.AN']['RS.AN-5']
            ),
            RSMI=RSMI(
                value=json_data['csf']['respond']['RS.MI']['value'],
                RSMI1=json_data['csf']['respond']['RS.MI']['RS.MI-1'],
                RSMI2=json_data['csf']['respond']['RS.MI']['RS.MI-2'],
                RSMI3=json_data['csf']['respond']['RS.MI']['RS.MI-3']
            ),
            RSIM=RSIM(
                value=json_data['csf']['respond']['RS.IM']['value'],
                RSIM1=json_data['csf']['respond']['RS.IM']['RS.IM-1'],
                RSIM2=json_data['csf']['respond']['RS.IM']['RS.IM-2']
            )
        )
        recover = CsfRecover(
            value=json_data['csf']['recover']['value'],
            RCRP=RCRP(
                value=json_data['csf']['recover']['RC.RP']['value'],
                RCRP1=json_data['csf']['recover']['RC.RP']['RC.RP-1']
            ),
            RCIM=RCIM(
                value=json_data['csf']['recover']['RC.IM']['value'],
                RCIM1=json_data['csf']['recover']['RC.IM']['RC.IM-1'],
                RCIM2=json_data['csf']['recover']['RC.IM']['RC.IM-2']
            ),
            RCCO=RCCO(
                value=json_data['csf']['recover']['RC.CO']['value'],
                RCCO1=json_data['csf']['recover']['RC.CO']['RC.CO-1'],
                RCCO2=json_data['csf']['recover']['RC.CO']['RC.CO-2'],
                RCCO3=json_data['csf']['recover']['RC.CO']['RC.CO-3']
            )
        )
        csf = CsfFunction(
            identify=identify,
            protect=protect,
            detect=detect,
            respond=respond,
            recover=recover
        )

        ac = AC(value=json_data['nist80053']['AC'],
                AC_1=json_data['nist80053']['AC']['AC-1'],
                AC_2=json_data['nist80053']['AC']['AC-2'],
                AC_3=json_data['nist80053']['AC']['AC-3'],
                AC_4=json_data['nist80053']['AC']['AC-4'],
                AC_5=json_data['nist80053']['AC']['AC-5'],
                AC_6=json_data['nist80053']['AC']['AC-6'],
                AC_7=json_data['nist80053']['AC']['AC-7'],
                AC_8=json_data['nist80053']['AC']['AC-8'],
                AC_10=json_data['nist80053']['AC']['AC-10'],
                AC_11=json_data['nist80053']['AC']['AC-11'],
                AC_12=json_data['nist80053']['AC']['AC-12'],
                AC_14=json_data['nist80053']['AC']['AC-14'],
                AC_17=json_data['nist80053']['AC']['AC-17'],
                AC_18=json_data['nist80053']['AC']['AC-18'],
                AC_19=json_data['nist80053']['AC']['AC-19'],
                AC_20=json_data['nist80053']['AC']['AC-20'],
                AC_21=json_data['nist80053']['AC']['AC-21'],
                AC_22=json_data['nist80053']['AC']['AC-22'])
        at = AT(value=json_data['nist80053']['AT'],
                AT_1=json_data['nist80053']['AT']['AT-1'],
                AT_2=json_data['nist80053']['AT']['AT-2'],
                AT_3=json_data['nist80053']['AT']['AT-3'],
                AT_4=json_data['nist80053']['AT']['AT-4'])
        au = AU(value=json_data['nist80053']['AU'],
                AU_1=json_data['nist80053']['AU']['AU-1'],
                AU_2=json_data['nist80053']['AU']['AU-2'],
                AU_3=json_data['nist80053']['AU']['AU-3'],
                AU_4=json_data['nist80053']['AU']['AU-4'],
                AU_5=json_data['nist80053']['AU']['AU-5'],
                AU_6=json_data['nist80053']['AU']['AU-6'],
                AU_7=json_data['nist80053']['AU']['AU-7'],
                AU_8=json_data['nist80053']['AU']['AU-8'],
                AU_9=json_data['nist80053']['AU']['AU-9'],
                AU_10=json_data['nist80053']['AU']['AU-10'],
                AU_11=json_data['nist80053']['AU']['AU-11'],
                AU_12=json_data['nist80053']['AU']['AU-12'])
        ca = CA(value=json_data['nist80053']['CA'],
                CA_1=json_data['nist80053']['CA']['CA-1'],
                CA_2=json_data['nist80053']['CA']['CA-2'],
                CA_3=json_data['nist80053']['CA']['CA-3'],
                CA_5=json_data['nist80053']['CA']['CA-5'],
                CA_6=json_data['nist80053']['CA']['CA-6'],
                CA_7=json_data['nist80053']['CA']['CA-7'],
                CA_8=json_data['nist80053']['CA']['CA-8'],
                CA_9=json_data['nist80053']['CA']['CA-9'])
        cm = CM(value=json_data['nist80053']['CM'],
                CM_1=json_data['nist80053']['CM']['CM-1'],
                CM_2=json_data['nist80053']['CM']['CM-2'],
                CM_3=json_data['nist80053']['CM']['CM-3'],
                CM_4=json_data['nist80053']['CM']['CM-4'],
                CM_5=json_data['nist80053']['CM']['CM-5'],
                CM_6=json_data['nist80053']['CM']['CM-6'],
                CM_7=json_data['nist80053']['CM']['CM-7'],
                CM_8=json_data['nist80053']['CM']['CM-8'],
                CM_9=json_data['nist80053']['CM']['CM-9'],
                CM_10=json_data['nist80053']['CM']['CM-10'],
                CM_11=json_data['nist80053']['CM']['CM-11'],
                CM_12=json_data['nist80053']['CM']['CM-12'])
        cp = CP(value=json_data['nist80053']['CP'],
                CP_1=json_data['nist80053']['CP']['CP-1'],
                CP_2=json_data['nist80053']['CP']['CP-2'],
                CP_3=json_data['nist80053']['CP']['CP-3'],
                CP_4=json_data['nist80053']['CP']['CP-4'],
                CP_6=json_data['nist80053']['CP']['CP-6'],
                CP_7=json_data['nist80053']['CP']['CP-7'],
                CP_8=json_data['nist80053']['CP']['CP-8'],
                CP_9=json_data['nist80053']['CP']['CP-9'],
                CP_10=json_data['nist80053']['CP']['CP-10'])
        ia = IA(value=json_data['nist80053']['IA'],
                IA_1=json_data['nist80053']['IA']['IA-1'],
                IA_2=json_data['nist80053']['IA']['IA-2'],
                IA_3=json_data['nist80053']['IA']['IA-3'],
                IA_4=json_data['nist80053']['IA']['IA-4'],
                IA_5=json_data['nist80053']['IA']['IA-5'],
                IA_6=json_data['nist80053']['IA']['IA-6'],
                IA_7=json_data['nist80053']['IA']['IA-7'],
                IA_8=json_data['nist80053']['IA']['IA-8'],
                IA_11=json_data['nist80053']['IA']['IA-11'],
                IA_12=json_data['nist80053']['IA']['IA-12'])
        ir = IR(value=json_data['nist80053']['IR'],
                IR_1=json_data['nist80053']['IR']['IR-1'],
                IR_2=json_data['nist80053']['IR']['IR-2'],
                IR_3=json_data['nist80053']['IR']['IR-3'],
                IR_4=json_data['nist80053']['IR']['IR-4'],
                IR_5=json_data['nist80053']['IR']['IR-5'],
                IR_6=json_data['nist80053']['IR']['IR-6'],
                IR_7=json_data['nist80053']['IR']['IR-7'],
                IR_8=json_data['nist80053']['IR']['IR-8'])
        ma = MA(value=json_data['nist80053']['MA'],
                MA_1=json_data['nist80053']['MA']['MA-1'],
                MA_2=json_data['nist80053']['MA']['MA-2'],
                MA_3=json_data['nist80053']['MA']['MA-3'],
                MA_4=json_data['nist80053']['MA']['MA-4'],
                MA_5=json_data['nist80053']['MA']['MA-5'],
                MA_6=json_data['nist80053']['MA']['MA-6'])
        mp = MP(value=json_data['nist80053']['MP'],
                MP_1=json_data['nist80053']['MP']['MP-1'],
                MP_2=json_data['nist80053']['MP']['MP-2'],
                MP_3=json_data['nist80053']['MP']['MP-3'],
                MP_4=json_data['nist80053']['MP']['MP-4'],
                MP_5=json_data['nist80053']['MP']['MP-5'],
                MP_6=json_data['nist80053']['MP']['MP-6'],
                MP_7=json_data['nist80053']['MP']['MP-7'])
        pe = PE(value=json_data['nist80053']['PE'],
                PE_1=json_data['nist80053']['PE']['PE-1'],
                PE_2=json_data['nist80053']['PE']['PE-2'],
                PE_3=json_data['nist80053']['PE']['PE-3'],
                PE_4=json_data['nist80053']['PE']['PE-4'],
                PE_5=json_data['nist80053']['PE']['PE-5'],
                PE_6=json_data['nist80053']['PE']['PE-6'],
                PE_8=json_data['nist80053']['PE']['PE-8'],
                PE_9=json_data['nist80053']['PE']['PE-9'],
                PE_10=json_data['nist80053']['PE']['PE-10'],
                PE_11=json_data['nist80053']['PE']['PE-11'],
                PE_12=json_data['nist80053']['PE']['PE-12'],
                PE_13=json_data['nist80053']['PE']['PE-13'],
                PE_14=json_data['nist80053']['PE']['PE-14'],
                PE_15=json_data['nist80053']['PE']['PE-15'],
                PE_16=json_data['nist80053']['PE']['PE-16'],
                PE_17=json_data['nist80053']['PE']['PE-17'],
                PE_18=json_data['nist80053']['PE']['PE-18'])
        pl = PL(value=json_data['nist80053']['PL'],
                PL_1=json_data['nist80053']['PL']['PL-1'],
                PL_2=json_data['nist80053']['PL']['PL-2'],
                PL_4=json_data['nist80053']['PL']['PL-4'],
                PL_8=json_data['nist80053']['PL']['PL-8'],
                PL_10=json_data['nist80053']['PL']['PL-10'],
                PL_11=json_data['nist80053']['PL']['PL-11'])
        ps = PS(value=json_data['nist80053']['PS'],
                PS_1=json_data['nist80053']['PS']['PS-1'],
                PS_2=json_data['nist80053']['PS']['PS-2'],
                PS_3=json_data['nist80053']['PS']['PS-3'],
                PS_4=json_data['nist80053']['PS']['PS-4'],
                PS_5=json_data['nist80053']['PS']['PS-5'],
                PS_6=json_data['nist80053']['PS']['PS-6'],
                PS_7=json_data['nist80053']['PS']['PS-7'],
                PS_8=json_data['nist80053']['PS']['PS-8'],
                PS_9=json_data['nist80053']['PS']['PS-9'])
        ra = RA(value=json_data['nist80053']['RA'],
                RA_1=json_data['nist80053']['RA']['RA-1'],
                RA_2=json_data['nist80053']['RA']['RA-2'],
                RA_3=json_data['nist80053']['RA']['RA-3'],
                RA_5=json_data['nist80053']['RA']['RA-5'],
                RA_7=json_data['nist80053']['RA']['RA-7'],
                RA_9=json_data['nist80053']['RA']['RA-9'])
        sa = SA(value=json_data['nist80053']['SA'],
                SA_1=json_data['nist80053']['SA']['SA-1'],
                SA_2=json_data['nist80053']['SA']['SA-2'],
                SA_3=json_data['nist80053']['SA']['SA-3'],
                SA_4=json_data['nist80053']['SA']['SA-4'],
                SA_5=json_data['nist80053']['SA']['SA-5'],
                SA_8=json_data['nist80053']['SA']['SA-8'],
                SA_9=json_data['nist80053']['SA']['SA-9'],
                SA_10=json_data['nist80053']['SA']['SA-10'],
                SA_11=json_data['nist80053']['SA']['SA-11'],
                SA_15=json_data['nist80053']['SA']['SA-15'],
                SA_16=json_data['nist80053']['SA']['SA-16'],
                SA_17=json_data['nist80053']['SA']['SA-17'],
                SA_21=json_data['nist80053']['SA']['SA-21'],
                SA_22=json_data['nist80053']['SA']['SA-22'])
        sc = SC(value=json_data['nist80053']['SC'],
                SC_1=json_data['nist80053']['SC']['SC-1'],
                SC_2=json_data['nist80053']['SC']['SC-2'],
                SC_3=json_data['nist80053']['SC']['SC-3'],
                SC_4=json_data['nist80053']['SC']['SC-4'],
                SC_5=json_data['nist80053']['SC']['SC-5'],
                SC_7=json_data['nist80053']['SC']['SC-7'],
                SC_8=json_data['nist80053']['SC']['SC-8'],
                SC_10=json_data['nist80053']['SC']['SC-10'],
                SC_12=json_data['nist80053']['SC']['SC-12'],
                SC_13=json_data['nist80053']['SC']['SC-13'],
                SC_15=json_data['nist80053']['SC']['SC-15'],
                SC_17=json_data['nist80053']['SC']['SC-17'],
                SC_18=json_data['nist80053']['SC']['SC-18'],
                SC_20=json_data['nist80053']['SC']['SC-20'],
                SC_21=json_data['nist80053']['SC']['SC-21'],
                SC_22=json_data['nist80053']['SC']['SC-22'],
                SC_23=json_data['nist80053']['SC']['SC-23'],
                SC_24=json_data['nist80053']['SC']['SC-24'],
                SC_28=json_data['nist80053']['SC']['SC-28'],
                SC_39=json_data['nist80053']['SC']['SC-39'])
        si = SI(value=json_data['nist80053']['SI'],
                SI_1=json_data['nist80053']['SI']['SI-1'],
                SI_2=json_data['nist80053']['SI']['SI-2'],
                SI_3=json_data['nist80053']['SI']['SI-3'],
                SI_4=json_data['nist80053']['SI']['SI-4'],
                SI_5=json_data['nist80053']['SI']['SI-5'],
                SI_6=json_data['nist80053']['SI']['SI-6'],
                SI_7=json_data['nist80053']['SI']['SI-7'],
                SI_8=json_data['nist80053']['SI']['SI-8'],
                SI_10=json_data['nist80053']['SI']['SI-10'],
                SI_11=json_data['nist80053']['SI']['SI-11'],
                SI_12=json_data['nist80053']['SI']['SI-12'],
                SI_16=json_data['nist80053']['SI']['SI-16'])
        sr = SR(value=json_data['nist80053']['SR'],
                SR_1=json_data['nist80053']['SR']['SR-1'],
                SR_2=json_data['nist80053']['SR']['SR-2'],
                SR_3=json_data['nist80053']['SR']['SR-3'],
                SR_5=json_data['nist80053']['SR']['SR-5'],
                SR_6=json_data['nist80053']['SR']['SR-6'],
                SR_8=json_data['nist80053']['SR']['SR-8'],
                SR_9=json_data['nist80053']['SR']['SR-9'],
                SR_10=json_data['nist80053']['SR']['SR-10'],
                SR_11=json_data['nist80053']['SR']['SR-11'],
                SR_12=json_data['nist80053']['SR']['SR-12'])

        nist80053 = Nist80053(AC=ac, AT=at, AU=au, CA=ca, CM=cm, CP=cp, IA=ia, IR=ir, MA=ma, MP=mp, PE=pe, PL=pl, PS=ps, \
                              RA=ra, SA=sa, SC=sc, SI=si, SR=sr)

        return CyrceInput(
            attackMotivators=attackMotivators,
            exploitability=exploitability,
            attackSurface=attackSurface,
            threatActorInput=threatActorInput,
            csf=csf,
            nist80053=nist80053,
            impact=impact,
            scenario=scenario
        )


class CyrceTtpCoverageResource(Resource):

    def post(self):
        json_data = request.json
        cyrce_ttp_coverage_input = self.json_to_input(json_data)
        response = run_ttp_coverage_metric(cyrce_ttp_coverage_input)
        return response.reprJSON()

    def json_to_input(self, json_data):
        foo = 1
        return CyrceTtpCoverageInput(foo=foo)
