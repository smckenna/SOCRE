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

from core_module.model_main import run_cyrce, run_cyrce_ttp_coverage

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

        ac = AC(value=json_data['nist80053']['AC']['value'],
                AC_1=json_data['nist80053']['AC']['AC_1']['value'],
                AC_2=json_data['nist80053']['AC']['AC_2']['value'],
                AC_3=json_data['nist80053']['AC']['AC_3']['value'],
                AC_4=json_data['nist80053']['AC']['AC_4']['value'],
                AC_5=json_data['nist80053']['AC']['AC_5']['value'],
                AC_6=json_data['nist80053']['AC']['AC_6']['value'],
                AC_7=json_data['nist80053']['AC']['AC_7']['value'],
                AC_8=json_data['nist80053']['AC']['AC_8']['value'],
                AC_10=json_data['nist80053']['AC']['AC_10']['value'],
                AC_11=json_data['nist80053']['AC']['AC_11']['value'],
                AC_12=json_data['nist80053']['AC']['AC_12']['value'],
                AC_14=json_data['nist80053']['AC']['AC_14']['value'],
                AC_17=json_data['nist80053']['AC']['AC_17']['value'],
                AC_18=json_data['nist80053']['AC']['AC_18']['value'],
                AC_19=json_data['nist80053']['AC']['AC_19']['value'],
                AC_20=json_data['nist80053']['AC']['AC_20']['value'],
                AC_21=json_data['nist80053']['AC']['AC_21']['value'],
                AC_22=json_data['nist80053']['AC']['AC_22']['value'])
        at = AT(value=json_data['nist80053']['AT']['value'],
                AT_1=json_data['nist80053']['AT']['AT_1']['value'],
                AT_2=json_data['nist80053']['AT']['AT_2']['value'],
                AT_3=json_data['nist80053']['AT']['AT_3']['value'],
                AT_4=json_data['nist80053']['AT']['AT_4']['value'])
        au = AU(value=json_data['nist80053']['AU']['value'],
                AU_1=json_data['nist80053']['AU']['AU_1']['value'],
                AU_2=json_data['nist80053']['AU']['AU_2']['value'],
                AU_3=json_data['nist80053']['AU']['AU_3']['value'],
                AU_4=json_data['nist80053']['AU']['AU_4']['value'],
                AU_5=json_data['nist80053']['AU']['AU_5']['value'],
                AU_6=json_data['nist80053']['AU']['AU_6']['value'],
                AU_7=json_data['nist80053']['AU']['AU_7']['value'],
                AU_8=json_data['nist80053']['AU']['AU_8']['value'],
                AU_9=json_data['nist80053']['AU']['AU_9']['value'],
                AU_10=json_data['nist80053']['AU']['AU_10']['value'],
                AU_11=json_data['nist80053']['AU']['AU_11']['value'],
                AU_12=json_data['nist80053']['AU']['AU_12']['value'])
        ca = CA(value=json_data['nist80053']['CA']['value'],
                CA_1=json_data['nist80053']['CA']['CA_1']['value'],
                CA_2=json_data['nist80053']['CA']['CA_2']['value'],
                CA_3=json_data['nist80053']['CA']['CA_3']['value'],
                CA_5=json_data['nist80053']['CA']['CA_5']['value'],
                CA_6=json_data['nist80053']['CA']['CA_6']['value'],
                CA_7=json_data['nist80053']['CA']['CA_7']['value'],
                CA_8=json_data['nist80053']['CA']['CA_8']['value'],
                CA_9=json_data['nist80053']['CA']['CA_9']['value'])
        cm = CM(value=json_data['nist80053']['CM']['value'],
                CM_1=json_data['nist80053']['CM']['CM_1']['value'],
                CM_2=json_data['nist80053']['CM']['CM_2']['value'],
                CM_3=json_data['nist80053']['CM']['CM_3']['value'],
                CM_4=json_data['nist80053']['CM']['CM_4']['value'],
                CM_5=json_data['nist80053']['CM']['CM_5']['value'],
                CM_6=json_data['nist80053']['CM']['CM_6']['value'],
                CM_7=json_data['nist80053']['CM']['CM_7']['value'],
                CM_8=json_data['nist80053']['CM']['CM_8']['value'],
                CM_9=json_data['nist80053']['CM']['CM_9']['value'],
                CM_10=json_data['nist80053']['CM']['CM_10']['value'],
                CM_11=json_data['nist80053']['CM']['CM_11']['value'],
                CM_12=json_data['nist80053']['CM']['CM_12']['value'])
        cp = CP(value=json_data['nist80053']['CP']['value'],
                CP_1=json_data['nist80053']['CP']['CP_1']['value'],
                CP_2=json_data['nist80053']['CP']['CP_2']['value'],
                CP_3=json_data['nist80053']['CP']['CP_3']['value'],
                CP_4=json_data['nist80053']['CP']['CP_4']['value'],
                CP_6=json_data['nist80053']['CP']['CP_6']['value'],
                CP_7=json_data['nist80053']['CP']['CP_7']['value'],
                CP_8=json_data['nist80053']['CP']['CP_8']['value'],
                CP_9=json_data['nist80053']['CP']['CP_9']['value'],
                CP_10=json_data['nist80053']['CP']['CP_10']['value'])
        ia = IA(value=json_data['nist80053']['IA']['value'],
                IA_1=json_data['nist80053']['IA']['IA_1']['value'],
                IA_2=json_data['nist80053']['IA']['IA_2']['value'],
                IA_3=json_data['nist80053']['IA']['IA_3']['value'],
                IA_4=json_data['nist80053']['IA']['IA_4']['value'],
                IA_5=json_data['nist80053']['IA']['IA_5']['value'],
                IA_6=json_data['nist80053']['IA']['IA_6']['value'],
                IA_7=json_data['nist80053']['IA']['IA_7']['value'],
                IA_8=json_data['nist80053']['IA']['IA_8']['value'],
                IA_11=json_data['nist80053']['IA']['IA_11']['value'],
                IA_12=json_data['nist80053']['IA']['IA_12']['value'])
        ir = IR(value=json_data['nist80053']['IR']['value'],
                IR_1=json_data['nist80053']['IR']['IR_1']['value'],
                IR_2=json_data['nist80053']['IR']['IR_2']['value'],
                IR_3=json_data['nist80053']['IR']['IR_3']['value'],
                IR_4=json_data['nist80053']['IR']['IR_4']['value'],
                IR_5=json_data['nist80053']['IR']['IR_5']['value'],
                IR_6=json_data['nist80053']['IR']['IR_6']['value'],
                IR_7=json_data['nist80053']['IR']['IR_7']['value'],
                IR_8=json_data['nist80053']['IR']['IR_8']['value'])
        ma = MA(value=json_data['nist80053']['MA']['value'],
                MA_1=json_data['nist80053']['MA']['MA_1']['value'],
                MA_2=json_data['nist80053']['MA']['MA_2']['value'],
                MA_3=json_data['nist80053']['MA']['MA_3']['value'],
                MA_4=json_data['nist80053']['MA']['MA_4']['value'],
                MA_5=json_data['nist80053']['MA']['MA_5']['value'],
                MA_6=json_data['nist80053']['MA']['MA_6']['value'])
        mp = MP(value=json_data['nist80053']['MP']['value'],
                MP_1=json_data['nist80053']['MP']['MP_1']['value'],
                MP_2=json_data['nist80053']['MP']['MP_2']['value'],
                MP_3=json_data['nist80053']['MP']['MP_3']['value'],
                MP_4=json_data['nist80053']['MP']['MP_4']['value'],
                MP_5=json_data['nist80053']['MP']['MP_5']['value'],
                MP_6=json_data['nist80053']['MP']['MP_6']['value'],
                MP_7=json_data['nist80053']['MP']['MP_7']['value'])
        pe = PE(value=json_data['nist80053']['PE']['value'],
                PE_1=json_data['nist80053']['PE']['PE_1']['value'],
                PE_2=json_data['nist80053']['PE']['PE_2']['value'],
                PE_3=json_data['nist80053']['PE']['PE_3']['value'],
                PE_4=json_data['nist80053']['PE']['PE_4']['value'],
                PE_5=json_data['nist80053']['PE']['PE_5']['value'],
                PE_6=json_data['nist80053']['PE']['PE_6']['value'],
                PE_8=json_data['nist80053']['PE']['PE_8']['value'],
                PE_9=json_data['nist80053']['PE']['PE_9']['value'],
                PE_10=json_data['nist80053']['PE']['PE_10']['value'],
                PE_11=json_data['nist80053']['PE']['PE_11']['value'],
                PE_12=json_data['nist80053']['PE']['PE_12']['value'],
                PE_13=json_data['nist80053']['PE']['PE_13']['value'],
                PE_14=json_data['nist80053']['PE']['PE_14']['value'],
                PE_15=json_data['nist80053']['PE']['PE_15']['value'],
                PE_16=json_data['nist80053']['PE']['PE_16']['value'],
                PE_17=json_data['nist80053']['PE']['PE_17']['value'],
                PE_18=json_data['nist80053']['PE']['PE_18']['value'])
        pl = PL(value=json_data['nist80053']['PL']['value'],
                PL_1=json_data['nist80053']['PL']['PL_1']['value'],
                PL_2=json_data['nist80053']['PL']['PL_2']['value'],
                PL_4=json_data['nist80053']['PL']['PL_4']['value'],
                PL_8=json_data['nist80053']['PL']['PL_8']['value'],
                PL_10=json_data['nist80053']['PL']['PL_10']['value'],
                PL_11=json_data['nist80053']['PL']['PL_11']['value'])
        ps = PS(value=json_data['nist80053']['PS']['value'],
                PS_1=json_data['nist80053']['PS']['PS_1']['value'],
                PS_2=json_data['nist80053']['PS']['PS_2']['value'],
                PS_3=json_data['nist80053']['PS']['PS_3']['value'],
                PS_4=json_data['nist80053']['PS']['PS_4']['value'],
                PS_5=json_data['nist80053']['PS']['PS_5']['value'],
                PS_6=json_data['nist80053']['PS']['PS_6']['value'],
                PS_7=json_data['nist80053']['PS']['PS_7']['value'],
                PS_8=json_data['nist80053']['PS']['PS_8']['value'],
                PS_9=json_data['nist80053']['PS']['PS_9']['value'])
        ra = RA(value=json_data['nist80053']['RA']['value'],
                RA_1=json_data['nist80053']['RA']['RA_1']['value'],
                RA_2=json_data['nist80053']['RA']['RA_2']['value'],
                RA_3=json_data['nist80053']['RA']['RA_3']['value'],
                RA_5=json_data['nist80053']['RA']['RA_5']['value'],
                RA_7=json_data['nist80053']['RA']['RA_7']['value'],
                RA_9=json_data['nist80053']['RA']['RA_9']['value'])
        sa = SA(value=json_data['nist80053']['SA']['value'],
                SA_1=json_data['nist80053']['SA']['SA_1']['value'],
                SA_2=json_data['nist80053']['SA']['SA_2']['value'],
                SA_3=json_data['nist80053']['SA']['SA_3']['value'],
                SA_4=json_data['nist80053']['SA']['SA_4']['value'],
                SA_5=json_data['nist80053']['SA']['SA_5']['value'],
                SA_8=json_data['nist80053']['SA']['SA_8']['value'],
                SA_9=json_data['nist80053']['SA']['SA_9']['value'],
                SA_10=json_data['nist80053']['SA']['SA_10']['value'],
                SA_11=json_data['nist80053']['SA']['SA_11']['value'],
                SA_15=json_data['nist80053']['SA']['SA_15']['value'],
                SA_16=json_data['nist80053']['SA']['SA_16']['value'],
                SA_17=json_data['nist80053']['SA']['SA_17']['value'],
                SA_21=json_data['nist80053']['SA']['SA_21']['value'],
                SA_22=json_data['nist80053']['SA']['SA_22']['value'])
        sc = SC(value=json_data['nist80053']['SC']['value'],
                SC_1=json_data['nist80053']['SC']['SC_1']['value'],
                SC_2=json_data['nist80053']['SC']['SC_2']['value'],
                SC_3=json_data['nist80053']['SC']['SC_3']['value'],
                SC_4=json_data['nist80053']['SC']['SC_4']['value'],
                SC_5=json_data['nist80053']['SC']['SC_5']['value'],
                SC_7=json_data['nist80053']['SC']['SC_7']['value'],
                SC_8=json_data['nist80053']['SC']['SC_8']['value'],
                SC_10=json_data['nist80053']['SC']['SC_10']['value'],
                SC_12=json_data['nist80053']['SC']['SC_12']['value'],
                SC_13=json_data['nist80053']['SC']['SC_13']['value'],
                SC_15=json_data['nist80053']['SC']['SC_15']['value'],
                SC_17=json_data['nist80053']['SC']['SC_17']['value'],
                SC_18=json_data['nist80053']['SC']['SC_18']['value'],
                SC_20=json_data['nist80053']['SC']['SC_20']['value'],
                SC_21=json_data['nist80053']['SC']['SC_21']['value'],
                SC_22=json_data['nist80053']['SC']['SC_22']['value'],
                SC_23=json_data['nist80053']['SC']['SC_23']['value'],
                SC_24=json_data['nist80053']['SC']['SC_24']['value'],
                SC_28=json_data['nist80053']['SC']['SC_28']['value'],
                SC_39=json_data['nist80053']['SC']['SC_39']['value'])
        si = SI(value=json_data['nist80053']['SI']['value'],
                SI_1=json_data['nist80053']['SI']['SI_1']['value'],
                SI_2=json_data['nist80053']['SI']['SI_2']['value'],
                SI_3=json_data['nist80053']['SI']['SI_3']['value'],
                SI_4=json_data['nist80053']['SI']['SI_4']['value'],
                SI_5=json_data['nist80053']['SI']['SI_5']['value'],
                SI_6=json_data['nist80053']['SI']['SI_6']['value'],
                SI_7=json_data['nist80053']['SI']['SI_7']['value'],
                SI_8=json_data['nist80053']['SI']['SI_8']['value'],
                SI_10=json_data['nist80053']['SI']['SI_10']['value'],
                SI_11=json_data['nist80053']['SI']['SI_11']['value'],
                SI_12=json_data['nist80053']['SI']['SI_12']['value'],
                SI_16=json_data['nist80053']['SI']['SI_16']['value'])
        sr = SR(value=json_data['nist80053']['SR']['value'],
                SR_1=json_data['nist80053']['SR']['SR_1']['value'],
                SR_2=json_data['nist80053']['SR']['SR_2']['value'],
                SR_3=json_data['nist80053']['SR']['SR_3']['value'],
                SR_5=json_data['nist80053']['SR']['SR_5']['value'],
                SR_6=json_data['nist80053']['SR']['SR_6']['value'],
                SR_8=json_data['nist80053']['SR']['SR_8']['value'],
                SR_9=json_data['nist80053']['SR']['SR_9']['value'],
                SR_10=json_data['nist80053']['SR']['SR_10']['value'],
                SR_11=json_data['nist80053']['SR']['SR_11']['value'],
                SR_12=json_data['nist80053']['SR']['SR_12']['value'])

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
        response = run_cyrce_ttp_coverage(cyrce_ttp_coverage_input)
        return response.reprJSON()

    def json_to_input(self, json_data):
        foo = 1
        return CyrceTtpCoverageInput(foo=foo)
