import networkx as nx
from flask import request
from flask_restful import Resource
import os

from typing import List

from core_module.analysis import run_ttp_coverage_metric
from input_module.cyrce_input import CyrceInput, CyrceTtpCoverageInput, \
    AttackMotivators, Exploitability, AttackSurface, ThreatActorInput, \
    CsfFunction, CsfIdentify, Scenario, Config, \
    IDAM, IDBE, IDGV, IDRA, IDRM, IDSC, \
    CsfProtect, CsfDetect, CsfRespond, CsfRecover, DirectImpact, Impact, IndirectImpact, PRAC, PRAT, PRDS, PRIP, PRMA, \
    PRPT, DEAE, DECM, DEDP, RSRP, RSCO, RSAN, RSMI, RSIM, RCRP, RCIM, RCCO, Sp80053, \
    AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PL, PE, PS, RA, SA, SC, SI, SR
from core_module.model_main import run_socre_core
from api_resources.ttp_coverage_resource import MitreAttackControl

graph = nx.read_graphml(os.path.join(os.path.dirname(__file__),
                                     '../model_resources/demo_network_model.graphml'))


class CyrceResource(Resource):

    def post(self):
        json_data = request.json
        cyrceInput = self.jsonToInput(json_data)
        response = run_socre_core(cyrceInput, graph)
        print(response)
        return response.reprJSON()

    def jsonToInput(self, json_data):
        # set default config parameters
        engine_version = 'v1.0.0'
        number_mc_iterations = 1000
        impact_model = 'score'
        impact_calc_mode = 'mean'
        risk_upper_score_bound = 5.
        likelihood_upper_score_bound = 5.
        impact_upper_score_bound = 5.
        if 'user_config' in json_data:
            if 'engine_version' in json_data['user_config']:
                engine_version = json_data['user_config']['engine_version']
            if 'number_mc_iterations' in json_data['user_config']:
                number_mc_iterations = json_data['user_config']['number_mc_iterations']
            if 'impact_model' in json_data['user_config']:
                impact_model = json_data['user_config']['impact_model']
            if 'impact_calc_mode' in json_data['user_config']:
                impact_calc_mode = json_data['user_config']['impact_calc_mode']
            if 'risk_upper_score_bound' in json_data['user_config']:
                risk_upper_score_bound = json_data['user_config']['risk_upper_score_bound']
            if 'likelihood_upper_score_bound' in json_data['user_config']:
                likelihood_upper_score_bound = json_data['user_config']['likelihood_upper_score_bound']
            if 'impact_upper_score_bound' in json_data['user_config']:
                impact_upper_score_bound = json_data['user_config']['impact_upper_score_bound']
        config = Config(engine_version=engine_version,
                        number_mc_iterations=number_mc_iterations,
                        impact_model=impact_model,
                        impact_calc_mode=impact_calc_mode,
                        risk_upper_score_bound=risk_upper_score_bound,
                        likelihood_upper_score_bound=likelihood_upper_score_bound,
                        impact_upper_score_bound=impact_upper_score_bound)
        mitreAttackControls: List[MitreAttackControl] = []
        if 'controls' in json_data:
            for item in json_data['controls']:
                mitreAttackControls.append(
                    MitreAttackControl(
                        label=item['label'],
                        score=item['score'],
                        ttps=item['ttps']
                    )
                )
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

        return CyrceInput(
            attackMotivators=attackMotivators,
            exploitability=exploitability,
            attackSurface=attackSurface,
            threatActorInput=threatActorInput,
            csf=csf,
            impact=impact,
            scenario=scenario,
            mitreControls=mitreAttackControls,
            config=config
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
