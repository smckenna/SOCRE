import networkx as nx
import os
from input_module.cyrce_input import CyrceCsfInput, Cyrce80053Input, \
    AttackMotivators, Exploitability, AttackSurface, ThreatActorInput, DirectImpact, Impact, IndirectImpact, \
    CsfFunction, CsfIdentify, CsfProtect, CsfDetect, CsfRespond, CsfRecover, \
    IDAM, IDBE, IDGV, IDRA, IDRM, IDSC, PRAC, PRAT, PRDS, PRIP, PRMA, \
    PRPT, DEAE, DECM, DEDP, RSRP, RSCO, RSAN, RSMI, RSIM, RCRP, RCIM, RCCO

from core_module.model_main import run_cyrce, run_cyrce_ttp_coverage

from scenario_module.ScenarioModel import Scenario

if __name__ == '__main__':
    graph = nx.read_graphml(
        os.path.join(os.path.dirname(__file__), '../model_resources/enterprise_network_model.graphml'))
    bbn_file = os.path.join(os.path.dirname(__file__), '../scenario_module/scenario_bbn.json')

    attackMotivators = AttackMotivators(2.5, 2.5, 2.5, 2.5)
    attackSurface = AttackSurface(2.5, 2.5)
    exploitability = Exploitability(2.5)
    threatActorInput = ThreatActorInput(determination='high', resources='government', sophistication='strategic')
    directImpact = DirectImpact(3, 3, 2, 1)
    indirectImpact = IndirectImpact(3, 3, 2, 1)
    impact = Impact(directImpact, indirectImpact)
    scenario = Scenario(attackAction='hacking', attackThreatType='external', attackTarget='enterprise',
                        attackLossType='c', attackIndustry='miningandutilities', attackGeography='na', orgSize="small",
                        bbn_file=bbn_file)
    identify = CsfIdentify(IDAM=IDAM(0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
                           IDBE=IDBE(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
                           IDGV=IDGV(0.8, 0.8, 0.8, 0.8, 0.8),
                           IDRA=IDRA(0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
                           IDRM=IDRM(0.8, 0.8, 0.8, 0.8),
                           IDSC=IDSC(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
                           value=0.24
                           )
    protect = CsfProtect(value=0.2,
                         PRAC=PRAC(value=0.4, PRAC1=0.4, PRAC2=0.4, PRAC3=0.4, PRAC4=0.4, PRAC5=0.4, PRAC6=0.4,
                                   PRAC7=0.4),
                         PRAT=PRAT(value=0.4, PRAT1=0.4, PRAT2=0.4, PRAT3=0.4, PRAT4=0.4, PRAT5=0.4),
                         PRDS=PRDS(value=0.4, PRDS1=0.4, PRDS2=0.4, PRDS3=0.4, PRDS4=0.4, PRDS5=0.4, PRDS6=0.4,
                                   PRDS7=0.4, PRDS8=0.4),
                         PRIP=PRIP(value=0.4, PRIP1=0.4, PRIP2=0.4, PRIP3=0.4, PRIP4=0.4, PRIP5=0.4, PRIP6=0.4,
                                   PRIP7=0.4, PRIP8=0.4,
                                   PRIP9=0.4, PRIP10=0.4, PRIP11=0.4, PRIP12=0.4),
                         PRMA=PRMA(value=0.4, PRMA1=0.4, PRMA2=0.4),
                         PRPT=PRPT(value=0.4, PRPT1=0.4, PRPT2=0.4, PRPT3=0.4, PRPT4=0.4, PRPT5=0.4)
                         )
    detect = CsfDetect(value=0.2,
                       DEAE=DEAE(value=0.4, DEAE1=0.4, DEAE2=0.4, DEAE3=0.4, DEAE4=0.4, DEAE5=0.4),
                       DECM=DECM(value=0.4, DECM1=0.4, DECM2=0.4, DECM3=0.4, DECM4=0.4, DECM5=0.4, DECM6=0.4, DECM7=0.4,
                                 DECM8=0.4),
                       DEDP=DEDP(value=0.4, DEDP1=0.4, DEDP2=0.4, DEDP3=0.4, DEDP4=0.4, DEDP5=0.4))
    respond = CsfRespond(value=0.6,
                         RSRP=RSRP(value=0.426, RSRP1=0.426),
                         RSCO=RSCO(value=0.426, RSCO1=0.426, RSCO2=0.426, RSCO3=0.426, RSCO4=0.426, RSCO5=0.426),
                         RSAN=RSAN(value=0.426, RSAN1=0.426, RSAN2=0.426, RSAN3=0.426, RSAN4=0.426, RSAN5=0.426),
                         RSMI=RSMI(value=0.426, RSMI1=0.426, RSMI2=0.426, RSMI3=0.426),
                         RSIM=RSIM(value=0.426, RSIM1=0.426, RSIM2=0.426))
    recover = CsfRecover(value=0.6,
                         RCRP=RCRP(value=0.426, RCRP1=0.426),
                         RCIM=RCIM(value=0.426, RCIM1=0.426, RCIM2=0.426),
                         RCCO=RCCO(value=0.426, RCCO1=0.426, RCCO2=0.426, RCCO3=0.426)
                         )
    csf = CsfFunction(identify=identify,
                      protect=protect,
                      detect=detect,
                      respond=respond,
                      recover=recover)
    cyrce_csf_input = CyrceCsfInput(attackMotivators=attackMotivators,
                                attackSurface=attackSurface,
                                exploitability=exploitability,
                                threatActorInput=threatActorInput,
                                impact=impact,
                                csf=csf,
                                scenario=scenario)
    cyrce_80053_input = CyrceCsfInput(attackMotivators=attackMotivators,
                                attackSurface=attackSurface,
                                exploitability=exploitability,
                                threatActorInput=threatActorInput,
                                impact=impact,
                                csf=csf,
                                scenario=scenario)
    output_csf = run_cyrce(cyrce_input=cyrce_csf_input, mode='csf', graph=graph, bbn_file=bbn_file)
    output_80053 = run_cyrce(cyrce_input=cyrce_80053_input, mode='80053', graph=graph, bbn_file=bbn_file)
    x = run_cyrce_ttp_coverage(in_val=11111)
