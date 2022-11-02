"""
Cyber Risk Computational Engine - CyCRE
"""

import logging
from scipy import interpolate
from scipy.stats import poisson
import networkx as nx
import os
from output_module.cyrce_output import CyrceOutput, ValueVar
from config import INPUTS
from entity_module.Entity import *
from threat_module.ThreatActor import ThreatActor
from scenario_module import ScenarioModel
# from environment_module.network_traversal import *
from environment_module.groups import *
from environment_module.network import *
from helpers.helper_functions import get_confidence_interval, flatten_list
from collections import OrderedDict
from pert import PERT
import numpy as np
import platform
from scipy.stats import uniform, norm


def generate_pert_random_variables(modeValue=0.5, gamma=2.0, nIterations=1000):
    """
    The Beta-PERT methodology was developed in the context of Program Evaluation and Review Technique (PERT). It is 
    based on a pessimistic estimate (minimum value), a most likely estimate (mode), and an optimistic estimate 
    (maximum value), typically derived through expert elicitation. 
    
    :param modeValue: the mode
    :param gamma: the spread parameter
    :param nIterations: number of values to generate
    :return: nIterations samples from the specified PERT distribution
    """
    maxValue = 1
    return PERT(0, modeValue, maxValue, gamma).rvs(size=nIterations)


def generate_gaussian_random_variables(mean=0.0, stdDev=1.0, nIterations=1000):
    """
    :param mean: mean
    :param stdDev: standard deviation
    :param nIterations: number of values to generate
    :return: nIterations samples from the normal distribution
    """
    return norm.rvs(loc=mean, scale=stdDev, size=nIterations)


def generate_uniform_random_variables(nIterations=1000):
    """
    Generate random variables from the uniform distribution from 0 to 1
    :param nIterations: number of values to generate
    :return: nIterations samples from the unit uniform distribution
    """
    return uniform.rvs(loc=0, scale=1, size=nIterations)


def determine_initial_access(tac, ia_control_inherent, ia_control_residual, vuln, ia_RV,
                             coeffs):  # TODO these could be done "once" outside loop
    """
    Determine "initial access" (ATT&CK Recon, Resource Dev, Initial Access) success or failure
    :param tac: threat actor capability
    :param ia_control_inherent: control against Initial Access TTPs, inherent
    :param ia_control_residual: control against Initial Access TTPs, residual
    :param vuln: vulnerability metric
    :param iaRV: Initial Access random variable
    :param coeffs: threat actor capability versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    inherent_vuln = vuln * (1 - ia_control_inherent)
    residual_vuln = vuln * (1 - ia_control_residual)
    p00 = coeffs[0]
    p10 = coeffs[1]
    p01 = coeffs[2]
    p20 = coeffs[3]
    p11 = coeffs[4]
    p02 = coeffs[5]
    p30 = coeffs[6]
    p21 = coeffs[7]
    p12 = coeffs[8]
    p03 = coeffs[9]
    x = 1 - inherent_vuln
    y = tac
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.

    if ia_RV <= prob:
        inherent_result = True
    else:
        inherent_result = False

    x = 1 - residual_vuln
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if ia_RV <= prob:
        residual_result = True
    else:
        residual_result = False

    return inherent_result, residual_result


def determine_execution(tac, exec_control_inherent, exec_control_resdiual, exploitability, execution_RV, coeffs):
    """
    Determine "execution" (ATT&CK Execution, Persistence, Priv Escalation, Defensive Evasion, Cred Access, Discovery,
        Collection) success or failure
    :param tac: threat actor capability
    :param exec_control_inherent: control against "execution" TTPs, inherent
    :param exec_control_inherent: control against "execution" TTPs, residual
    :param exploitability: exploitability metric
    :param execution_RV: Execution random variable
    :param coeffs: threat actor capability versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    inherent_expl = exploitability * (1 - exec_control_inherent)
    residual_expl = exploitability * (1 - exec_control_resdiual)

    p00 = coeffs[0]
    p10 = coeffs[1]
    p01 = coeffs[2]
    p20 = coeffs[3]
    p11 = coeffs[4]
    p02 = coeffs[5]
    p30 = coeffs[6]
    p21 = coeffs[7]
    p12 = coeffs[8]
    p03 = coeffs[9]
    x = 1 - inherent_expl
    y = tac
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if execution_RV <= prob:
        inherent_result = True
    else:
        inherent_result = False

    x = 1 - residual_expl
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if execution_RV <= prob:
        residual_result = True
    else:
        residual_result = False

    return inherent_result, residual_result


def determine_movement(tac, movement_control_inherent, movement_control_resdiual, exploitability, movement_RV, coeffs):
    """
    Determine "movement" (ATT&CK Lateral Movement) success or failure
    :param tac: threat actor capability
    :param movement_control_inherent: control against "movement" TTPs, inherent
    :param movement_control_resdiual: control against "movement" TTPs, residual
    :param exploitability: exploitability metric
    :param movement_RV: Movement random variable
    :param coeffs: threat actor capability versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    inherent_expl = exploitability * (1 - movement_control_inherent)
    residual_expl = exploitability * (1 - movement_control_resdiual)

    p00 = coeffs[0]
    p10 = coeffs[1]
    p01 = coeffs[2]
    p20 = coeffs[3]
    p11 = coeffs[4]
    p02 = coeffs[5]
    p30 = coeffs[6]
    p21 = coeffs[7]
    p12 = coeffs[8]
    p03 = coeffs[9]
    x = 1 - inherent_expl
    y = tac
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if movement_RV <= prob:
        inherent_result = True
    else:
        inherent_result = False

    x = 1 - residual_expl
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if movement_RV <= prob:
        residual_result = True
    else:
        residual_result = False

    return inherent_result, residual_result


def determine_impact(impact_control_inherent, impact_control_residual, entity):
    """
    Determine "impact" (ATT&CK C&C, Exfil, Impact) success or failure
    I = (1 - RR) * VAL
    :param impact_control_inherent: control against "impact" TTPs, inherent
    :param impact_control_residual: control against "impact" TTPs, residual
    :param entity: entity object
    :return: A pair of impact values (inherent, residual)
    """
    inherentImpact = entity.assets[0].value * (1 - impact_control_inherent)
    residualImpact = entity.assets[0].value * (1 - impact_control_residual)

    return inherentImpact, residualImpact


def compute_impact_values(cyrce_input, impactCalcMode='mean'):
    """
    Compute impact values
    :param cyrce_input: input object containing input impact values
    :param impactCalcMode: either 'mean' or 'max'
    :return: total impact (using either mean or max approach), direct impact, and indirect impact
    """
    directImpactValues = list(cyrce_input.impact.directImpact.__dict__.values())
    indirectImpactValues = list(cyrce_input.impact.indirectImpact.__dict__.values())
    directImpactValue = np.mean(directImpactValues)
    indirectImpactValue = np.mean(indirectImpactValues)
    if impactCalcMode == 'mean':
        impact = np.mean((directImpactValue, indirectImpactValue))
    else:
        impact = np.max(directImpactValues + indirectImpactValues)
    return impact, directImpactValue, indirectImpactValue


def update_attack_probability_given_rate(poissonRate, timeWindow, attackMotivator):
    """
    Compute the posterior probability of attack using a prior attack rate estimate and new information -- in this case,
        the Attack Motivator metric, using the log-odds-ratio method
    :param poissonRate: rate of attack as counts per [unit of time]
    :param timeWindow: window of time we are concerned with (number of units of time)
    :param attackMotivator: Attack Motivator metric
    :return: posterior probability and prior probability
    """
    priorAttackProbability = np.min((0.99, 1. - poisson.cdf(1, poissonRate)))  # 1 or more attacks, aka ALO
    condProbTable = np.array([max(0.01, 0.1 * priorAttackProbability),  # these values are SPM-best-guesses
                              max(0.01, 0.5 * priorAttackProbability),
                              priorAttackProbability,
                              min(1.5 * priorAttackProbability, 0.99),
                              min(2 * priorAttackProbability, 0.99)], dtype=np.double)
    baselineLogOdds = np.log(priorAttackProbability / (1 - priorAttackProbability))
    logOddsChangeAttackProbability = np.log(np.divide(condProbTable, (1 - condProbTable))) - baselineLogOdds
    x = logOddsChangeAttackProbability + baselineLogOdds
    attackProbabilityTable = np.divide(1, (1 + np.divide(1, np.exp(x))))
    func = interpolate.interp1d(np.arange(5) / 4., attackProbabilityTable, kind='linear')
    attackProbability = func(attackMotivator)
    attackProbability = 1 - (1 - attackProbability) ** timeWindow
    priorAttackProbability = 1 - (1 - priorAttackProbability) ** timeWindow
    return attackProbability, priorAttackProbability


def update_attack_probability_given_probability(priorAttackProbability, timeWindow, attackMotivator):
    """
    Compute the posterior probability of attack using a prior probability estimate and new information -- in this case,
    the Attack Motivator metric, using the log-odds-ratio method
    :param priorAttackProbability: prior probability estimate (over [unit of time])
    :param timeWindow: window of time we are concerned with (number of units of time)
    :param attackMotivator: Attack Motivator metric
    :return: posterior probability and prior probability
    """
    condProbTable = np.array([max(0.01, 0.1 * priorAttackProbability),  # these values are SPM-best-guesses
                              max(0.01, 0.5 * priorAttackProbability),
                              priorAttackProbability,
                              min(1.5 * priorAttackProbability, 0.99),
                              min(2 * priorAttackProbability, 0.99)], dtype=np.double)
    baselineLogOdds = np.log(priorAttackProbability / (1 - priorAttackProbability))
    logOddsChangeAttackProbability = np.log(np.divide(condProbTable, (1 - condProbTable))) - baselineLogOdds
    x = logOddsChangeAttackProbability + baselineLogOdds
    attackProbabilityTable = np.divide(1, (1 + np.divide(1, np.exp(x))))
    func = interpolate.interp1d(np.arange(5) / 4., attackProbabilityTable, kind='linear')
    attackProbability = func(attackMotivator)
    attackProbability = 1 - (1 - attackProbability) ** timeWindow
    priorAttackProbability = 1 - (1 - priorAttackProbability) ** timeWindow
    return attackProbability, priorAttackProbability


def update_metric(x, z, baselineStdDev=0.2, measStdDev=0.1):
    """
    Function to update the estimate of a metric using a "measurement" of the metric, based on Kalman Filter
    :param x: initial estimate of the metric
    :param z: measurement of the metric
    :param baselineStdDev: std dev of the initial estimate of the metric
    :param measStdDev: std dev of the measurement of the metric
    :return: updated estimate of the metric
    """
    x10 = x  # initial estimate
    p10 = baselineStdDev * baselineStdDev  # uncertainty of initial estimate
    k = p10 / (p10 + measStdDev * measStdDev)  # Kalman gain
    x11 = x10 + k * (z - x10)  # updated estimate
    p11 = (1 - k) * p10  # updated uncertainty
    return x11, p11


def run_cyrce(mode, cyrce_input, graph_model_file, bbn_file):
    """
    Main routine to run the Booz Allen Cyber Risk Engine
    :param mode: controls mode, 'csf' or 'sp80053'
    :param cyrce_input: input object
    :param graph_model_file: network model file
    :param bbn_file: pybbn bbn file
    :return: outputs
    """

    # TODO NETWORK ATTACK!
    # used for testing, etc.
    if platform.uname()[1] == 'BAHG3479J3':
        np.random.seed(101798)
        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.DEBUG)
    else:
        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.INFO)

    graph = nx.read_graphml(os.path.join(os.path.dirname(__file__), graph_model_file))

    numberOfMonteCarloRuns = INPUTS['numberOfMonteCarloRuns']
    impactCalcMode = INPUTS['impactCalcMode']
    riskMode = INPUTS['riskMode']
    coeffs = INPUTS['tac_v_ctrl_coeffs']

    # Compute total impact from direct and indirect
    impactValue, directImpactValue, indirectImpactValue = compute_impact_values(cyrce_input, impactCalcMode)

    # Set up entities  TODO hack for now; trying to get toward auto gen via network, etc. (may need to change Entity to take a type ...)
    # TODO programmatically create entity classes?
    # Hand jamming some entities
    all_entities = AllEntities()
    entity1 = CriticalServer(label="Crown Jewel")
    entity1.value = impactValue
    #entity2 = Server(label="WebApp")
    #entity2.value = impactValue / 100
    #entity3 = Desktop(label="Joe's Machine")
    #entity3.value = impactValue / 10000
    all_entities.list.append(entity1)
    #all_entities.list.append(entity2)
    #all_entities.list.append(entity3)

    # Set up threat actor
    threat_actor = ThreatActor(type=cyrce_input.scenario.attackThreatType)
    threat_actor.assign_property('sophistication', cyrce_input.threatActorInput.sophistication)
    threat_actor.assign_property('resources', cyrce_input.threatActorInput.resources)
    threat_actor.assign_property('determination', cyrce_input.threatActorInput.determination)
    threat_actor.set_attempt_limit()
    threat_actor.set_capability(cyrce_input)

    # Assign control values to each entity
    for a in all_entities.list:
        if mode == 'csf':
            a.controls['csf']['identify']['value'] = cyrce_input.csf.identify.value
            a.controls['csf']['protect']['value'] = cyrce_input.csf.protect.value
            a.controls['csf']['detect']['value'] = cyrce_input.csf.detect.value
            a.controls['csf']['respond']['value'] = cyrce_input.csf.respond.value
            a.controls['csf']['recover']['value'] = cyrce_input.csf.recover.value
        elif mode == 'sp80053':
            a.controls['sp80053']['AT'] = cyrce_input.sp80053.AT
            a.controls['sp80053']['RA'] = cyrce_input.sp80053.RA

        a.allocate_data_space(['impactI', 'impactR', 'accessI', 'accessR', 'riskI', 'riskR'], numberOfMonteCarloRuns)

    # Use this metadata to set scale factor on likelihood of attack
    attackAction = cyrce_input.scenario.attackAction
    attackIndustry = cyrce_input.scenario.attackIndustry
    attackGeography = cyrce_input.scenario.attackGeography
    attackLossType = cyrce_input.scenario.attackLossType
    attackThreatType = cyrce_input.scenario.attackThreatType
    orgSize = cyrce_input.scenario.orgSize

    scenario = ScenarioModel.Scenario(attackAction=attackAction, attackThreatType=attackThreatType,
                                      attackGeography=attackGeography, attackLossType=attackLossType,
                                      attackIndustry=attackIndustry, orgSize=orgSize, bbn_file=bbn_file)
    scenario.determine_scenario_probability_scale_factor(verbose=False)

    # Abstraction groups
    # Done manually here; will be programmatic using asset management data, network model
    ng1 = NetworkGroup(label='subnet1')
    #ng2 = NetworkGroup(label='subnet2')
    #ng3 = NetworkGroup(label='subnet3')
    #mg_servers = MachineGroup(label='servers', type='servers', network_group=ng2)
    mg_critical_servers = MachineGroup(label='critical_servers', type='critical_servers', network_group=ng1)
    #mg_desktops = MachineGroup(label='desktops', type='desktops', network_group=ng3)
    #mg_servers.assets = [a for a in all_entities.list if a.type.lower() == 'server']
    mg_critical_servers.assets = [a for a in all_entities.list if a.type.lower() == 'critical_server']
    #mg_desktops.assets = [a for a in all_entities.list if a.type.lower() == 'desktop']
    ng1.machine_groups = [mg_critical_servers]
    #ng2.machine_groups = [mg_servers]
    #ng3.machine_groups = [mg_desktops]
    network_model = Network(graph=graph)
    network_model.list_of_network_groups = [ng1] #, ng2, ng3]

    for mg in ng1.machine_groups:
        for a in mg.assets:
            ng1.assets.append(a)
            a.machine_group = mg
            a.network_group = ng1
#    for mg in ng2.machine_groups:
#        for a in mg.assets:
#            ng2.assets.append(a)
#            a.machine_group = mg
#            a.network_group = ng2
#    for mg in ng3.machine_groups:
#        for a in mg.assets:
#            ng3.assets.append(a)
#            a.machine_group = mg
#            a.network_group = ng3

    # Handle and set up attack target(s)
    attack_mg_target = []
    if cyrce_input.scenario.attackTarget is not None:
        if 'type' in cyrce_input.scenario.attackTarget:
            attack_mg_target.append([mg for mg in ng1.machine_groups
                                if cyrce_input.scenario.attackTarget.replace('type:', '') in [a.type for a in mg.assets]])
            #attack_mg_target.append([mg for mg in ng2.machine_groups
            #                    if cyrce_input.scenario.attackTarget.replace('type:', '') in [a.type for a in mg.assets]])
            #attack_mg_target.append([mg for mg in ng3.machine_groups
            #                    if cyrce_input.scenario.attackTarget.replace('type:', '') in [a.type for a in mg.assets]])
        elif 'label' in cyrce_input.scenario.attackTarget:
            attack_mg_target.append([mg for mg in ng1.machine_groups
                                if cyrce_input.scenario.attackTarget.replace('label:', '') in [a.label for a in mg.assets]])
            #attack_mg_target.append([mg for mg in ng2.machine_groups
            #                    if cyrce_input.scenario.attackTarget.replace('label:', '') in [a.label for a in mg.assets]])
            #attack_mg_target.append([mg for mg in ng3.machine_groups
            #                    if cyrce_input.scenario.attackTarget.replace('label:', '') in [a.label for a in mg.assets]])
    else:
        attack_mg_target.append(ng1.machine_groups)
        #attack_mg_target.append(ng2.machine_groups)
        #attack_mg_target.append(ng3.machine_groups)

    attack_mg_target = flatten_list(attack_mg_target)

    attack_assets_target = []
    for mg in attack_mg_target:
        for a in mg.assets:
            attack_assets_target.append(a)

    # TODO make these entries optional, if that is deemed a good idea, then update them as below if there is info to
    # TODO use for the update, o/w use baseline
    # Compute Attack Motivator metric
    attackMotivator = np.mean([cyrce_input.attackMotivators.reward,  # TODO weights?
                               cyrce_input.attackMotivators.appeal,
                               cyrce_input.attackMotivators.targeting,
                               cyrce_input.attackMotivators.perceivedDefenses])

    probability_scale_factor0 = scenario.probability_scale_factor

    # Handle type of analysis
    if 'cert' in riskMode:
        scenario.probability_scale_factor = 1.
    elif 'prob' in riskMode:
        # Update the initial starting value of the scenario_probability_scale_factor using the Attack Motivator metric
        scenario.probability_scale_factor = scenario.probability_scale_factor * attackMotivator

    probability_scale_factor = scenario.probability_scale_factor

    """
    Bayes to incorporate log data (a la ARM) (not in this version, but noted here for future)
    attackProbabilityBayes = probLogDataGivenAttack * probAttack / probLogData
    """

    # Compute Threat Level; only used as a reporting metric
    threatLevel = probability_scale_factor * threat_actor.properties[
        'capability']  # MODEL: power = ~rate * force;  P = F * V

    # Pre-allocate space
    attackDict = OrderedDict((k, {}) for k in range(numberOfMonteCarloRuns))

    # TODO using this idea, but not sold on it
    # Using baseline Attack Surface metric, update it with attack surface values from inputs
    attackSurface0 = 0.5  # baseline value of 0.5
    attackSurface_ = np.mean([cyrce_input.attackSurface.awareness, cyrce_input.attackSurface.opportunity])
    attackSurface, _ = update_metric(attackSurface0, attackSurface_)

    # Using baseline Exploitability metric, update it with exploitability value from inputs
    exploitability0 = 0.5  # baseline value of 0.5
    exploitability_ = cyrce_input.exploitability.easeOfExploit
    exploitability, _ = update_metric(exploitability0, exploitability_)

    # Compute Vulnerability metrics
    vulnerability = exploitability * attackSurface  # MODEL:  flux = porosity * area * gradient(=1)

    # Get random variable samples ahead of the MCS
    exploitabilityRV = generate_pert_random_variables(modeValue=exploitability,
                                                      nIterations=numberOfMonteCarloRuns)
    attackSurfaceRV = generate_pert_random_variables(modeValue=attackSurface,
                                                     nIterations=numberOfMonteCarloRuns)
    vulnerabilityRV = np.multiply(exploitabilityRV, attackSurfaceRV)

    initial_access_RV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)
    execution_RV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)
    movement_RV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)

    detectRVInherent = np.zeros([numberOfMonteCarloRuns])
    detectRVResidual = generate_pert_random_variables(modeValue=cyrce_input.csf.detect.value,
                                                      gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                                      nIterations=numberOfMonteCarloRuns)

    protectRVInherent = np.zeros([numberOfMonteCarloRuns])
    protectRVResidual = generate_pert_random_variables(modeValue=cyrce_input.csf.protect.value,
                                                       gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                                       nIterations=numberOfMonteCarloRuns)

    # Compute combined Protect and Detect metric
    protectDetectRVInherent = np.zeros([numberOfMonteCarloRuns])
    protectDetectRVResidual = np.divide(np.add(detectRVResidual, protectRVResidual), 2)

    respondRVInherent = np.zeros([numberOfMonteCarloRuns])
    respondRVResidual = generate_pert_random_variables(modeValue=cyrce_input.csf.respond.value,
                                                       gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                                       nIterations=numberOfMonteCarloRuns)

    recoverRVInherent = np.zeros([numberOfMonteCarloRuns])
    recoverRVResidual = generate_pert_random_variables(modeValue=cyrce_input.csf.recover.value,
                                                       gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                                       nIterations=numberOfMonteCarloRuns)

    # Compute combined Respond and Recover metric
    respondRecoverRVInherent = np.zeros([numberOfMonteCarloRuns])
    respondRecoverRVResidual = np.divide(np.add(respondRVResidual, recoverRVResidual), 2)

    """
    ******************************************
    MC loop begins for inherent and residual *
    ******************************************
    Each iteration is a single attack
    A single attack may have multiple attempts, though, based on the TA attempt_limit
    """

    for iteration in range(0, numberOfMonteCarloRuns):

        tryCountI, tryCountR = 1, 1
        origin = 'internet'
        destination = attack_mg_target
        entryNode = attack_mg_target # [mg_servers]

        initial_access = True
        currentNode = None
        failedNodeList = []
        doResidual = True

        logger.debug(' -----------------')
        logger.debug(' Iteration: ' + str(iteration))

        attackDict[iteration]['iteration'] = iteration
        attackDict[iteration]['attack_type'] = 'nominal'
        attackDict[iteration]['probability_scale_factor'] = probability_scale_factor
        attackDict[iteration]['origin'] = origin
        attackDict[iteration]['destination'] = destination
        attackDict[iteration]['entryPoint'] = entryNode
        attackDict[iteration]['sequenceI'] = [origin]
        attackDict[iteration]['sequenceR'] = [origin]

        attackDictElement = attackDict[iteration]
        done = False

        while not done:

            while tryCountI <= threat_actor.attempt_limit:  # tryCountI should always be < tryCountR

                if initial_access:
                    nextNode = network_model.from_node_to_node(from_node=attackDictElement['origin'],
                                                               objective_list=attackDictElement['entryPoint'],
                                                               network_model=network_model,
                                                               failed_node_list=failedNodeList)
                    if nextNode is not None:
                        logger.debug(' ' + attackDictElement['origin'] + ' ----> ' + nextNode.label)
                else:
                    nextNode = network_model.from_node_to_node(from_node=currentNode.network_group.label,
                                                               objective_list=attackDictElement['destination'],
                                                               network_model=network_model,
                                                               failed_node_list=failedNodeList)
                    if nextNode is not None:
                        logger.debug(currentNode.label + ' ----> ' + nextNode.label)

                if nextNode is None:
                    logger.debug(' End of path reached')
                    tryCountI += 1
                    tryCountR += 1
                    failedNodeList.append(nextNode)
                    if tryCountI > threat_actor.attempt_limit:
                        logger.debug('   End of path reached (I/R), attacker giving up')
                        done = True
                        break
                    else:
                        logger.debug('   End of path reached (I), attacker trying again')
                    if doResidual:
                        if tryCountR > threat_actor.attempt_limit:
                            logger.debug('   End of path reached (R), attacker giving up')
                            doResidual = False
                        elif doResidual:
                            logger.debug('   End of path reached (R), attacker trying again')
                        else:
                            logger.debug('   End of path reached (R), residual attack ends')
                        continue

                # Determine if threat actor gains INITIAL ACCESS
                if initial_access:
                    inherentAccess, residualAccess = determine_initial_access(threat_actor.properties['capability'],
                                                                              protectDetectRVInherent[iteration],
                                                                              protectDetectRVResidual[iteration],
                                                                              vulnerabilityRV[iteration],
                                                                              initial_access_RV[iteration], coeffs)
                else:  # Determine if threat actor moves to next node
                    inherentAccess, residualAccess = determine_movement(threat_actor.properties['capability'],
                                                                        protectDetectRVInherent[iteration],
                                                                        protectDetectRVResidual[iteration],
                                                                        exploitabilityRV[iteration],
                                                                        movement_RV[iteration], coeffs)

                if nextNode is not None:

                    if inherentAccess is False:  # residualAccess should also be False
                        tryCountI += 1
                        tryCountR += 1
                        failedNodeList.append(nextNode)
                        if tryCountI > threat_actor.attempt_limit:
                            logger.debug('   Failed (I/R), attacker giving up - too many tries')
                            done = True
                            break
                        else:
                            logger.debug('   Failed (I), trying again')
                        if tryCountR > threat_actor.attempt_limit and doResidual:
                            logger.debug('   Failed (R), residual attack ends - too many tries')
                            doResidual = False
                        elif doResidual:  # both False
                            logger.debug('   Failed (R), but trying again since inherent also failed')

                    else:
                        logger.debug('   Next hop enabled (I) ...')
                        initial_access = False
                        currentNode = nextNode  # .label

                        if residualAccess is False and doResidual:
                            logger.debug(
                                '   Failed (R), residual attack ends since inherent succeeded')
                            doResidual = False
                        elif residualAccess is True and doResidual:
                            logger.debug('       Next hop enabled (R) ...')
                            currentNode = nextNode  # .label

                    if currentNode in attackDictElement['destination']:
                        done = True
                        initial_access = False
                        logger.debug(
                            '       Reached target (I)                                             XXX')
                        if residualAccess is True:
                            logger.debug(
                                '       Reached target (R)                                             ^^^')
                        break

            if tryCountI > threat_actor.attempt_limit:
                done = True

            if nextNode is not None:
                inherentExecution, residualExecution = determine_execution(threat_actor.properties['capability'],
                                                                           protectDetectRVInherent[iteration],
                                                                           protectDetectRVResidual[iteration],
                                                                           exploitabilityRV[iteration],
                                                                           execution_RV[iteration], coeffs)

                logger.debug(' Execution success?. (I): ' + str(inherentExecution))
                logger.debug(' Execution success? (R): ' + str(residualExecution))
                inherentImpact = 0.
                residualImpact = 0.
                inherentAccess = 0.
                residualAccess = 0.
                if residualExecution:
                    residualAccess = 1.
                    inherentAccess = 1.
                    inherentImpact, residualImpact = determine_impact(respondRecoverRVInherent[iteration],
                                                                      respondRecoverRVResidual[iteration], nextNode)
                    logger.debug(' Inherent Impact: ' + str(round(inherentImpact, 2)))
                    logger.debug(' Residual Impact: ' + str(round(residualImpact, 2)))
                elif inherentExecution:
                    inherentAccess = 1.
                    inherentImpact, residualImpact = determine_impact(respondRecoverRVInherent[iteration],
                                                                      respondRecoverRVResidual[iteration], nextNode)
                    logger.debug(' Inherent Impact: ' + str(round(residualImpact, 2)))
                    residualImpact = 0.
                nextNode.assets[0].manifest['riskR'][iteration] = probability_scale_factor * residualImpact
                nextNode.assets[0].manifest['riskI'][iteration] = probability_scale_factor * inherentImpact
                nextNode.assets[0].manifest['impactR'][iteration] = residualImpact
                nextNode.assets[0].manifest['impactI'][iteration] = inherentImpact
                nextNode.assets[0].manifest['accessR'][iteration] = residualAccess
                nextNode.assets[0].manifest['accessI'][iteration] = inherentAccess

    # Collect MCS results to calculate the outputs we want (for the single enterprise node)
    for a in all_entities.list:
        a.lhR_vec = probability_scale_factor * a.manifest['accessR']
        a.lhI_vec = probability_scale_factor * a.manifest['accessI']
        a.impR_vec = a.manifest['impactR']
        a.impI_vec = a.manifest['impactI']
        a.riskI_vec = np.multiply(a.lhI_vec, a.impI_vec)
        a.riskR_vec = np.multiply(a.lhR_vec, a.impR_vec)

        # Computing confidence intervals
        a.LH_confIntI = get_confidence_interval(a.lhI_vec, alpha=INPUTS['confidenceAlpha'])
        a.LH_confIntR = get_confidence_interval(a.lhR_vec, alpha=INPUTS['confidenceAlpha'])
        a.imp_confIntI = get_confidence_interval(a.impI_vec[a.manifest['accessI'] == 1],
                                                 alpha=INPUTS['confidenceAlpha'])
        a.imp_confIntR = get_confidence_interval(a.impR_vec[a.manifest['accessR'] == 1],
                                                 alpha=INPUTS['confidenceAlpha'])
        a.risk_confIntI = get_confidence_interval(a.riskI_vec, alpha=INPUTS['confidenceAlpha'])
        a.risk_confIntR = get_confidence_interval(a.riskR_vec, alpha=INPUTS['confidenceAlpha'])
        if INPUTS['scoring_lambda'] == 0:
            tmpRiskTransformedI_vec = np.log(a.riskI_vec + 1e-10)
            tmpRiskTransformedR_vec = np.log(a.riskR_vec + 1e-10)
        else:
            tmpRiskTransformedI_vec = np.power(a.riskI_vec, INPUTS['scoring_lambda'])
            tmpRiskTransformedR_vec = np.power(a.riskR_vec, INPUTS['scoring_lambda'])

        riskLevelI_vec = INPUTS['scoring_fit'][0] * tmpRiskTransformedI_vec + INPUTS['scoring_fit'][1]
        riskLevelI_vec[riskLevelI_vec < 0] = 0
        riskLevelI_vec[riskLevelI_vec > 5] = 5

        riskLevelR_vec = INPUTS['scoring_fit'][0] * tmpRiskTransformedR_vec + INPUTS['scoring_fit'][1]
        riskLevelR_vec[riskLevelR_vec < 0] = 0
        riskLevelR_vec[riskLevelR_vec > 5] = 5

        a.riskLevel_confIntI = max(min(2.5, get_confidence_interval(riskLevelI_vec[riskLevelI_vec > 0],
                                                                    alpha=INPUTS['confidenceAlpha'])), 0)
        a.riskLevel_confIntR = max(min(2.5, get_confidence_interval(riskLevelR_vec[riskLevelR_vec > 0],
                                                                    alpha=INPUTS['confidenceAlpha'])), 0)
        # Computing variances
        a.LH_varI = float(np.var(a.lhI_vec))
        a.LH_varR = float(np.var(a.lhR_vec))

        a.imp_varI = float(np.var(a.impI_vec))
        a.imp_varR = float(np.var(a.impR_vec))

        a.risk_varI = np.var(a.riskI_vec)
        a.risk_varR = np.var(a.riskR_vec)

        a.riskLevel_varI = np.var(riskLevelI_vec)
        a.riskLevel_varR = np.var(riskLevelR_vec)

        if INPUTS['scoring_lambda'] == 0:
            riskTransformedI = np.log(np.mean(a.riskI_vec) + 1e-10)
            riskTransformedR = np.log(np.mean(a.riskR_vec) + 1e-10)
        else:
            riskTransformedI = np.mean(a.riskI_vec) ** INPUTS['scoring_lambda']
            riskTransformedR = np.mean(a.riskR_vec) ** INPUTS['scoring_lambda']

        a.riskLevelI = max(min(5, INPUTS['scoring_fit'][0] * np.mean(riskTransformedI) + INPUTS['scoring_fit'][1]), 0)
        a.riskLevelR = max(min(5, INPUTS['scoring_fit'][0] * np.mean(riskTransformedR) + INPUTS['scoring_fit'][1]), 0)

        # Computing means
        a.lhI = np.mean(a.lhI_vec)
        a.lhR = np.mean(a.lhR_vec)
        a.impI = np.mean(a.impI_vec[a.manifest['accessI'] > 0])
        a.impR = np.mean(a.impR_vec[a.manifest['accessR'] > 0])
        a.riskI = np.mean(a.riskI_vec)
        a.riskR = np.mean(a.riskR_vec)

        if True:  # a.uuid == enterprise.uuid:
            # SPM diagnostics
            print("lhI = " + str(np.round(a.lhI, 4)))
            print("impI = " + str(np.round(a.impI, 4)))
            print("riskI = " + str(np.round(a.riskI, 4)))
            print("riskI_CI = " + str(np.round(a.risk_confIntI, 4)))
            print("riskLevelI = " + str(np.round(a.riskLevelI, 1)))
            print("riskLevelI_CI = " + str(np.round(a.riskLevel_confIntI, 2)))
            print("--------------------------------")

            print("lhR = " + str(np.round(a.lhR, 4)))
            print("impR = " + str(np.round(a.impR, 4)))
            print("riskR = " + str(np.round(a.riskR, 4)))
            print("riskR_CI = " + str(np.round(a.risk_confIntR, 4)))
            print("riskLevelR = " + str(np.round(a.riskLevelR, 2)))
            print("riskLevelR_CI = " + str(np.round(a.riskLevel_confIntR, 2)))
            print("--------------------------------")

            logger.debug('output: ' + str(CyrceOutput(
                overallInherentLikelihood=ValueVar(float(a.lhI), a.LH_varI, a.LH_confIntI),
                overallResidualLikelihood=ValueVar(float(a.lhR), a.LH_varR, a.LH_confIntR),
                overallInherentImpact=ValueVar(float(a.impI), a.imp_varI, a.imp_confIntI),
                overallResidualImpact=ValueVar(float(a.impR), a.imp_varR, a.imp_confIntR),
                overallInherentRiskLevel=ValueVar(a.riskLevelI, float(a.riskLevel_varI), a.riskLevel_confIntI),
                overallResidualRiskLevel=ValueVar(a.riskLevelR, float(a.riskLevel_varR), a.riskLevel_confIntR),
                attackSurface=float(attackSurface),
                exploitability=exploitability,
                vulnerability=vulnerability,
                threatActorCapacity=threat_actor.properties['capability'],
                threatLevel=float(np.mean(threatLevel)),
                probability_scale_factor0=float(probability_scale_factor0),
                probability_scale_factor=float(probability_scale_factor),
                attackMotivators=float(attackMotivator),
                directImpact=float(directImpactValue),
                indirectImpact=float(indirectImpactValue))))

            return CyrceOutput(
                overallInherentLikelihood=ValueVar(float(a.lhI), a.LH_varI, a.LH_confIntI),
                overallResidualLikelihood=ValueVar(float(a.lhR), a.LH_varR, a.LH_confIntR),
                overallInherentImpact=ValueVar(float(a.impI), a.imp_varI, a.imp_confIntI),
                overallResidualImpact=ValueVar(float(a.impR), a.imp_varR, a.imp_confIntR),
                overallInherentRiskLevel=ValueVar(a.riskLevelI, float(a.riskLevel_varI), a.riskLevel_confIntI),
                overallResidualRiskLevel=ValueVar(a.riskLevelR, float(a.riskLevel_varR), a.riskLevel_confIntR),
                attackSurface=float(attackSurface),
                exploitability=exploitability,
                vulnerability=vulnerability,
                threatActorCapacity=threat_actor.properties['capability'],
                threatLevel=float(np.mean(threatLevel)),
                probability_scale_factor0=float(probability_scale_factor0),
                probability_scale_factor=float(probability_scale_factor),
                attackMotivators=float(attackMotivator),
                directImpact=float(directImpactValue),
                indirectImpact=float(indirectImpactValue)
            )
