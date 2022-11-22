"""
Cyber Risk Computational Engine - CyCRE
"""
import os
import platform
from collections import OrderedDict

import networkx as nx
import pandas as pd
from scipy import interpolate
from scipy.stats import poisson

from config import INPUTS
from entity_module.Entity import *
from environment_module.network import *
from helpers.helper_functions import get_confidence_interval, flatten_list, generate_pert_random_variables, \
    generate_uniform_random_variables, compute_metric
from output_module.cyrce_output import CyrceOutput, ValueVar
from scenario_module import ScenarioModel
from threat_module.ThreatActor import ThreatActor


def compute_tac_v_control_prob(vuln, tac, coeffs):
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
    x = 1 - vuln
    y = tac
    return p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + p30 * x ** 3 + p21 * x ** 2 * y + \
           p12 * x * y ** 2 + p03 * y ** 3


def determine_initial_access(tac, ia_control, vuln, ia_RV, coeffs):
    # TODO these could be done "once" outside loop
    """
    Determine "initial access" (ATT&CK Recon, Resource Dev, Initial Access) success or failure
    :param tac: threat actor capability
    :param ia_control: control against Initial Access TTPs
    :param vuln: vulnerability metric
    :param ia_RV: Initial Access random variable
    :param coeffs: threat actor capability versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    vuln = vuln * (1 - ia_control)
    prob = compute_tac_v_control_prob(vuln, tac, coeffs)
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if ia_RV <= prob:
        result = True
    else:
        result = False

    return result


def determine_execution(tac, exec_control, exploitability, execution_RV, coeffs):
    """
    Determine "execution" (ATT&CK Execution, Persistence, Priv Escalation, Defensive Evasion, Cred Access, Discovery,
        Collection) success or failure
    :param tac: threat actor capability
    :param exec_control: control against "execution" TTPs
    :param exploitability: exploitability metric
    :param execution_RV: Execution random variable
    :param coeffs: threat actor capability versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    expl = exploitability * (1 - exec_control)
    prob = compute_tac_v_control_prob(expl, tac, coeffs)
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if execution_RV <= prob:
        result = True
    else:
        result = False

    return result


def determine_movement(tac, movement_control, exploitability, movement_RV, coeffs):
    """
    Determine "movement" (ATT&CK Lateral Movement) success or failure
    :param tac: threat actor capability
    :param movement_control: control against "movement" TTPs
    :param exploitability: exploitability metric
    :param movement_RV: Movement random variable
    :param coeffs: threat actor capability versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    expl = exploitability * (1 - movement_control)
    prob = compute_tac_v_control_prob(expl, tac, coeffs)
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if movement_RV <= prob:
        result = True
    else:
        result = False

    return result


def determine_impact(impact_control, entity):
    """
    Determine "impact" (ATT&CK C&C, Exfil, Impact) success or failure
    I = (1 - RR) * VAL
    :param impact_control: control against "impact" TTPs
    :param entity: entity object
    :return: impact value
    """
    impact = entity.assets[0].value * (1 - impact_control)  # TODO this [0] is temporary

    return impact


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


def run_cyrce(cyrce_input, control_mode='csf', run_mode=['residual'], sweep=False):
    """
    Main routine to run CyRCE
    :param control_mode: controls mode, 'csf' or 'sp80053'
    :param run_mode: list of ways to run, 'inherent' or 'residual' or ...
    :param cyrce_input: input object
    :return: outputs
    """

    # TODO NETWORK ATTACK!
    # used for testing, etc.
    if platform.uname()[1] == 'BAHG3479J3':
        random_seed = INPUTS['random_seed']
        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.DEBUG)
    else:
        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.INFO)
        rng = np.random.default_rng()
        random_seed = int(rng.random() * 100000)
    if sweep:
        logger.setLevel(level=logging.INFO)

    np.random.seed(random_seed)

    graph = nx.read_graphml(os.path.join(os.path.dirname(__file__), INPUTS['graph_model_file']))

    numberOfMonteCarloRuns = INPUTS['numberOfMonteCarloRuns']
    impactCalcMode = INPUTS['impactCalcMode']
    coeffs = INPUTS['tac_v_ctrl_coeffs']

    # Compute total impact from direct and indirect
    impactValue, directImpactValue, indirectImpactValue = compute_impact_values(cyrce_input, impactCalcMode)

    # Set up entities; at this stage, just assets
    all_entities = AllEntities()
    asset_group = EntityGroup("assets")
    df = pd.read_csv(INPUTS['assets_file'])
    for idx, row in df.iterrows():
        entity = Entity(label=row['label'], type=row['type'], critical=bool(row['critical']))
        entity.value = impactValue * row['value']
        entity.assign_properties('ip_address', row['ip'])
        entity.assign_properties('os', row['os'])
        all_entities.list.append(entity)
        asset_group.add_entity([entity])

    # Set up threat actor
    threat_actor = ThreatActor(type=cyrce_input.scenario.attackThreatType)
    if cyrce_input.scenario.attackAction == 'error':  # current approach to error case
        cyrce_input.threatActorInput.determination = 0
        cyrce_input.threatActorInput.determinationWeight = 0
    threat_actor.assign_property('sophistication', cyrce_input.threatActorInput.sophistication)
    threat_actor.assign_property('resources', cyrce_input.threatActorInput.resources)
    threat_actor.assign_property('determination', cyrce_input.threatActorInput.determination)
    threat_actor.set_attempt_limit()
    threat_actor.set_capability(cyrce_input)

    # Assign control values to each entity
    # TODO controls should not be tied to entity; but will go with an entity
    for a in all_entities.list:
        if control_mode == 'csf':
            a.controls['csf']['identify']['value'] = cyrce_input.csf.identify.value
            a.controls['csf']['protect']['value'] = cyrce_input.csf.protect.value
            a.controls['csf']['detect']['value'] = cyrce_input.csf.detect.value
            a.controls['csf']['respond']['value'] = cyrce_input.csf.respond.value
            a.controls['csf']['recover']['value'] = cyrce_input.csf.recover.value
        elif control_mode == 'sp80053':
            a.controls['sp80053']['AT'] = cyrce_input.sp80053.AT
            a.controls['sp80053']['RA'] = cyrce_input.sp80053.RA
            a.controls['csf']['identify']['value'] = cyrce_input.csf.identify.value
            a.controls['csf']['protect']['value'] = cyrce_input.csf.protect.value
            a.controls['csf']['detect']['value'] = cyrce_input.csf.detect.value
            a.controls['csf']['respond']['value'] = cyrce_input.csf.respond.value
            a.controls['csf']['recover']['value'] = cyrce_input.csf.recover.value
        a.allocate_data_space(['impact', 'access', 'risk'], numberOfMonteCarloRuns)

    # Use this metadata to set scale factor on likelihood of attack
    attackAction = cyrce_input.scenario.attackAction
    attackIndustry = cyrce_input.scenario.attackIndustry
    attackGeography = cyrce_input.scenario.attackGeography
    attackLossType = cyrce_input.scenario.attackLossType
    attackThreatType = cyrce_input.scenario.attackThreatType
    orgSize = cyrce_input.scenario.orgSize

    bbn_file = os.path.join(os.path.dirname(__file__), INPUTS['bbn_file'])

    scenario = ScenarioModel.Scenario(attackAction=attackAction, attackThreatType=attackThreatType,
                                      attackGeography=attackGeography, attackLossType=attackLossType,
                                      attackIndustry=attackIndustry, orgSize=orgSize)
    scenario.determine_scenario_probability_scale_factor(bbn_file=bbn_file, verbose=False)

    # Abstraction groups
    # Will use asset management data, network model, etc.
    network_model = Network(graph=graph)
    logger.debug("      Assigning assets to network groups")
    network_model.assign_assets_to_network_groups(all_entities.list)
    logger.debug("      Assigning assets to machine groups")
    network_model.assign_assets_to_machine_groups()

    # Handle and set up attack target(s)
    attack_mg_target = []
    if cyrce_input.scenario.attackTarget is not None:
        if 'type' in cyrce_input.scenario.attackTarget:
            for ng in network_model.list_of_network_groups:
                attack_mg_target.append([mg for mg in ng.machine_groups
                                         if cyrce_input.scenario.attackTarget.replace('type:', '') in [a.type for a in
                                                                                                       mg.assets]])
        elif 'label' in cyrce_input.scenario.attackTarget:
            for ng in network_model.list_of_network_groups:
                attack_mg_target.append([mg for mg in ng.machine_groups
                                         if cyrce_input.scenario.attackTarget.replace('label:', '') in [a.label for a in
                                                                                                        mg.assets]])
    else:
        attack_mg_target = [ng.machine_groups for ng in network_model.list_of_network_groups]
    attack_mg_target = flatten_list(attack_mg_target)

    attack_assets_target = []
    for mg in attack_mg_target:
        for a in mg.assets:
            attack_assets_target.append(a)

    # TODO make these entries optional, if that is deemed a good idea, then update them as below if there is info to
    # TODO use for the update, o/w use baseline
    # Compute Attack Motivator metric
    attackMotivator0 = 0.5  # baseline value of 0.5
    attackMotivator_ = np.mean([cyrce_input.attackMotivators.reward,  # TODO weights?
                                cyrce_input.attackMotivators.appeal,
                                cyrce_input.attackMotivators.targeting,
                                cyrce_input.attackMotivators.perceivedDefenses])
    attackMotivator, _ = update_metric(attackMotivator0, attackMotivator_)

    probability_scale_factor0 = scenario.probability_scale_factor

    probability_scale_factor = scenario.probability_scale_factor * attackMotivator

    if scenario.attackLossType is None:
        scenario.attackLossType = np.random.choice(['c', 'i', 'a'])  # pick a loss type randomly

    """
    Bayes to incorporate log data (a la ARM) (not in this version, but noted here for future)
    attackProbabilityBayes = probLogDataGivenAttack * probAttack / probLogData
    """

    # Compute Threat Level; only used as a reporting metric
    # MODEL: power = ~rate * force;  P = F * V
    threatLevel = compute_metric(probability_scale_factor, threat_actor.properties['capability'], method="harmonic")

    # Pre-allocate space for tracking dict
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
    # MODEL:  flux = permeability * area * gradient(=1)
    vulnerability = compute_metric(exploitability, attackSurface, method='geometric')

    # Get random variable samples ahead of the MCS
    exploitabilityRV = generate_pert_random_variables(modeValue=exploitability,
                                                      nIterations=numberOfMonteCarloRuns)
    attackSurfaceRV = generate_pert_random_variables(modeValue=attackSurface,
                                                     nIterations=numberOfMonteCarloRuns)

    vulnerabilityRV = compute_metric(exploitabilityRV, attackSurfaceRV, method='geometric')

    initial_access_RV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)
    execution_RV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)

    for a in all_entities.list:
        a.assign_properties('exploitability', exploitability)
        a.assign_properties('attack_surface', attackSurface)
        a.assign_properties('vulnerability', compute_metric(exploitability, attackSurface, method='geometric'))

    # *************************************
    # Comment movement_RV to mimic vista
    # *************************************
    movement_RV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)

    detectRV = generate_pert_random_variables(modeValue=cyrce_input.csf.detect.value,
                                              gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                              nIterations=numberOfMonteCarloRuns)

    protectRV = generate_pert_random_variables(modeValue=cyrce_input.csf.protect.value,
                                               gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                               nIterations=numberOfMonteCarloRuns)

    # Compute combined Protect and Detect metric
    protectDetectRV = np.divide(np.add(detectRV, protectRV), 2)

    respondRV = generate_pert_random_variables(modeValue=cyrce_input.csf.respond.value,
                                               gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                               nIterations=numberOfMonteCarloRuns)

    recoverRV = generate_pert_random_variables(modeValue=cyrce_input.csf.recover.value,
                                               gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                               nIterations=numberOfMonteCarloRuns)

    # Compute combined Respond and Recover metric
    respondRecoverRV = np.divide(np.add(respondRV, recoverRV), 2)

    """
    ********************
    *  MC loop begins  *
    ********************
    Each iteration is a single attack
    A single attack may have multiple attempts, though, based on the TA attempt_limit
    """
    for run in run_mode:
        np.random.seed(random_seed)

        if run == 'inherent':
            protectDetectRV = 0 * protectDetectRV
            respondRecoverRV = 0 * respondRecoverRV

        for iteration in range(0, numberOfMonteCarloRuns):

            tryCount = 1
            origin = network_model.list_of_network_groups[0].machine_groups[0]  # = internet
            destination = attack_mg_target
            entryNode = attack_mg_target

            initial_access = True
            currentNode = None
            failedNodeList = []

            logger.debug(' -----------------')
            logger.debug(' Iteration: ' + str(iteration))

            attackDict[iteration]['iteration'] = iteration
            attackDict[iteration]['attack_type'] = 'nominal'
            attackDict[iteration]['probability_scale_factor'] = probability_scale_factor
            attackDict[iteration]['origin'] = origin
            attackDict[iteration]['destination'] = destination
            attackDict[iteration]['entryPoint'] = entryNode
            attackDict[iteration]['sequence'] = [origin]

            attackDictElement = attackDict[iteration]
            done = False

            while not done:

                while tryCount <= threat_actor.attempt_limit:

                    if initial_access:
                        from_node = attackDictElement['origin']
                        objective_node = attackDictElement['entryPoint']
                        logger_from_string = attackDictElement['origin'].label
                    else:
                        from_node = currentNode
                        objective_node = attackDictElement['destination']
                        logger_from_string = currentNode.label

                    nextNode = network_model.from_node_to_node(from_node=from_node,
                                                               objective_list=objective_node,
                                                               network_model=network_model,
                                                               failed_node_list=failedNodeList)
                    if nextNode is not None:
                        logger.debug(' ' + logger_from_string + ' ----> ' + nextNode.label)

                    if nextNode is None:
                        tryCount += 1
                        failedNodeList.append(nextNode)
                        if tryCount > threat_actor.attempt_limit:
                            logger.debug('   End of path reached, attacker giving up')
                            done = True
                            break
                        else:
                            logger.debug('   End of path reached, attacker trying again')

                    # Determine if threat actor gains INITIAL ACCESS
                    if initial_access:
                        if (attackAction == 'error') or (attackAction == 'misuse'):
                            access = True  # these are for insider, who has initial access
                        else:
                            access = determine_initial_access(threat_actor.properties['capability'],
                                                              protectDetectRV[iteration],
                                                              vulnerabilityRV[iteration],
                                                              initial_access_RV[iteration], coeffs)
                    else:  # Determine if threat actor moves to next node
                        access = determine_movement(threat_actor.properties['capability'],
                                                    protectDetectRV[iteration],
                                                    exploitabilityRV[iteration],
                                                    movement_RV[iteration], coeffs)

                    if nextNode is not None:
                        if access is False:
                            tryCount += 1
                            failedNodeList.append(nextNode)
                            if tryCount > threat_actor.attempt_limit:
                                logger.debug('   Failed, attacker giving up - too many tries')
                                done = True
                                break
                            else:
                                logger.debug('   Failed, trying again')
                        else:
                            logger.debug('    Next hop enabled ...')
                            initial_access = False
                            currentNode = nextNode

                        if currentNode in attackDictElement['destination']:
                            done = True
                            initial_access = False
                            logger.debug('       Reached target                                             XXX')
                            break

                if tryCount > threat_actor.attempt_limit:
                    done = True

                if nextNode is not None:
                    execution = determine_execution(threat_actor.properties['capability'],
                                                    protectDetectRV[iteration],
                                                    exploitabilityRV[iteration],
                                                    execution_RV[iteration], coeffs)

                    logger.debug('          Execution success?: ' + str(execution))
                    impact = 0.
                    access = 0.
                    if execution:
                        access = 1.
                        impact = determine_impact(respondRecoverRV[iteration], nextNode)
                        logger.debug('             Impact: ' + str(round(impact, 2)))
                    nextNode.assets[0].manifest['risk'][iteration] = probability_scale_factor * impact
                    nextNode.assets[0].manifest['impact'][iteration] = impact
                    nextNode.assets[0].manifest['access'][iteration] = access

        # Collect MCS results to calculate the outputs we want (for the single target node)
        for a in [_ for _ in all_entities.list if _.type == 'server' and _.critical]:
            a.lh_vec = probability_scale_factor * a.manifest['access']
            a.imp_vec = a.manifest['impact']
            a.risk_vec = np.multiply(a.lh_vec, a.imp_vec)

            # Computing confidence intervals
            a.LH_confInt = get_confidence_interval(a.lh_vec, alpha=INPUTS['confidenceAlpha'])
            a.imp_confInt = get_confidence_interval(a.imp_vec[a.manifest['access'] == 1],
                                                    alpha=INPUTS['confidenceAlpha'])
            a.risk_confInt = get_confidence_interval(a.risk_vec, alpha=INPUTS['confidenceAlpha'])
            if INPUTS['scoring_lambda'] == 0:
                tmpRiskTransformed_vec = np.log(a.risk_vec + 1e-10)
            else:
                tmpRiskTransformed_vec = np.power(a.risk_vec, INPUTS['scoring_lambda'])

            riskLevel_vec = INPUTS['scoring_fit'][0] * tmpRiskTransformed_vec + INPUTS['scoring_fit'][1]
            riskLevel_vec[riskLevel_vec < 0] = 0
            riskLevel_vec[riskLevel_vec > 5] = 5

            a.riskLevel_confInt = max(min(2.5, get_confidence_interval(riskLevel_vec[riskLevel_vec > 0],
                                                                       alpha=INPUTS['confidenceAlpha'])), 0)
            # Computing variances
            a.LH_var = float(np.var(a.lh_vec))
            a.imp_var = float(np.var(a.imp_vec))
            a.risk_var = np.var(a.risk_vec)
            a.riskLevel_var = np.var(riskLevel_vec)

            if INPUTS['scoring_lambda'] == 0:
                riskTransformed = np.log(np.mean(a.risk_vec) + 1e-10)
            else:
                riskTransformed = np.mean(a.risk_vec) ** INPUTS['scoring_lambda']

            a.riskLevel = max(min(5, INPUTS['scoring_fit'][0] * np.mean(riskTransformed) + INPUTS['scoring_fit'][1]), 0)

            # Computing means
            a.lh = np.mean(a.lh_vec)
            a.imp = np.mean(a.imp_vec[a.manifest['access'] > 0])
            a.risk = np.mean(a.risk_vec)

            # SPM diagnostics
            if not sweep:
                print("--------------------------------")
                print("lh = " + str(np.round(a.lh, 4)))
                print("imp = " + str(np.round(a.imp, 4)))
                print("risk = " + str(np.round(a.risk, 4)))
                print("risk_CI = " + str(np.round(a.risk_confInt, 4)))
                print("riskLevel = " + str(np.round(a.riskLevel, 2)))
                print("riskLevel_CI = " + str(np.round(a.riskLevel_confInt, 2)))
                print("--------------------------------")

                logger.debug('output: ' + str(CyrceOutput(
                    overallInherentLikelihood=ValueVar(float(a.lh), a.LH_var, a.LH_confInt),
                    overallResidualLikelihood=ValueVar(float(a.lh), a.LH_var, a.LH_confInt),
                    overallInherentImpact=ValueVar(float(a.imp), a.imp_var, a.imp_confInt),
                    overallResidualImpact=ValueVar(float(a.imp), a.imp_var, a.imp_confInt),
                    overallInherentRiskLevel=ValueVar(a.riskLevel, float(a.riskLevel_var), a.riskLevel_confInt),
                    overallResidualRiskLevel=ValueVar(a.riskLevel, float(a.riskLevel_var), a.riskLevel_confInt),
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
        overallInherentLikelihood=ValueVar(float(a.lh), a.LH_var, a.LH_confInt),
        overallResidualLikelihood=ValueVar(float(a.lh), a.LH_var, a.LH_confInt),
        overallInherentImpact=ValueVar(float(a.imp), a.imp_var, a.imp_confInt),
        overallResidualImpact=ValueVar(float(a.imp), a.imp_var, a.imp_confInt),
        overallInherentRiskLevel=ValueVar(a.riskLevel, float(a.riskLevel_var), a.riskLevel_confInt),
        overallResidualRiskLevel=ValueVar(a.riskLevel, float(a.riskLevel_var), a.riskLevel_confInt),
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
