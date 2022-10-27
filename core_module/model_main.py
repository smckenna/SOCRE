'''
title
'''

import logging
from scipy import interpolate
from scipy.stats import poisson

from output_module.cyrce_output import CyrceOutput, ValueVar
from config import INPUTS
from entity_module.Entity import Organization
from threat_module.ThreatActor import ThreatActor
from scenario_module import ScenarioModel
from environment_module.network_traversal import *
from helpers.helper_functions import get_confidence_interval
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


def determine_initial_access(tac, proti, protr, vuln, iaRV, coeffs):  # TODO these could be done "once" outside loop
    """
    :param tac: threat actor capacity
    :param proti: CSF Protect Function metric, inherent
    :param protr: CSF Protect Function metric, residual
    :param vuln: vulnerability metric
    :param iaRV: Initial Access random variable
    :param coeffs: Threat Actor Capacity versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    inherent_vuln = vuln * (1 - proti)
    residual_vuln = vuln * (1 - protr)
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

    if iaRV <= prob:
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
    if iaRV <= prob:
        residual_result = True
    else:
        residual_result = False

    return inherent_result, residual_result


def determine_execution(tac, proti, protr, exploitability, iaRV, coeffs):
    """
    :param tac: threat actor capacity
    :param proti: CSF Protect Function metric, inherent
    :param protr: CSF Protect Function metric, residual
    :param exploitability: exploitability metric
    :param iaRV: Initial Access random variable
    :param coeffs: Threat Actor Capacity versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    inherent_expl = exploitability * (1 - proti)
    residual_expl = exploitability * (1 - protr)

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
    if iaRV <= prob:
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
    if iaRV <= prob:
        residual_result = True
    else:
        residual_result = False

    return inherent_result, residual_result


def determine_movement():
    # TBD
    return 0


def determine_impact(rri, rrr, entity):
    """
    I = (1 - RR) * VAL
    :param rri: CSF Respond & Recover Function metric, inherent
    :param rrr:  CSF Respond & Recover Function metric, residual
    :param entity: entity object
    :return: A pair of impact values (inherent, residual)
    """
    inherentImpact = entity.value * (1 - rri)
    residualImpact = entity.value * (1 - rrr)
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


# temp code to test this
def run_cyrce_ttp_coverage(in_val):
    print(in_val)
    print("Running run_cyrce_ttp_coverage")


def run_cyrce(mode, cyrce_input, graph, bbn_file):
    """
    Main routine to run the Booz Allen Cyber Risk Engine
    :param mode: controls mode, 'csf' or '80053'
    :param cyrce_input_: input object
    :param graph: network model as a graph
    :param bbn_file: pybbn bbn as json
    :return: outputs
    """

    # used for testing, etc.
    if platform.uname()[1] == 'BAHG3479J3':
        np.random.seed(101798)

    numberOfMonteCarloRuns = INPUTS['numberOfMonteCarloRuns']
    impactCalcMode = INPUTS['impactCalcMode']
    timeWindow = INPUTS['timeWindow']
    riskMode = INPUTS['riskMode']
    coeffs = INPUTS['tac_v_ctrl_coeffs']

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('Main')

    # Compute total impact from direct and indirect
    impactValue, directImpactValue, indirectImpactValue = compute_impact_values(cyrce_input, impactCalcMode)

    # Define the "atomic" entity
    enterprise = Organization(label='Enterprise')
    enterprise.value = impactValue

    # Create list of all entities
    allEntitiesList = [enterprise]

    # Set up threat actor
    threat_actor = ThreatActor(type=cyrce_input.scenario.attackThreatType)
    threat_actor.assign_property('sophistication', cyrce_input.threatActorInput.sophistication)
    threat_actor.assign_property('resources', cyrce_input.threatActorInput.resources)
    threat_actor.assign_property('determination', cyrce_input.threatActorInput.determination)
    threat_actor.set_attempt_limit()
    threat_actor.set_capability(cyrce_input)

    # Assign control values to each entity
    for a in allEntitiesList:
        if mode == 'csf':
            a.controls['csf']['identify']['value'] = cyrce_input.csf.identify.value
            a.controls['csf']['protect']['value'] = cyrce_input.csf.protect.value
            a.controls['csf']['detect']['value'] = cyrce_input.csf.detect.value
            a.controls['csf']['respond']['value'] = cyrce_input.csf.respond.value
            a.controls['csf']['recover']['value'] = cyrce_input.csf.recover.value
        elif mode == '80053':
            a.controls['80053']['AT'] = cyrce_input.sp80053.AT
            a.controls['80053']['RA'] = cyrce_input.sp80053.RA

        a.allocate_data_space(['impactI', 'impactR', 'accessI', 'accessR', 'riskI', 'riskR'], numberOfMonteCarloRuns)

    # Use this metadata to set scale factor on likelihood of attack
    attackAction = cyrce_input.scenario.attackAction
    attackTarget = cyrce_input.scenario.attackTarget  # also, threat actor objective here
    attackIndustry = cyrce_input.scenario.attackIndustry
    attackGeography = cyrce_input.scenario.attackGeography
    attackLossType = cyrce_input.scenario.attackLossType
    attackThreatType = cyrce_input.scenario.attackThreatType
    orgSize = cyrce_input.scenario.orgSize

    scenario = ScenarioModel.Scenario(attackAction=attackAction, attackThreatType=attackThreatType,
                                      attackGeography=attackGeography, attackLossType=attackLossType,
                                      attackIndustry=attackIndustry, orgSize=orgSize, bbn_file=bbn_file)
    scenario.determine_scenario_probability_scale_factor(verbose=False)

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
    Bayes to incorporate log data (a la ARM) (not in VISTA, but noted here for future)
    attackProbabilityBayes = probLogDataGivenAttack * probAttack / probLogData
    """

    # Compute Threat Level; only used as a reporting metric
    threatLevel = probability_scale_factor * threat_actor.properties['capability']  # MODEL: power = ~rate * force;  P = F * V

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

    initial_accessRV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)
    execution_accessRV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)

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
        destination = enterprise.network_label  # attack target
        entryNode = enterprise.network_label  # first node to gain entry

        initialAccess = True
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

                if initialAccess:
                    nextNode = from_node_to_node(from_node=attackDictElement['origin'],
                                                 objective_node=attackDictElement['entryPoint'],
                                                 attack_type=attackDictElement['attack_type'],
                                                 graph=graph,
                                                 all_assets_list=allEntitiesList,
                                                 failed_node_list=failedNodeList)
                    if nextNode is not None:
                        logger.debug(' ' + attackDictElement['origin'] + ' ----> ' + nextNode.network_label)
                else:
                    nextNode = from_node_to_node(from_node=currentNode,
                                                 objective_node=attackDictElement['destination'],
                                                 attack_type=attackDictElement['attack_type'],
                                                 graph=graph,
                                                 all_assets_list=allEntitiesList,
                                                 failed_node_list=failedNodeList)
                    if nextNode is not None:
                        logger.debug(currentNode + ' ----> ' + nextNode.network_label)

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

                # Determine if threat actor gains INITIAL ACCESS to entity
                inherentAccess, residualAccess = determine_initial_access(threat_actor.properties['capability'],
                                                                          protectDetectRVInherent[iteration],
                                                                          protectDetectRVResidual[iteration],
                                                                          vulnerabilityRV[iteration],
                                                                          initial_accessRV[iteration], coeffs)

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
                        initialAccess = False
                        currentNode = nextNode.network_label

                        if residualAccess is False and doResidual:
                            logger.debug(
                                '   Failed (R), residual attack ends since inherent succeeded')
                            doResidual = False
                        elif residualAccess is True and doResidual:
                            logger.debug('       Next hop enabled (R) ...')
                            currentNode = nextNode.network_label

                    if currentNode == attackDictElement['destination']:
                        done = True
                        initialAccess = False
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
                                                                           execution_accessRV[iteration], coeffs)

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
                nextNode.manifest['riskR'][iteration] = probability_scale_factor * residualImpact
                nextNode.manifest['riskI'][iteration] = probability_scale_factor * inherentImpact
                nextNode.manifest['impactR'][iteration] = residualImpact
                nextNode.manifest['impactI'][iteration] = inherentImpact
                nextNode.manifest['accessR'][iteration] = residualAccess
                nextNode.manifest['accessI'][iteration] = inherentAccess

    # Collect MCS results to calculate the outputs we want (for the single enterprise node)
    for a in allEntitiesList:
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

        if a.uuid == enterprise.uuid:
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
