"""
Simulation of Cyber Risk Engine - SOCRE
"""
import datetime
import os
import platform
from collections import OrderedDict

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


def compute_transformed_vec(v, lmbda):
    """
    Box-Cox transform
    :param v: vector of values
    :param lmbda: lambda exponent
    :return: transformed vector (v ** lambda)
    """
    if lmbda == 0:
        vec = np.log(v + 1e-10)
    else:
        if isinstance(v, float):
            vec = v ** lmbda
        else:
            vec = np.power(v, lmbda)
    return vec


def compute_levels(v, p, lower_bound=0, upper_bound=5):
    """
    Scoring approach that uses a linear function to map raw to level
    :param v: vector of values
    :param p: coefficients of linear fit, p[0] is intercept, p[1] is slope
    :param lower_bound: lower bound on score level
    :param upper_bound: upper bound on score level
    :return: level = p[0] + p[1] * v, level in [lower, upper]
    """
    level = p[0] * v + p[1]
    if isinstance(v, float):
        if level < lower_bound:
            level = lower_bound
        elif level > upper_bound:
            level = upper_bound
    else:
        level[level < lower_bound] = lower_bound
        level[level > upper_bound] = upper_bound
    return level


def compute_tac_v_control_prob(vuln, tac):
    """
    The TAC vs. control model, i.e., a polynomial of two independent variables to compute the resulting probability
    :param vuln: entity vulnerability metric
    :param tac: threat actor capability
    :return: probability that tac beats control
    """
    p00, p10, p01, p11, p02, p12, p03 = INPUTS['tac_v_ctrl_coeffs']
    x = 1 - vuln
    y = tac
    return p00 + p10 * x + p01 * y + p11 * x * y + p02 * y ** 2 + p12 * x * y ** 2 + p03 * y ** 3


def determine_initial_access(tac, ia_control, vuln, ia_RV):
    # TODO could these could be done "once" outside loop
    """
    Determine "initial access" (ATT&CK Recon, Resource Dev, Initial Access) success or failure
    :param tac: threat actor capability
    :param ia_control: control against Initial Access TTPs
    :param vuln: entity vulnerability metric
    :param ia_RV: Initial Access random variable
    :return: Boolean, True for success, False for fail
    """
    vuln = vuln * (1 - ia_control)
    prob = compute_tac_v_control_prob(vuln, tac)
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if ia_RV <= prob:
        result = True
    else:
        result = False

    return result


def determine_execution(tac, exec_control, exploitability, execution_RV):
    """
    Determine "execution" (ATT&CK Execution, Persistence, Priv Escalation, Defensive Evasion, Cred Access, Discovery,
        Collection) success or failure
    :param tac: threat actor capability
    :param exec_control: control against "execution" TTPs
    :param exploitability: exploitability metric
    :param execution_RV: Execution random variable
    :return: Boolean, True for success, False for fail
    """
    expl = exploitability * (1 - exec_control)
    prob = compute_tac_v_control_prob(expl, tac)
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if execution_RV <= prob:
        result = True
    else:
        result = False

    return result


def determine_movement(tac, movement_control, exploitability, movement_RV):
    """
    Determine "movement" (ATT&CK Lateral Movement) success or failure
    :param tac: threat actor capability
    :param movement_control: control against "movement" TTPs
    :param exploitability: exploitability metric
    :param movement_RV: Movement random variable
    :return: Boolean, True for success, False for fail
    """
    expl = exploitability * (1 - movement_control)
    prob = compute_tac_v_control_prob(expl, tac)
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if movement_RV <= prob:
        result = True
    else:
        result = False

    return result


def determine_impact(impact_control, value):
    """
    Determine "impact" (ATT&CK C&C, Exfil, Impact) success or failure
    I = (1 - RR) * VAL
    :param impact_control: control against "impact" TTPs
    :param value: value of entity
    :return: impact value
    """
    # impact = 0
    # for a in [_ for _ in entity.assets if _.type == 'server' and _.critical]:
    #    impact = a.value * (1 - impact_control)
    return value * (1 - impact_control)


def compute_impact_values(cyrce_input, impact_calc_mode='mean'):
    """
    Compute impact values
    :param cyrce_input: input object containing input impact values
    :param impact_calc_mode: either 'mean' or 'max'
    :return: total impact (using either mean or max approach), direct impact, and indirect impact
    """
    direct_impact_values = list(cyrce_input.impact.directImpact.__dict__.values())
    indirect_impact_values = list(cyrce_input.impact.indirectImpact.__dict__.values())
    direct_impact_value = np.mean(direct_impact_values)
    indirect_impact_value = np.mean(indirect_impact_values)
    if impact_calc_mode == 'mean':
        impact = np.mean((direct_impact_value, indirect_impact_value))
    else:
        impact = np.max(direct_impact_values + indirect_impact_values)
    return impact, direct_impact_value, indirect_impact_value


def update_attack_probability_given_rate(poisson_rate, time_window, attack_motivator):
    """
    Compute the posterior probability of attack using a prior attack rate estimate and new information -- in this case,
        the Attack Motivator metric, using the log-odds-ratio method
    :param poisson_rate: rate of attack as counts per [unit of time]
    :param time_window: window of time we are concerned with (number of units of time)
    :param attack_motivator: Attack Motivator metric
    :return: posterior probability and prior probability
    """
    prior_attack_probability = np.min((0.99, 1. - poisson.cdf(1, poisson_rate)))  # 1 or more attacks, aka ALO
    cond_prob_table = np.array([max(0.01, 0.1 * prior_attack_probability),  # these values are SPM-best-guesses
                                max(0.01, 0.5 * prior_attack_probability),
                                prior_attack_probability,
                                min(1.5 * prior_attack_probability, 0.99),
                                min(2 * prior_attack_probability, 0.99)], dtype=np.double)
    baseline_log_odds = np.log(prior_attack_probability / (1 - prior_attack_probability))
    log_odds_change_attack_probability = np.log(np.divide(cond_prob_table, (1 - cond_prob_table))) - baseline_log_odds
    x = log_odds_change_attack_probability + baseline_log_odds
    attack_probability_table = np.divide(1, (1 + np.divide(1, np.exp(x))))
    func = interpolate.interp1d(np.arange(5) / 4., attack_probability_table, kind='linear')
    attack_probability = func(attack_motivator)
    attack_probability = 1 - (1 - attack_probability) ** time_window
    prior_attack_probability = 1 - (1 - prior_attack_probability) ** time_window
    return attack_probability, prior_attack_probability


def update_attack_probability_given_probability(prior_attack_probability, time_window, attack_motivator):
    """
    Compute the posterior probability of attack using a prior probability estimate and new information -- in this case,
    the Attack Motivator metric, using the log-odds-ratio method
    :param prior_attack_probability: prior probability estimate (over [unit of time])
    :param time_window: window of time we are concerned with (number of units of time)
    :param attackMotivator: Attack Motivator metric
    :return: posterior probability and prior probability
    """
    cond_prob_table = np.array([max(0.01, 0.1 * prior_attack_probability),  # these values are SPM-best-guesses
                                max(0.01, 0.5 * prior_attack_probability),
                                prior_attack_probability,
                                min(1.5 * prior_attack_probability, 0.99),
                                min(2 * prior_attack_probability, 0.99)], dtype=np.double)
    baseline_log_odds = np.log(prior_attack_probability / (1 - prior_attack_probability))
    log_odds_change_attack_probability = np.log(np.divide(cond_prob_table, (1 - cond_prob_table))) - baseline_log_odds
    x = log_odds_change_attack_probability + baseline_log_odds
    attack_probability_table = np.divide(1, (1 + np.divide(1, np.exp(x))))
    func = interpolate.interp1d(np.arange(5) / 4., attack_probability_table, kind='linear')
    attack_probability = func(attack_motivator)
    attack_probability = 1 - (1 - attack_probability) ** time_window
    prior_attack_probability = 1 - (1 - prior_attack_probability) ** time_window
    return attack_probability, prior_attack_probability


def update_metric_KF(x, z, baseline_std_dev=0.2, meas_std_dev=0.1):
    """
    Function to update the estimate of a metric using a "measurement" of the metric, based on Kalman Filter
    :param x: initial estimate of the metric
    :param z: measurement of the metric
    :param baseline_std_dev: std dev of the initial estimate of the metric
    :param meas_std_dev: std dev of the measurement of the metric
    :return: updated estimate of the metric and its covariance
    """
    x10 = x  # initial estimate
    p10 = baseline_std_dev * baseline_std_dev  # uncertainty of initial estimate
    k = p10 / (p10 + meas_std_dev * meas_std_dev)  # Kalman gain
    x11 = x10 + k * (z - x10)  # updated estimate
    p11 = (1 - k) * p10  # updated uncertainty
    return x11, p11


def update_metric(x):
    """
    Function to update the estimate of a metric
    :param x: estimate of the metric
    :return: updated estimate of the metric
    """
    if x is None:
        return 0.5  # naive baseline value of 0.5  # TODO -> settings
    else:
        return x


def run_socre_core(cyrce_input, graph, control_mode='csf', run_mode=['residual'], sweep=False):
    """
    Main routine to run SOCRE
    :param cyrce_input: input object
    :param graph: network model as a graph
    :param control_mode: controls mode, 'csf' or 'sp80053'
    :param run_mode: list of ways to run, 'inherent' or 'residual' or ...
    :param sweep: flag to indicate if we're doing a parameter sweep
    :return: outputs
    """

    # used for testing, etc.
    if (platform.uname()[1] == 'BAHG3479J3') or (
            platform.uname()[1] == 'aframe') and not sweep:  # local, not doing sweep
        random_seed = 101798
        logging.basicConfig(level=logging.INFO,
                            filename="sim_" + str(datetime.datetime.now()).replace(" ", "_").replace(":", "_") + ".log",
                            filemode="w",
                            format="%(name)s - %(levelname)s - %(message)s")
    #        logger = logging.getLogger("Main")
    #        logger.setLevel(level=logging.DEBUG)
    elif not sweep:  # deployed
        random_seed = 101798
        #        logger = logging.getLogger("Main")
        #        logger.setLevel(level=logging.INFO)
        logging.basicConfig(level=logging.CRITICAL,
                            filename="warnings_" + str(datetime.datetime.now()).replace(" ", "_").replace(":",
                                                                                                          "_") + ".log",
                            filemode="w",
                            format="%(name)s - %(levelname)s - %(message)s")
    elif platform.uname()[1] == 'BAHG3479J3' and sweep:  # local, sweep
        #        logger = logging.getLogger("Main")
        #        logger.setLevel(level=logging.INFO)
        logging.basicConfig(level=logging.WARNING,
                            filename="warnings_" + str(datetime.datetime.now()).replace(" ", "_").replace(":",
                                                                                                          "_") + ".log",
                            filemode="w",
                            format="%(name)s - %(levelname)s - %(message)s")
        rng = np.random.default_rng()
        random_seed = int(rng.random() * 100000)

    #np.random.seed(random_seed)
    logging.info(str(random_seed))
    random_state = np.random.RandomState(random_seed)

    # graph = nx.read_graphml(os.path.join(os.path.dirname(__file__), INPUTS['graph_model_file']))

    number_of_monte_carlo_runs = cyrce_input.config.number_mc_iterations
    impact_calc_mode = cyrce_input.config.impact_calc_mode

    # Compute total impact from direct and indirect
    impact_value, direct_impact_value, indirect_impact_value = compute_impact_values(cyrce_input, impact_calc_mode)

    # Set up entities; at this stage, just assets
    all_entities = AllEntities()
    asset_group = EntityGroup('assets')
    df = pd.read_csv("./model_resources/demo_assets.csv")
    for idx, row in df.iterrows():
        entity = Entity(label=row['label'], type=row['type'], critical=bool(row['critical']))
        entity.value = impact_value * row['value']
        entity.assign_properties('ip_address', row['ip'])
        entity.assign_properties('os', row['os'])
        all_entities.list.append(entity)
        asset_group.add_entity([entity])

    # Set up threat actor
    threat_actor = ThreatActor(type=cyrce_input.scenario.attackThreatType)
    threat_actor.assign_property('sophistication', cyrce_input.threatActorInput.sophistication)
    threat_actor.assign_property('resources', cyrce_input.threatActorInput.resources)
    threat_actor.assign_property('determination', cyrce_input.threatActorInput.determination)
    threat_actor.set_attempt_limit()
    threat_actor.set_capability(cyrce_input)

    tacRV = generate_pert_random_variables(random_state=random_state, mode_value=threat_actor.properties['capability'],
                                           gamma=10, nIterations=number_of_monte_carlo_runs)  # TODO -> setting gamma

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
        a.allocate_data_space(['impact', 'access', 'risk'], number_of_monte_carlo_runs)

    # Use this metadata to set scale factor on likelihood of attack
    attack_action = cyrce_input.scenario.attackAction
    attack_industry = cyrce_input.scenario.attackIndustry
    attack_geography = cyrce_input.scenario.attackGeography
    attack_loss_type = cyrce_input.scenario.attackLossType
    attack_threat_type = cyrce_input.scenario.attackThreatType
    org_size = cyrce_input.scenario.orgSize
    attack_target = cyrce_input.scenario.attackTarget

    bbn_file = os.path.join(os.path.dirname(__file__), INPUTS['bbn_file'])

    scenario = ScenarioModel.Scenario(attackAction=attack_action, attackThreatType=attack_threat_type,
                                      attackGeography=attack_geography, attackLossType=attack_loss_type,
                                      attackIndustry=attack_industry, orgSize=org_size, attackTarget=attack_target)
    scenario.determine_scenario_probability_scale_factor(bbn_file=bbn_file, verbose=False)

    # Abstraction groups
    # Will use asset management data, network model, etc.
    network_model = Network(graph=graph)
    logging.info("      Assigning entities to network groups")
    network_model.assign_assets_to_network_groups(all_entities.list)
    logging.info("      Assigning entities to machine groups")
    network_model.assign_assets_to_machine_groups()

    # Handle and set up attack target(s)
    attack_mg_target = []
    if cyrce_input.scenario.attackTarget is not None:
        if 'type' in cyrce_input.scenario.attackTarget:
            for ng in network_model.list_of_network_groups:
                attack_mg_target.append([mg for mg in ng.machine_groups
                                         if cyrce_input.scenario.attackTarget.replace("type:", "") in [a.type for a in
                                                                                                       mg.assets]])
        elif 'label' in cyrce_input.scenario.attackTarget:
            for ng in network_model.list_of_network_groups:
                attack_mg_target.append([mg for mg in ng.machine_groups
                                         if cyrce_input.scenario.attackTarget.replace("label:", "") in [a.label for a in
                                                                                                        mg.assets]])
    else:
        attack_mg_target = [ng.machine_groups for ng in network_model.list_of_network_groups]
    attack_mg_target = flatten_list(attack_mg_target)

    attack_assets_target = []
    for mg in attack_mg_target:
        for a in mg.assets:
            attack_assets_target.append(a)

    # TODO make these entries optional, if that is deemed a good idea, then update them as below if there is info to
    # TODO            use for the update, o/w use baseline
    # Compute Attack Motivator metric
    if attack_action == 'error':
        diligence = cyrce_input.threatActorInput.sophistication
        diligence_RV = generate_pert_random_variables(random_state=random_state, mode_value=diligence,
                                                      nIterations=number_of_monte_carlo_runs)
        attack_motivator = 1  # no adjustment
    else:
        attack_motivator_ = np.mean([cyrce_input.attackMotivators.reward,  # TODO weights?
                                     cyrce_input.attackMotivators.appeal,
                                     cyrce_input.attackMotivators.targeting,
                                     cyrce_input.attackMotivators.perceivedDefenses])
        attack_motivator = update_metric(attack_motivator_)

    probability_scale_factor0 = scenario.probability_scale_factor
    probability_scale_factor = compute_metric(scenario.probability_scale_factor, attack_motivator,
                                              method='geometric')

    if scenario.attackLossType is None:
        scenario.attackLossType = np.random.choice(['c', 'i', 'a'])  # pick a loss type randomly

    """
    Bayes to incorporate log data (a la ARM) (not in this version, but noted here for future)
    attackProbabilityBayes = probLogDataGivenAttack * probAttack / probLogData
    """

    # Compute Threat Level; only used as a reporting metric
    # MODEL: power = ~rate * force;  P = F * V
    threat_level = compute_metric(probability_scale_factor, threat_actor.properties['capability'], method='harmonic')

    # Pre-allocate space for tracking dict
    attack_dict = OrderedDict((k, {}) for k in range(number_of_monte_carlo_runs))

    # TODO using this idea, but not sold on it
    # Using baseline Attack Surface metric, update it with attack surface values from inputs
    attack_surface_ = np.mean([cyrce_input.attackSurface.awareness, cyrce_input.attackSurface.opportunity])
    attack_surface = update_metric(attack_surface_)

    # Using baseline Exploitability metric, update it with exploitability value from inputs
    exploitability_ = cyrce_input.exploitability.easeOfExploit
    exploitability = update_metric(exploitability_)

    # Compute Vulnerability metrics
    # MODEL:  flux = permeability * area * gradient(=1)
    vulnerability = compute_metric(exploitability, attack_surface, method='geometric')

    # Get random variable samples ahead of the MCS
    exploitability_RV = generate_pert_random_variables(random_state=random_state, mode_value=exploitability,
                                                       nIterations=number_of_monte_carlo_runs)
    vulnerability_RV = generate_pert_random_variables(random_state=random_state, mode_value=vulnerability,
                                                      nIterations=number_of_monte_carlo_runs)

    initial_access_RV = generate_uniform_random_variables(random_state=random_state,
                                                          nIterations=number_of_monte_carlo_runs)
    execution_RV = generate_uniform_random_variables(random_state=random_state,
                                                     nIterations=number_of_monte_carlo_runs)

    for a in all_entities.list:
        a.assign_properties('exploitability', exploitability)
        a.assign_properties('attack_surface', attack_surface)
        a.assign_properties('vulnerability', compute_metric(exploitability, attack_surface, method='geometric'))

    if scenario.attackThreatType == 'thirdparty':
        initial_access_thirdparty_RV = generate_uniform_random_variables(random_state=random_state,
                                                                         nIterations=number_of_monte_carlo_runs)
        tac_effect = threat_actor.properties['capability'] / 10.
        initial_access_thirdparty_level_RV = 0.9 + tac_effect

    movement_RV = generate_uniform_random_variables(random_state=random_state, nIterations=number_of_monte_carlo_runs)

    # Compute combined Protect and Detect metric
    protect_detect_RV = generate_pert_random_variables(random_state=random_state,
                                                       mode_value=(cyrce_input.csf.detect.value + cyrce_input.csf.protect.value) / 2,
                                                       gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                                       nIterations=number_of_monte_carlo_runs)

    # Compute combined Respond and Recover metric
    respond_recover_RV = generate_pert_random_variables(random_state=random_state,
                                                        mode_value=(cyrce_input.csf.respond.value + cyrce_input.csf.recover.value) / 2,
                                                        gamma=0.1 + 100 * cyrce_input.csf.identify.value,
                                                        nIterations=number_of_monte_carlo_runs)
    for run in run_mode:
        #np.random.seed(random_seed)
        #rng = np.random.default_rng(random_seed)
        #random_state = np.random.RandomState(random_seed)

        if run == 'inherent':
            protect_detect_RV = 0.
            respond_recover_RV = 0.

        """
        ***********************
        ERROR MC loop begins  *
        ***********************
        Each iteration is a single "error event"
        """
        if attack_action == 'error':
            for iteration in range(0, number_of_monte_carlo_runs):
                execution = 1 - diligence_RV[iteration] > protect_detect_RV[iteration]
                impact = 0.
                access = 0.
                if execution:
                    access = 1.
                    impact = a.value * (1 - respond_recover_RV[iteration])
                    # logging.info(' Impact: ' + str(round(impact, 2)))

                a.manifest['risk'][iteration] = probability_scale_factor * impact
                a.manifest['impact'][iteration] = impact
                a.manifest['access'][iteration] = access
        else:
            """
            ********************
            *  MC loop begins  *
            ********************
            Each iteration is a single attack
            A single attack may have multiple attempts, though, based on the TA attempt_limit
            """
            for iteration in range(0, number_of_monte_carlo_runs):

                try_count = 1
                # TODO origin for insider and for 3rd party ...
                origin = network_model.list_of_network_groups[0].machine_groups[0]  # = internet
                destination = attack_mg_target
                entry_node = attack_mg_target

                seeking_initial_access = True
                current_node = None
                failed_node_list = []

                logging.info(" -----------------")
                logging.info(" Iteration: " + str(iteration))

                attack_dict[iteration]['iteration'] = iteration
                attack_dict[iteration]['attack_type'] = 'nominal'
                attack_dict[iteration]['probability_scale_factor'] = probability_scale_factor
                attack_dict[iteration]['origin'] = origin
                attack_dict[iteration]['destination'] = destination
                attack_dict[iteration]['entryPoint'] = entry_node
                attack_dict[iteration]['sequence'] = [origin]

                attack_dict_element = attack_dict[iteration]
                done = False

                while not done:

                    while try_count <= threat_actor.attempt_limit:

                        if seeking_initial_access:
                            from_node = attack_dict_element['origin']
                            objective_node = attack_dict_element['entryPoint']
                            logger_from_string = attack_dict_element['origin'].label
                        else:
                            from_node = current_node
                            objective_node = attack_dict_element['destination']
                            logger_from_string = current_node.label

                        next_node = network_model.from_node_to_node(from_node=from_node,
                                                                    objective_list=objective_node,
                                                                    network_model=network_model,
                                                                    failed_node_list=failed_node_list,
                                                                    random_state=random_state)
                        if next_node is not None:
                            logging.info(" " + logger_from_string + " ----> " + next_node.label)

                        if next_node is None:
                            try_count += 1
                            failed_node_list.append(next_node)
                            if try_count > threat_actor.attempt_limit:
                                logging.info("   End of path reached, attacker giving up")
                                done = True
                                break
                            else:
                                logging.info("   End of path reached, attacker trying again")

                        # Determine if threat actor gains INITIAL ACCESS to entity
                        if seeking_initial_access:
                            if attack_action == 'misuse':
                                access = True  # this is for an insider, who we assume to have initial access and we assume is malicious
                            else:
                                if scenario.attackThreatType == 'thirdparty':  # hacking modality
                                    # assume third party has initial access at least 90% of the time, based on capability
                                    access = initial_access_thirdparty_RV[iteration] < \
                                             initial_access_thirdparty_level_RV[iteration]
                                else:
                                    access = determine_initial_access(tacRV[iteration],
                                                                      protect_detect_RV[iteration],
                                                                      vulnerability_RV[iteration],
                                                                      initial_access_RV[iteration])

                        else:  # Determine if threat actor moves to next node
                            access = determine_movement(tacRV[iteration],
                                                        protect_detect_RV[iteration],
                                                        exploitability_RV[iteration],
                                                        movement_RV[iteration])

                        if next_node is not None:
                            if not access:
                                try_count += 1
                                failed_node_list.append(next_node)
                                if try_count > threat_actor.attempt_limit:
                                    logging.info("   Failed, attacker giving up - too many tries")
                                    done = True
                                    break
                                else:
                                    logging.info("   Failed, trying again")
                            else:
                                logging.info("    Next hop enabled ...")
                                seeking_initial_access = False
                                current_node = next_node

                            if current_node in attack_dict_element['destination']:
                                done = True
                                seeking_initial_access = False
                                logging.info("       Reached target                                             XXX")
                                break

                    if try_count > threat_actor.attempt_limit:
                        done = True

                    if next_node is not None:
                        execution = determine_execution(tacRV[iteration],
                                                        protect_detect_RV[iteration],
                                                        exploitability_RV[iteration],
                                                        execution_RV[iteration])

                        logging.info("          Execution success?: " + str(execution))
                        impact = 0.
                        access = 0.
                        if execution:
                            access = 1.
                            impact = determine_impact(respond_recover_RV[iteration], next_node.assets[0].value)
                            logging.info("             Impact: " + str(round(impact, 2)))
                        next_node.assets[0].manifest['risk'][iteration] = probability_scale_factor * impact
                        next_node.assets[0].manifest['impact'][iteration] = impact
                        next_node.assets[0].manifest['access'][iteration] = access

        # Collect MCS results to calculate the outputs we want (for the single target node)
        scoring_ceilings_risk = cyrce_input.config.risk_upper_score_bound
        scoring_ceilings_lh = cyrce_input.config.likelihood_upper_score_bound
        scoring_ceilings_imp = cyrce_input.config.impact_upper_score_bound
        a_lh = INPUTS['scoring_coeffs']['likelihood'][0]
        b_lh = INPUTS['scoring_coeffs']['likelihood'][1]
        a_imp = INPUTS['scoring_coeffs']['impact'][0]
        b_imp = INPUTS['scoring_coeffs']['impact'][1]
        a_risk = INPUTS['scoring_coeffs']['risk'][0]
        b_risk = INPUTS['scoring_coeffs']['risk'][1]

        results_df = pd.DataFrame(columns=['label', 'os', 'ip', 'lh', 'impact', 'risk'])
        i = 0
        #        for a in [_ for _ in all_entities.list if _.type == 'server' and _.critical]:
#        for a in [_ for _ in all_entities.list if _.machine_group in attack_mg_target[0].label and _.critical]:
        for a in all_entities.list:
            a.lh_vec = probability_scale_factor * a.manifest['access']
            a.imp_vec = a.manifest['impact']
            a.risk_vec = np.multiply(a.lh_vec, a.imp_vec)
            results_df.loc[i, 'label'] = a.label
            results_df.loc[i, 'os'] = a.properties['os']
            results_df.loc[i, 'ip'] = a.properties['ip_address']
            results_df.loc[i, 'lh'] = round(np.mean(a.lh_vec), 3)
            results_df.loc[i, 'impact'] = round(np.mean(a.imp_vec), 1)
            results_df.loc[i, 'risk'] = round(np.mean(a.risk_vec), 1)
            i += 1

            # # Computing confidence intervals
            # #   Raw
            # a.LH_confInt = 0.1 * a.lh
            # a.risk_confInt = get_confidence_interval(a.risk_vec, alpha=INPUTS['confidenceAlpha'])
            #
            # #   Levels as vectors
            # #       Risk
            # tmpRiskTransformed_vec = compute_transformed_vec(a.risk_vec, INPUTS['scoring_lambdas']['risk'])
            # #       Likelihood
            # tmpLHTransformed_vec = compute_transformed_vec(a.lh_vec, INPUTS['scoring_lambdas']['likelihood'])
            # #       Impact
            # tmpImpactTransformed_vec = compute_transformed_vec(a.imp_vec, INPUTS['scoring_lambdas']['impact'])
            #
            # # Compute the "Level" CIs (requires calc of levels for all runs - "vecs")
            # #   Risk
            # riskLevel_vec = compute_levels(tmpRiskTransformed_vec, INPUTS['scoring_coeffs']['risk'])
            # a.riskLevel_confInt = max(min(2.5, get_confidence_interval(riskLevel_vec[riskLevel_vec > 0],
            #                                                            alpha=INPUTS['confidenceAlpha'])), 0)
            # #   Likelihood
            # LHLevel_vec = compute_levels(tmpLHTransformed_vec, INPUTS['scoring_coeffs']['likelihood'])
            # a.LHLevel_confInt = max(min(2.5, get_confidence_interval(LHLevel_vec[LHLevel_vec > 0],
            #                                                          alpha=INPUTS['confidenceAlpha'])), 0)
            # #   Impact
            # impactLevel_vec = compute_levels(tmpImpactTransformed_vec, INPUTS['scoring_coeffs']['impact'])
            # a.impactLevel_confInt = max(min(2.5, get_confidence_interval(impactLevel_vec[impactLevel_vec > 0],
            #                                                              alpha=INPUTS['confidenceAlpha'])), 0)
            #
            # # Compute variances
            # #   Raw
            # a.LH_var = float(np.var(a.lh_vec))
            # a.imp_var = float(np.var(a.imp_vec))
            # a.risk_var = np.var(a.risk_vec)
            #
            # #   Levels
            # a.riskLevel_var = np.var(riskLevel_vec)
            # a.LHLevel_var = np.var(LHLevel_vec)
            # a.impactLevel_var = np.var(impactLevel_vec)
            #
            # # Compute mean Levels (the results we return)
            # #   Risk
            # riskTransformed = compute_transformed_vec(np.mean(a.risk_vec), INPUTS['scoring_lambdas']['risk'])
            # a.riskLevel = max(min(5, compute_levels(riskTransformed, INPUTS['scoring_coeffs']['risk'])), 0)
            #
            # #   Likelihood
            # LHTransformed = compute_transformed_vec(np.mean(a.lh_vec), INPUTS['scoring_lambdas']['likelihood'])
            # a.LHLevel = max(min(5, compute_levels(LHTransformed, INPUTS['scoring_coeffs']['likelihood'])), 0)
            #
            # #   Impact
            # impactTransformed = compute_transformed_vec(np.mean(a.imp_vec), INPUTS['scoring_lambdas']['likelihood'])
            # a.impactLevel = max(min(5, compute_levels(impactTransformed, INPUTS['scoring_coeffs']['impact'])), 0)
            #
            # # Compute mean raw values
            # a.lh = np.mean(a.lh_vec)
            # if np.sum(a.manifest['access']) == 0:
            #     a.imp = 0.
            # else:
            #     a.imp = np.mean(a.imp_vec[a.manifest['access'] > 0])
            # a.risk = np.mean(a.risk_vec)

            # SPM diagnostics
            # if not deployed and not sweep:
            #     print("lh: " + str(np.round(a.lh, 4)))
            #     print("imp: " + str(np.round(a.imp, 4)))
            #     print("lhLevel: " + str(np.round(a.LHLevel, 2)))
            #     print("lhLevel_CI: " + str(np.round(a.LHLevel_confInt, 3)))
            #     print("impLevel: " + str(np.round(a.impactLevel, 2)))
            #     print("impLevel_CI: " + str(np.round(a.impactLevel_confInt, 3)))
            #     print("risk: " + str(np.round(a.risk, 4)))
            #     print("risk_CI: " + str(np.round(a.risk_confInt, 4)))
            #     print("riskLevel: " + str(np.round(a.riskLevel, 2)))
            #     print("riskLevel_CI: " + str(np.round(a.riskLevel_confInt, 3)))
            #     print("--------------------------------")

            # logger.info("output: " + str(CyrceOutput(
            #     overallInherentLikelihood=ValueVar(float(a.lh), a.LH_var, a.LH_confInt),
            #     overallResidualLikelihood=ValueVar(float(a.lh), a.LH_var, a.LH_confInt),
            #     overallInherentImpact=ValueVar(float(a.imp), a.imp_var, a.imp_confInt),
            #     overallResidualImpact=ValueVar(float(a.imp), a.imp_var, a.imp_confInt),
            #     overallInherentRiskLevel=ValueVar(a.riskLevel, float(a.riskLevel_var), a.riskLevel_confInt),
            #     overallResidualRiskLevel=ValueVar(a.riskLevel, float(a.riskLevel_var), a.riskLevel_confInt),
            #     attack_surface=float(attack_surface),
            #     exploitability=exploitability,
            #     vulnerability=vulnerability,
            #     threatActorCapacity=threat_actor.properties['capability'],
            #     threat_level=float(np.mean(threat_level)),
            #     probability_scale_factor0=float(probability_scale_factor0),
            #     probability_scale_factor=float(probability_scale_factor),
            #     attackMotivators=float(attackMotivator),
            #     directImpact=float(directImpactValue),
            #     indirectImpact=float(indirectImpactValue))))
    return results_df
    # return CyrceOutput(
    #     overallInherentLikelihood=ValueVar(float(a.lh), a.LH_var, a.LH_confInt),
    #     overallResidualLikelihood=ValueVar(float(a.lh), a.LH_var, a.LH_confInt),
    #     overallInherentImpact=ValueVar(float(a.imp), a.imp_var, a.imp_confInt),
    #     overallResidualImpact=ValueVar(float(a.imp), a.imp_var, a.imp_confInt),
    #     overallInherentRiskLevel=ValueVar(a.riskLevel, float(a.riskLevel_var), a.riskLevel_confInt),
    #     overallResidualRiskLevel=ValueVar(a.riskLevel, float(a.riskLevel_var), a.riskLevel_confInt),
    #     attack_surface=float(attack_surface),
    #     exploitability=exploitability,
    #     vulnerability=vulnerability,
    #     threatActorCapacity=threat_actor.properties['capability'],
    #     threat_level=float(np.mean(threat_level)),
    #     probability_scale_factor0=float(probability_scale_factor0),
    #     probability_scale_factor=float(probability_scale_factor),
    #     attackMotivators=float(attack_motivator),
    #     directImpact=float(direct_impact_value),
    #     indirectImpact=float(indirect_impact_value)
    # )
