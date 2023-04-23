import networkx as nx
import os
import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from scipy.stats import uniform, boxcox_normmax
from bah.resources.vista_resource import VistaResource
import json
from bah.model.run_vista import runVista
from pert import PERT


def get_shift_parameters(x, percentile=0.001):
    a = np.quantile(x, percentile)
    b = np.quantile(x, 1 - percentile)
    return a, b


def get_scoring_parameters(x):
    mu = np.mean(x)
    sd = np.std(x)
    a = 1 / 6 / sd
    b = 1 / 2 - mu / 6 / sd
    return a, b


def generate_uniform_random_variables_scaled(randomState, lower=1., upper=5., nIterations=1000):
    """
    Generate random variables from the uniform distribution from lower to upper
    :param lower: lower bound
    :param upper: upper bound
    :param nIterations: number of values to generate
    :return: nIterations samples from the unit uniform distribution, scaled
    """
    return float(uniform.rvs(loc=lower, scale=upper - lower, size=nIterations, random_state=randomState))


def generate_pert_random_variables(randomState, minValue=0., modeValue=0.5, maxValue=1., gamma=20., nIterations=1000):
    """
    The Beta-PERT methodology was developed in the context of Program Evaluation and Review Technique (PERT). It is
    based on a pessimistic estimate (minimum value), a most likely estimate (mode), and an optimistic estimate
    (maximum value), typically derived through expert elicitation.

    :param modeValue: the mode
    :param gamma: the spread parameter
    :param nIterations: number of values to generate
    :return: nIterations samples from the specified PERT distribution
    """
    return PERT(minValue, modeValue, maxValue, gamma).rvs(size=nIterations, random_state=randomState)


if __name__ == '__main__':
    graph = nx.read_graphml(os.path.join(os.path.dirname(__file__),
                                         'model/resources/vista_enterprise_network_model.graphml'))
    bbn_file = os.path.join(os.path.dirname(__file__),
                            'model/scenario_module/scenario_bbn_dbir.json')

    vista_res = VistaResource()
    outfile = './mc_sweep_v5_100k.csv'

    # mimic api
    with open(os.path.join(os.path.dirname(__file__), 'request.json')) as file:
        json_data = json.load(file)

    nMC = 100000
    test_list = []
    rng = np.random.default_rng()
    for i in np.arange(0, nMC):
        json_data['attackMotivators']['targeting'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['attackMotivators']['reward'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['attackMotivators']['perceivedDefenses'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['exploitability']['easeOfExploit'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)[0]
        json_data['attackSurface']['awareness'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['attackSurface']['opportunity'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['threatActor']['resources'] = rng.choice(["individual", "organization", "government", "team"], size=1, p=[0.15, 0.35, 0.35, 0.15])[0]
        json_data['threatActor']['sophistication'] = rng.choice(["minimal", "intermediate", "advanced", "expert",
                                                                 "innovator", "strategic"], size=1, p=[0.05, 0.1, 0.15, 0.2, 0.25, 0.25])[0]
        json_data['threatActor']['determination'] = rng.choice(["low", "medium", "high"], size=1, p=[0.1, 0.3, 0.6])[0]
        json_data['scenario']['attackThreatType'] = \
        rng.choice(["threatactor", "insider", "thirdparty"], size=1, p=[0.82, 0.11, 0.07])[
            0]  # values from BBN, incident = True
        if json_data['scenario']['attackThreatType'] == "threatactor":
            json_data['scenario']['attackAction'] = rng.choice(["malware", "hacking", "social"], size=1,
                                                               p=[0.324, 0.487, 0.189])[0]
        else:
            json_data['scenario']['attackAction'] = \
            rng.choice(["malware", "hacking", "social", "misuse", "error"], size=1,
                       p=[0.239, 0.353, 0.166, 0.104, 0.138])[0]
        json_data['scenario']['attackLossType'] = rng.choice(["c", "i", "a"])[0]
        json_data['scenario']['attackIndustry'] = rng.choice(["accommodation", "administrative", "construction",
                                                              "education", "entertainment", "finance", "healthcare",
                                                              "information", "manufacturing", "miningandutilities",
                                                              "otherservices", "professional", "publicadministration",
                                                              "realestate", "retail", "transportation"], size=1,
                                                             p=[0.036, 0.033, 0.035, 0.067, 0.038, 0.098, 0.055,
                                                                0.097, 0.088, 0.047, 0.038, 0.131, 0.106, 0.036,
                                                                0.054, 0.041])[0]
        json_data['scenario']['orgSize'] = rng.choice(["small", "large"], size=1, p=[0.60, 0.40])[0]
        json_data['scenario']['attackGeography'] = rng.choice(["na", "emea", "apac", "lac", "global"], size=1,
                                                              p=[0.357-0.2/4, 0.183-0.2/4, 0.331-0.2/4,
                                                                 0.129-0.2/4, 0.2])[0]
        json_data['directImpact']['initialResponseCost'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['directImpact']['productivityLoss'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['directImpact']['replacementCosts'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['directImpact']['safety'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['indirectImpact']['competitiveAdvantageLoss'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['indirectImpact']['finesAndJudgements'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['indirectImpact']['reputationDamage'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['indirectImpact']['secondaryResponseCost'] = generate_pert_random_variables(minValue=1, modeValue=3, maxValue=5, gamma=2, nIterations=1)
        json_data['csf']['identify']['value'] = generate_pert_random_variables(minValue=0.2, modeValue=0.75, maxValue=0.8, gamma=1, nIterations=1)
        json_data['csf']['protect']['value'] = generate_pert_random_variables(minValue=0.2, modeValue=0.5, maxValue=0.8, gamma=1, nIterations=1)
        json_data['csf']['detect']['value'] = generate_pert_random_variables(minValue=0.2, modeValue=0.5, maxValue=0.8, gamma=1, nIterations=1)
        json_data['csf']['respond']['value'] = generate_pert_random_variables(minValue=0.2, modeValue=0.5, maxValue=0.8, gamma=1, nIterations=1)
        json_data['csf']['recover']['value'] = generate_pert_random_variables(minValue=0.2, modeValue=0.5, maxValue=0.8, gamma=1, nIterations=1)
        test_list.append(vista_res.jsonToInput(json_data=json_data))

    N = 12  # mp.cpu_count()
    graph_list = [graph] * nMC

    results = Parallel(n_jobs=N, verbose=10)(delayed(runVista)(i, j, k) for (i, j, k) in zip(test_list, graph_list, ['True']*nMC))

    with open(outfile, 'w+') as file:
        for foo in range(nMC):
            file.write(str(results[foo].overallInherentLikelihood.value))
            file.write(",")
            file.write(str(results[foo].overallResidualLikelihood.value))
            file.write(",")
            file.write(str(results[foo].overallInherentImpact.value))
            file.write(",")
            file.write(str(results[foo].overallResidualImpact.value))
            file.write(",")
            file.write(str(results[foo].overallInherentRisk.value))
            file.write(",")
            file.write(str(results[foo].overallResidualRisk.value))
            file.write(",")
            file.write(str(results[foo].attackSurface))
            file.write(",")
            file.write(str(results[foo].exploitability))
            file.write(",")
            file.write(str(results[foo].vulnerability))
            file.write(",")
            file.write(str(results[foo].threatActorCapacity))
            file.write(",")
            file.write(str(results[foo].priorAttackProbability))
            file.write(",")
            file.write(str(results[foo].attackProbability))
            file.write(",")
            file.write(str(results[foo].attackMotivators))
            file.write(",")
            file.write(str(results[foo].indirectImpact))
            file.write(",")
            file.write(str(results[foo].directImpact))
            file.write("\n")

    with open(outfile, 'rt') as file:
        df = pd.read_csv(file, header=None)

    lh = df.iloc[:, 1]
    im = df.iloc[:, 3]
    r = df.iloc[:, 5]
    lhv = np.array(lh)
    imv = np.array(im)
    rv = np.array(r)
    lh = lhv[((r > 0) & (r <= 1))]
    im = imv[((r > 0) & (r <= 1))]
    r = rv[((r > 0) & (r <= 1))]
    r = r[~np.isnan(r)]

    best_lambda_r = boxcox_normmax(r + 1e-16)
    best_lambda_lh = boxcox_normmax(lh + 1e-16)
    best_lambda_im = boxcox_normmax(im + 1e-16)
    print('no xform')
    print("lambda r = " + str(best_lambda_r))
    print("lambda lh = " + str(best_lambda_lh))
    print("lambda im = " + str(best_lambda_im))
    pRisk = get_scoring_parameters(r)
    print("pRisk 0 (a, b) = " + str(pRisk))
    pLH = get_scoring_parameters(lh)
    print("pLH (a, b) = " + str(pLH))
    pIm = get_scoring_parameters(im)
    print("pIm (a, b) = " + str(pIm))

    print('with xform')
    LHx = np.power(lh, best_lambda_lh)
    Imx = np.power(im, best_lambda_im)
    Rx = np.power(r, best_lambda_r)
    pRisk = get_scoring_parameters(Rx)
    print("pRisk X (a, b) = " + str(pRisk))
    pLH = get_scoring_parameters(LHx)
    print("pLH X (a, b) = " + str(pLH))
    pIm = get_scoring_parameters(Imx)
    print("pIm X (a, b) = " + str(pIm))
