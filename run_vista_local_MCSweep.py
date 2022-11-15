import json
import os

import networkx as nx
import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from scipy.stats import uniform, boxcox_normmax

from api_resources.cyrce_resource import CyrceResource
from core_module.model_main import run_cyrce


def generate_uniform_random_variables_scaled(lower=1., upper=5., nIterations=1000):
    """
    Generate random variables from the uniform distribution from lower to upper
    :param lower: lower bound
    :param upper: upper bound
    :param nIterations: number of values to generate
    :return: nIterations samples from the unit uniform distribution, scaled
    """
    return float(uniform.rvs(loc=lower, scale=upper-lower, size=nIterations))


if __name__ == '__main__':
    graph = nx.read_graphml(os.path.join(os.path.dirname(__file__),
                                         './model_resources/atomic_network_model.graphml'))

    cy_res = CyrceResource()

    # mimic api
    with open('request.json') as file:
        json_data = json.load(file)

    nMC = 20000
    test_list = []
    rng = np.random.default_rng()
    for i in np.arange(0, nMC):
        json_data['attackMotivators']['targeting'] = generate_uniform_random_variables_scaled(lower=0.3*5, upper=0.9*5, nIterations=1)
        json_data['attackMotivators']['reward'] = generate_uniform_random_variables_scaled(lower=0.3*5, upper=0.9*5, nIterations=1)
        json_data['attackMotivators']['perceivedDefenses'] = generate_uniform_random_variables_scaled(lower=0.3*5, upper=0.9*5, nIterations=1)
        if json_data['scenario']['attackThreatType'] == "error":
            json_data['exploitability']['easeOfExploit'] = generate_uniform_random_variables_scaled(lower=0.7*5, upper=0.1*5, nIterations=1)
            json_data['attackSurface']['awareness'] = generate_uniform_random_variables_scaled(lower=0.8*5, upper=0.1*5, nIterations=1)
            json_data['attackSurface']['opportunity'] = generate_uniform_random_variables_scaled(lower=0.8*5, upper=0.1*5, nIterations=1)
        else:
            json_data['exploitability']['easeOfExploit'] = generate_uniform_random_variables_scaled(lower=0.7*5, upper=0.1*5, nIterations=1)
            json_data['attackSurface']['awareness'] = generate_uniform_random_variables_scaled(lower=0.8*5, upper=0.1*5, nIterations=1)
            json_data['attackSurface']['opportunity'] = generate_uniform_random_variables_scaled(lower=0.8*5, upper=0.1*5, nIterations=1)
        json_data['threatActor']['resources'] = rng.choice(["individual", "organization", "government"], size=1)[0]
        json_data['threatActor']['sophistication'] = rng.choice(["intermediate", "advanced", "expert", "innovator", "strategic"], size=1)[0]
        json_data['threatActor']['determination'] = rng.choice(["medium", "high"], size=1)[0]
        json_data['scenario']['attackThreatType'] = rng.choice(["threatactor", "insider", "thirdparty"], size=1, p=[0.82, 0.11, 0.07])[0]  # values from BBN, incident = true
        if json_data['scenario']['attackThreatType'] == "threatactor":
            json_data['scenario']['attackAction'] = rng.choice(["malware", "hacking", "social"], size=1)[0]
        else:
            json_data['scenario']['attackAction'] = rng.choice(["malware", "hacking", "social", "misuse", "error"], size=1)[0]
        json_data['scenario']['attackLossType'] = rng.choice(["c", "i", "a"])[0]
        json_data['directImpact']['initialResponseCost'] = generate_uniform_random_variables_scaled(lower=0.5*5, upper=1*5, nIterations=1)
        json_data['directImpact']['productivityLoss'] = generate_uniform_random_variables_scaled(lower=0.5*5, upper=1*5, nIterations=1)
        json_data['directImpact']['replacementCosts'] = generate_uniform_random_variables_scaled(lower=0.5*5, upper=1*5, nIterations=1)
        json_data['directImpact']['safety'] = generate_uniform_random_variables_scaled(lower=0.5*5, upper=1*5, nIterations=1)
        json_data['indirectImpact']['competitiveAdvantageLoss'] = generate_uniform_random_variables_scaled(lower=0.4*5, upper=0.9*5, nIterations=1)
        json_data['indirectImpact']['finesAndJudgements'] = generate_uniform_random_variables_scaled(lower=0.4*5, upper=0.9*5, nIterations=1)
        json_data['indirectImpact']['reputationDamage'] = generate_uniform_random_variables_scaled(lower=0.4*5, upper=0.9*5, nIterations=1)
        json_data['indirectImpact']['secondaryResponseCost'] = generate_uniform_random_variables_scaled(lower=0.4*5, upper=0.9*5, nIterations=1)
        json_data['csf']['identify']['value'] = generate_uniform_random_variables_scaled(lower=0.3, upper=0.6, nIterations=1)
        json_data['csf']['protect']['value'] = generate_uniform_random_variables_scaled(lower=0.4, upper=0.6, nIterations=1)
        json_data['csf']['detect']['value'] = generate_uniform_random_variables_scaled(lower=0.3, upper=0.6, nIterations=1)
        json_data['csf']['respond']['value'] = generate_uniform_random_variables_scaled(lower=0.3, upper=0.6, nIterations=1)
        json_data['csf']['recover']['value'] = generate_uniform_random_variables_scaled(lower=0.3, upper=0.6, nIterations=1)
        test_list.append(cy_res.json_to_input(json_data=json_data))

    N = 12  # mp.cpu_count()

    results = Parallel(n_jobs=N, verbose=10)(delayed(run_cyrce)(i, j, k) for (i, j, k) in zip(test_list, ['csf']*nMC, ['residual']*nMC))
    r = []
    outfile = 'score_calibration/results20k_rev3.csv'
    with open(outfile, 'w+') as file:
        for foo in range(nMC):
            r.append(results[foo].overallInherentLikelihood.value * results[foo].overallInherentImpact.value)
            file.write(str(results[foo].overallInherentLikelihood.value))
            file.write(",")
            file.write(str(results[foo].overallResidualLikelihood.value))
            file.write(",")
            file.write(str(results[foo].overallInherentImpact.value))
            file.write(",")
            file.write(str(results[foo].overallResidualImpact.value))
            file.write(",")
            file.write(str(results[foo].overallInherentRiskLevel.value))
            file.write(",")
            file.write(str(results[foo].overallResidualRiskLevel.value))
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
            file.write(",")

            file.write("\n")

    with open(outfile, 'rt') as file:
        df = pd.read_csv(file, header=None)
    lh = df.iloc[:, 1]
    im = df.iloc[:, 3]
    r = np.multiply(lh, im).dropna()

    best_lambda = boxcox_normmax(r)
    #best_lambda = 0.255
    print("lambda = " + str(best_lambda))
    x = np.quantile(np.power(r, best_lambda), [.001, .1, .50, .9, .999])
    y = np.linspace(0, 5, 5)

    p = np.polyfit(x, y, 1)
    print("p = " + str(p))
