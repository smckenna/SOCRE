'''
Aggregation engine
'''

from aggregation_module.aggregation_input import AggregationInput
from aggregation_module.aggregation_output import AggregationOutput, ValueVar
from helpers.helper_functions import get_confidence_interval
import numpy as np
from config import INPUTS
import logging


def runAggregation(aggregationInput: AggregationInput):
    """
    Routine to aggregate risk values into Risk Levels
    :param aggregationInput: input object
    :return: outputs
    """

    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('Main')

    sum_values = 0.
    sum_weights = 0.
    for v, w in zip(aggregationInput.risk_values.values, aggregationInput.risk_values.weights):
        sum_values = sum_values + v * w
        sum_weights = sum_weights + w
    avg_risk = float(sum_values / sum_weights)
    weighted_risks = np.divide(np.multiply(aggregationInput.risk_values.values, aggregationInput.risk_values.weights),
                               aggregationInput.risk_values.weights)
    var_risk = float(np.var(weighted_risks))

    risk_confInt = max(min(5, get_confidence_interval(weighted_risks, alpha=INPUTS['confidenceAlpha'])), 0)

    if INPUTS['scoring_lambda'] == 0:
        riskTransformed = np.log(weighted_risks + 1e-10)
        riskTransformed1 = np.log(avg_risk + 1e-10)
    else:
        riskTransformed = weighted_risks ** INPUTS['scoring_lambda']
        riskTransformed1 = avg_risk ** INPUTS['scoring_lambda']

    riskLevel_ = INPUTS['scoring_fit'][0] * riskTransformed + INPUTS['scoring_fit'][1]
    riskLevel_[riskLevel_ < 0] = 0
    riskLevel_[riskLevel_ > 5] = 5

    riskLevel1 = max(min(5, INPUTS['scoring_fit'][0] * riskTransformed1 + INPUTS['scoring_fit'][1]), 0)

    riskLevel_confInt = max(min(5, get_confidence_interval(riskLevel_, alpha=INPUTS['confidenceAlpha'])), 0)
    riskLevel_var = float(np.var(riskLevel_))

    riskLevel = float(np.mean(riskLevel_))

    # SPM diagnostics
    print("risk values = " + str([round(r, 1) for r in aggregationInput.risk_values.values]))
    print("avg risk = " + str(round(avg_risk, 3)))
    print("risk levels = " + str([round(r, 1) for r in riskLevel_]))
    print("avg risk level = " + str(round(riskLevel1, 3)))
    print("agg riskLevel = " + str(round(riskLevel, 3)))
    print("agg riskLevel_var = " + str(round(riskLevel_var, 1)))
    print("agg riskLevel_CI = " + str(round(riskLevel_confInt, 2)))
    print("--------------------------------")

    logger.debug('output: ' + str(AggregationOutput(
        overallRisk=ValueVar(avg_risk, var_risk, risk_confInt),
        overallRiskLevel=ValueVar(riskLevel, riskLevel_var, riskLevel_confInt))))

    return AggregationOutput(
        overallRisk=ValueVar(avg_risk, var_risk, risk_confInt),
        overallRiskLevel=ValueVar(riskLevel, riskLevel_var, riskLevel_confInt))
