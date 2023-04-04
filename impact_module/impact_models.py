import math

import numpy as np
from scipy.special import erfcinv
from scipy.stats import uniform


def generate_uniform_random_variables_scaled(lower=1., upper=5., nIterations=1000):
    """
    Generate random variables from the uniform distribution from lower to upper
    :param lower: lower bound
    :param upper: upper bound
    :param nIterations: number of values to generate
    :return: nIterations samples from the unit uniform distribution, scaled
    """
    return uniform.rvs(loc=lower, scale=upper - lower, size=nIterations)


def log_normal_impact(lower_bound, upper_bound, N):
    """
    Estimate impact using log-normal distribution
    :param lower_bound: lower bound of loss
    :param upper_bound: upper bound of loss
    :param N: number of estimates to return
    :return: N estimates of impact
    """

    if upper_bound <= 0 or lower_bound < 0:
        print("High or Low Impact = 0")
        impact_list = generate_uniform_random_variables_scaled(lower=0, upper=1, nIterations=N)
    else:
        impact_list = []
        mu = (np.log(upper_bound) + np.log(lower_bound)) / 2.0
        sd = (np.log(upper_bound) - np.log(lower_bound)) / 3.29  # 3.29 from 90% confidence being 2 * 1.645 standard errors
        foo = generate_uniform_random_variables_scaled(lower=0, upper=1, nIterations=N)
        for i in range(N):
            logx0 = -math.sqrt(2.0) * erfcinv(2.0 * foo[i])
            impact = math.exp(sd * logx0 + mu)
            impact_list.append(impact)

    return impact_list


if __name__ == '__main__':
    imp = log_normal_impact(lower_bound=10, upper_bound=500., N=10000)
    #plt.hist(imp, 100)
    #plt.show()
