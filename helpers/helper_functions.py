import os
import numpy as np
import ast
from scipy.special import stdtr
import math
from scipy.stats import binom
from scipy.stats import norm
import requests
from shutil import copyfileobj
# np.seterr(all='raise')


def get_confidence_interval(x, alpha=0.05):
    if len(x) == 0:
        return 0.0
    sn = np.sqrt(np.var(x))
    if alpha == 0.05:
        zc = 1.96  # 95% ci
    elif alpha == 0.01:
        zc = 2.58  # 99% ci
    else:
        zc = norm.ppf((1 + (1 - alpha)) / 2.)  # any ci
    return zc * sn / np.sqrt(len(x))


def norm_excel(list_x):
    if list_x[1] >= 0:
        return (list_x[1] - list_x[0]) / (list_x[2] - list_x[0])
    else:
        return None


def download_file(url):
    local_filename = url.split('/')[-1]
    with requests.get(url, stream=True) as r:
        with open(local_filename, 'wb') as f:
            copyfileobj(r.raw, f)

    return local_filename


def cot_func(x, p):
    """
    cotangent plus polynomial function for score smoothing

    :param x: score
    :param p: coefficients
    :return: smoothed score
    """
    return p[0] * (math.tan(p[1] * x + p[2])) ** (-1) + p[3] * x ** 3 + p[4] * x ** 2 + p[5] * x + p[6]


def clscr():
    os.system('cls' if os.name == 'nt' else 'clear')
    """
    Clear console screen
    """


def flatten_list(not_flat_list):
    """
    Flattens a list

    :param not_flat_list: unflattened list
    :return: flattened list
    """
    if isinstance(not_flat_list, list):
        return [y for x in not_flat_list for y in x]
    else:
        return not_flat_list


def parse_ip_ranges(entry):
    """
    :param entry: an IP address entry, which may depict a range using [ ] and comma- or semi-colon-separated entries,
    or a single host
    :return IPNetwork object representation of single node or a list of IPNetwork objects
    """

    try:
        if len(entry) < 7:
            return None

        elif len(entry) > 18:

            if '[' in entry:
                entry = entry.replace("[", "")
                entry = entry.replace("]", "")
            if ',' in entry:
                list_of_ip_strings = entry.split(',')
            elif ';' in entry:
                list_of_ip_strings = entry.split(';')
            else:
                return None
            ip = []
            for ip_entry in list_of_ip_strings:
                ip.append(IPNetwork(ip_entry.strip()))

            ip = flatten_list(ip)

        else:
            ip = IPNetwork(entry)

    except:
        ip = None

    return ip


def random_bounded_gaussian(m, v, size=None, lower_bound=0.01, upper_bound=0.99):
    """
    Bounded Gaussian random number generation
    param m: float or array_like of floats
             Mean (“center”) of the distribution
    :param v: float or array_like of floats
              Variance (spread or “width”) of the distribution
    :param size: int or tuple of ints, optional
              Output shape. If the given shape is, e.g., (m, n, k),
              then m * n * k samples are drawn. If size is None (default),
              a single value is returned if loc and scale are both scalars.
              Otherwise, np.broadcast(loc, scale).size samples are drawn.
    :param lower_bound: scalar or array_like or None
           Minimum value. If None, clipping is not performed on lower interval edge.
           Not more than one of lower_bound and upper_bound may be None.
    :param upper_bound: scalar or array_like or None
           Maximum value. If None, clipping is not performed on upper interval edge.
           Not more than one of lower_bound and upper_bound may be None. If lower_bound
           or upper_bound are array_like, then the three arrays will be broadcast to match their shapes.
    :return: Drawn samples from the parameterized normal distribution,
             between lower_bound and upper_bound :type: ndarray or scalar
    """

    try:
        out = np.clip(np.random.normal(np.asarray(m), np.sqrt(np.asarray(v)), size), lower_bound, upper_bound)
    except:
        out = None

    return out


def cpe_truncation(cpe):
    """
    Drops parts of the cpe we don't have standardized everywhere
    """

    cpe = cpe.replace("cpe:2.3:o:", "")
    cpe = cpe.replace("cpe:2.3:a:", "")
    cpe = cpe.replace("cpe:2.2:o:", "")
    cpe = cpe.replace("cpe:2.2:a:", "")
    cpe = cpe.replace(":*:*:*:*:*:*:*:*", "")
    cpe = cpe.replace(":*:*:*:*:*:*:*", "")
    cpe = cpe.replace(":*:*:*:*:*:*", "")
    cpe = cpe.replace(":r1:sp1", ":r1")
    cpe = cpe.replace(":r2:sp1", ":r2")
    cpe = cpe.replace(":r1:sp2", ":r1")
    cpe = cpe.replace(":r2:sp2", ":r2")
    # TODO just make the asterices replacement regex

    return cpe


def cpe_remove_asterices(cpe):
    """
    Drops asterices from CPEs
    """

    cpe = cpe.replace(":*", "")
    #    cpe = cpe.replace(":r1:sp1", "")
    #    cpe = cpe.replace(":r2:sp1", "")
    #    cpe = cpe.replace(":r1:sp2", "")
    #    cpe = cpe.replace(":r2:sp2", "")

    return cpe


def safestrip(x):
    """
    "Safe" strip

    :param x: string to strip
    :return: stripped string
    """

    try:
        if x is not None:
            return x.strip()
    except:
        return str(x)


def filterNaN(theValue):
    if theValue != theValue:
        return 'null'
    else:
        return theValue


def get_tactic_index(foo):
    if [list(t)[0] for t in foo] == 'mitre-attack_module':
        idx = 1
    else:
        idx = 0

    return idx


def small_poisson(x):
    return np.random.poisson(x * 10000) * GENERAL['Threat Time Window'] / (10000 * GENERAL['Days Per Year'])


def small_binom_rvs(n, p, size):
    return binom.rvs(n, p * 10000, size) / 10000.


def sigmoid(x, a=-1.0):
    return 1. / (1. + math.exp(a * x))


def ttest(abar, avar, na, data):
    nb = len(data)
    bbar = np.mean(data)
    bvar = np.var(data)
    t = (abar - bbar) / np.sqrt(avar / na + bvar / nb)
    adof = na - 1
    bdof = nb - 1
    dof = (avar / na + bvar / nb) ** 2 / (avar ** 2 / (na ** 2 * adof) + bvar ** 2 / (nb ** 2 * bdof))
    p = 2 * stdtr(dof, -np.abs(t))

    return t, p


def hyp_tan(number, function_scalar):
    """
    Hyperbolic tangent function (should be scaled as necessary by expert).

    :param number: float
    :param function_scalar: float
    :return: float
    """

    x = float(number)
    c = float(function_scalar)
    y = math.tanh(x / c)
    return y


def convert_literal_list_to_list(s):
    """
    Converts a text list in form 'X,Y,Z' to python list ['X', 'Y', 'Z']

    :param s: string
    :return: list
    """

    if type(s) is list:
        return s
    else:
        s = "['" + s + "']"
        s = s.replace("\n", " ")
        s = s.replace(",", "', '")
        s_list = ast.literal_eval(s)
        return s_list


def create_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def unique_list(x):
    return list(set(x))
