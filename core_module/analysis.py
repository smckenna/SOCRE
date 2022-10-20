'''
Routines that supports CyRCE and does other analysis
'''

import logging
from output_module.cyrce_output import ValueVar
import numpy as np
import pandas as pd
from copy import deepcopy
import json
from helpers.helper_functions import fetch_excel_data


def update_nist_json(ctrls_dict):
    """
    Writes out a simpler json of the 800-54 controls; used during dev
    :param ctrls_dict: dict of original json
    :return: 1
    """

    new_dict = deepcopy(ctrls_dict)
    for fam in ctrls_dict:
        for k1 in ctrls_dict[fam].keys():
            if 'value' in k1:
                del new_dict[fam][k1]
            else:
                for k2 in ctrls_dict[fam][k1]:
                    if 'value' in k2:
                        val = ctrls_dict[fam][k1][k2]
                        del new_dict[fam][k1][k2]
                        new_dict[fam][k1] = val

    with open('../nist80053.json', 'wt') as file:
        json.dump(new_dict, file)
    return 1


def fetch_mitre_nist(version=10):
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('Main')
    if version == 9:
        url = "https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/raw/master/frameworks/ATT%26CK-v9.0/nist800-53-r5/nist800-53-r5-mappings.xlsx"
    elif version == 10:
        url = "https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/raw/main/frameworks/attack_10_1/nist800_53_r5/nist800-53-r5-mappings.xlsx"
    else:
        url = "https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/raw/main/frameworks/attack_10_1/nist800_53_r5/nist800-53-r5-mappings.xlsx"

    sheet_name = 'Sheet1'
    mappings = fetch_excel_data(url, sheet_name, skip_rows=0, data_type=str)
    logger.debug('Pulled NIST 800-53 to MITRE mappings from ' + url)
    ttp_to_controls = {}
    for row in mappings.iterrows():
        ttp_to_controls[row[1]['Technique ID']] = row[1]['Control ID']
    return ttp_to_controls


def run_ttp_coverage_metric(scenario, ctrls_dict):
    ttp_to_controls = fetch_mitre_nist(version=10)
    fam_scores = {}
    for fam in ctrls_dict:
        fam_scores[fam] = 0.
        for ctrl in ctrls_dict[fam].keys():
            fam_scores[fam] = fam_scores[fam] + ctrls_dict[fam][ctrl]
        fam_scores[fam] = fam_scores[fam] / len(ctrls_dict[fam].keys())

    in_scope_controls = []
    ttps = ['T1111', 'T1137', 'T1185', 'T1528', 'T1021', 'T1563']

    for ttp in ttps:
        ctrl = ttp_to_controls[ttp]
        in_scope_controls.append(ctrl.replace('-', '_'))

    m = 0
    n = 0
    for in_ctrl in in_scope_controls:
        fam = in_ctrl[0:2]
        for ctrl in ctrls_dict[fam].keys():
            if in_ctrl == ctrl:
                m = m + ctrls_dict[fam][ctrl]
                n += 1
    return m / n * 100.
