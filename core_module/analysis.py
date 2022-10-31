"""
Routines that supports CyRCE and does other analysis
"""

import logging
from copy import deepcopy
import json

import pandas as pd

from helpers.helper_functions import fetch_excel_data
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
import numpy as np
import requests
import urllib3
import json


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

    with open('../sp80053.json', 'wt') as file:
        json.dump(new_dict, file)
    return 1


def fetch_mitre_nist(version=10, local=True):
    # logging.basicConfig(level=logging.DEBUG)
    # logger = logging.getLogger('Main')
    if local:
        if version == 9:
            local_filename = 'nist800-53-r5-mappings_v9.csv'
        else:
            local_filename = 'nist800-53-r5-mappings_v10.csv'

        ttp_to_controls = pd.read_csv(local_filename)
        # logger.debug('Read NIST 800-53 to MITRE mappings from ' + local_filename)

    else:
        sheet_name = 'Sheet1'
        # mappings = fetch_excel_data(url, sheet_name, skip_rows=0, data_type=str)
        # logger.debug('Pulled NIST 800-53 to MITRE mappings from ' + url)
        # ttp_to_controls = {}
        # for row in mappings.iterrows():
        #    ttp_to_controls[row[1]['Technique ID']] = row[1]['Control ID']
    #    response = requests.get("https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/tree/main/frameworks/attack_10_1/nist800_53_r5/stix/nist800-53-r5-mappings.json")
    #    if response and response.status_code == 200:
    # opener = urllib3.build_opener()
    # f = opener.open(response)
    # x = json.loads(f.read())

    #        binary_content = base64.b64decode(response.json()["content"])
    #        content = binary_content.decode("utf-8")
    #        json = json.loads(content)
    #        print(json)

    #    else:
    #        print(response)
    # if version == 9:
    #     url = "https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/tree/main/frameworks/attack_9_0/nist800_53_r5/nist800-53-r5-mappings.xlsx"
    # elif version == 10:
    #     url = "https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/blob/main/frameworks/attack_10_1/nist800_53_r5/nist800-53-r5-mappings.xlsx"
    # else:
    #     url = "https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/blob/main/frameworks/attack_10_1/nist800_53_r5/nist800-53-r5-mappings.xlsx"

    return ttp_to_controls


def run_ttp_coverage_metric(scenario, ctrls_dict):
    ttp_to_controls = fetch_mitre_nist(version=10, local=True)
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
        in_scope_controls.append(ctrl)

    m = 0
    n = 0
    for in_ctrl in in_scope_controls:
        fam = in_ctrl[0:2]
        for ctrl in ctrls_dict[fam].keys():
            if in_ctrl == ctrl:
                m = m + ctrls_dict[fam][ctrl]
                n += 1
    return m / n * 100.


def mit():
    # Download and parse ATT&CK STIX data
    attackdata = attackToExcel.get_stix_data("enterprise-attack")
    techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    tactics_data = stixToDf.tacticsToDf(attackdata)

    # Show T1102 and sub-techniques of T1102
    techniques_df = techniques_data["techniques"]
    print(techniques_df[techniques_df["ID"].str.contains("T1102")]["name"])
    # Show citation data for LOLBAS Wmic reference
    citations_df = techniques_data["citations"]
    print(citations_df[citations_df["reference"].str.contains("LOLBAS Wmic")])
    # tactic_lbls = np.unique(techniques_df.tactics)
    # app_tactic_list = []
    # for t in tactic_lbls:
    #    tacs_ = tactic_lbls[1].split(',')
    #    for tc in tacs_:
    #        app_tactic_list.append(tc.strip())
    # LAYERS OF CONTROLS
    tactic_list = tactics_data['tactics'].name.tolist()
    phase_dict = {key: {'ttps': [], 'sp80053': []} for key in tactic_list}
    b = 1


if __name__ == '__main__':
    mit()
