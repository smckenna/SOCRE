"""
Routines that supports CyRCE and does other analysis
"""

import json
import os
from copy import deepcopy

import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
import numpy as np
import pandas as pd

from config import INPUTS
from helpers.helper_functions import flatten_list, get_confidence_interval


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


"""
Threat Coverage Code
"""


def run_ttp_coverage_metric(ttpInput):
    controls = ttpInput.controls
    action = ttpInput.action
    fam_scores = {}
    for ctrl in controls:
        fam = ctrl.label.split("-")[0]
        if fam in fam_scores.keys():
            fam_scores[fam].append([ctrl.score] * len(ctrl.ttps))
        else:
            fam_scores[fam] = [[ctrl.score] * len(ctrl.ttps)]

    for fam in fam_scores:
        fam_scores[fam] = np.mean(flatten_list(fam_scores[fam]))

    df = pd.read_csv(os.path.join(os.path.dirname(__file__), '../model_resources/control_action_ttp_mapping.csv'), dtype='string')
    ttps = []
    for r in df.iterrows():
        if not pd.isna(r[1]['MITRE ATTACK Technique']):
            ttps.append(r[1]['MITRE ATTACK Technique'].split('.')[0])
        else:
            ttps.append("")
    df['TTP'] = ttps

    action_dict = {}
    action_list = ['error', 'misuse', 'hacking', 'malware', 'social']
    for act in action_list:
        act_df = df[df['VERIS Threat Action'].str.contains(act + '.variety')]
        action_dict[act] = list(zip(act_df['NIST 800-53 Control'].tolist(), act_df['TTP'].tolist()))

    sum1 = []
    in_scope_ttps = [x[1] for x in action_dict[action]]
    in_scope_actions_ = df[df['VERIS Threat Action'].str.contains(action + '.variety')]
    in_scope_actions = np.unique(in_scope_actions_['VERIS Threat Action'].tolist())

    mitigated_ttps = []
    mitigated_actions = []
    for ctrl_ttp in action_dict[action]:  # the in-scope controls|ttps
        if ctrl_ttp[0] not in [x.label for x in controls]:  # control not assessed
            score = 0
            count1 = 1
        else:
            if action in ['hacking', 'malware', 'social']:
                score = [x.score for x in controls if x.label == ctrl_ttp[0]][0]  # control score
                mitigated_ttps.append(ctrl_ttp[1])  # ttp mitigated by this control
                count1 = 1
            else:
                score = [x.score for x in controls if x.label == ctrl_ttp[0]][0]
                if action == 'error':
                    error = df[df['VERIS Threat Action'].str.contains('error.variety')]
                    mitigated_actions_ = error[error['NIST 800-53 Control'].str.contains(ctrl_ttp[0])][
                        'VERIS Threat Action'].tolist()  # actions mitigated by this control
                else:
                    misuse = df[df['VERIS Threat Action'].str.contains('misuse.variety')]
                    mitigated_actions_ = misuse[misuse['NIST 800-53 Control'].str.contains(ctrl_ttp[0])][
                        'VERIS Threat Action'].tolist()  # action(s) mitigated by this control
                count1 = len(mitigated_actions_)  # number of actions mitigated by this control
                mitigated_actions.append(mitigated_actions_)
        sum1.append([score] * count1)

    effectiveness = np.mean(flatten_list(sum1))
    if action in ['hacking', 'malware', 'social']:
        n = len(np.unique(mitigated_ttps))
        d = len(np.unique(in_scope_ttps))
    else:
        n = len(np.unique(flatten_list(mitigated_actions)))
        d = len(in_scope_actions)

    coverage = n / d
    threat_coverage = effectiveness * coverage
    ci = get_confidence_interval(flatten_list(sum1), alpha=INPUTS['confidenceAlpha'])  # no need to factor in the
                                                                                       # coverage since that is just a
                                                                                       # constant and does not affect
                                                                                       # the CI math
    return {'effectiveness': effectiveness,
            'coverage': coverage,
            'n': n,
            'd': d,
            'threat_coverage': threat_coverage,
            'confidence_interval': ci,
            'var': np.var(flatten_list(sum1))}



def mit():
    # Download and parse ATT&CK STIX data
    attackdata = attackToExcel.get_stix_data("enterprise-attack")
    #techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    #tactics_data = stixToDf.tacticsToDf(attackdata)

    # Show T1102 and sub-techniques of T1102
    #techniques_df = techniques_data["techniques"]
    #print(techniques_df[techniques_df["ID"].str.contains("T1102")]["name"])
    # Show citation data for LOLBAS Wmic reference
    #citations_df = techniques_data["citations"]
    #print(citations_df[citations_df["reference"].str.contains("LOLBAS Wmic")])
    # tactic_lbls = np.unique(techniques_df.tactics)
    # app_tactic_list = []
    # for t in tactic_lbls:
    #    tacs_ = tactic_lbls[1].split(',')
    #    for tc in tacs_:
    #        app_tactic_list.append(tc.strip())
    # LAYERS OF CONTROLS
    #tactic_list = tactics_data['tactics'].name.tolist()
    #phase_dict = {key: {'ttps': [], 'sp80053': []} for key in tactic_list}
    #b = 1
    foo = stixToDf.matricesToDf(attackdata, "enterprise-attack")
    db=1
if __name__ == '__main__':
    mit()
