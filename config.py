INPUTS = {
    'bbn_file': '../scenario_module/scenario_bbn_2022_dbir.json',
    'control_mapping_refresh': False,
    'timeWindow': 1,  # 1 year
    'confidenceAlpha': 0.05,
    'scoring_coeffs': {'risk': [6.95, 0.28], 'likelihood': [1.91, 0.26], 'impact': [2.57, -0.14]},
    'tac_v_ctrl_coeffs': [0.056030,
                          -0.095449,
                          2.448443,
                          -2.320180,
                          -2.114923,
                          1.934016,
                          0.699526]
}

THREAT_ACTOR_OBJECTIVES = [
                              'accidental',
                              'coercion',
                              'dominance',
                              'ideology',
                              'notoriety',
                              'organizationalGain',
                              'personalGain',
                              'personalSatisfaction',
                              'revenge',
                              'unpredictable'
                          ],
THREAT_ACTOR_CAPABILITY_VALUES = {
    'determination': {
        'low': 0.1,
        'medium': 0.5,
        'high': 0.9
    },
    'resources': {
        'individual': 0.2,
        'club': 0.4,
        'contest': 0.1,
        'team': 0.5,
        'organization': 0.8,
        'government': 0.95
    },
    'sophistication': {
        'none': 0.05,
        'minimal': 0.1,
        'intermediate': 0.4,
        'advanced': 0.6,
        'expert': 0.7,
        'innovator': 0.8,
        'strategic': 0.95
    }
}
THREAT_ACTOR_CAPABILITY_WEIGHTS = {
    'determination': 0.9,
    'sophistication': 1,
    'resources': 0.8
}
