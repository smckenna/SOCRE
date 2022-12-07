INPUTS = {
    'numberOfMonteCarloRuns': 1000,
    'graph_model_file': '../model_resources/test_network_model.graphml',
    'bbn_file': '../scenario_module/scenario_bbn_dbir.json',
    'assets_file': './model_resources/assets.csv',
    'impactCalcMode': 'mean',  # mean or max
    'random_seed': 101798,
    'confidenceAlpha': 0.05,
    'scoring_lambda': 0.245,
    'scoring_fit': [8.4, -0.03],
    'tac_v_ctrl_coeffs': [0.056030,
                          -0.095449,
                          2.448443,
                          -2.320180,
                          -2.114923,
                          1.934016,
                          0.699526]
}
THREAT_ACTOR_CAPACITY_VALUES = {
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
        'none': 0.1,
        'minimal': 0.28,
        'intermediate': 0.46,
        'advanced': 0.64,
        'expert': 0.82,
        'innovator': 0.82,
        'strategic': 0.95
    }
}
THREAT_ACTOR_CAPACITY_WEIGHTS = {
    'determination': 0.9,
    'sophistication': 1,
    'resources': 0.8
}
