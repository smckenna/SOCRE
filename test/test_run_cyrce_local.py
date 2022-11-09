import json
import os

import pytest

from api_resources.cyrce_resource import CyrceResource
from core_module.model_main import run_cyrce


@pytest.fixture(name="run")
def fixture_run():
    with open(os.path.join(os.path.dirname(__file__), '../request.json')) as file:
        json_data = json.load(file)

    cy_res = CyrceResource()
    cyrce_input = cy_res.json_to_input(control_mode='csf', json_data=json_data)

    return cyrce_input


def test_run(run):

    cyrce_input = run

    output_csf = run_cyrce(control_mode='csf', cyrce_input=cyrce_input, run_mode=['residual'])

    # base
    assert output_csf.overallResidualRiskLevel.value == 3.076897319940575
    # min
    #assert output_csf.overallResidualRiskLevel.value == 0.7773578795842138
    # max
    #assert output_csf.overallResidualRiskLevel.value == 5
    # no impact
    #assert output_csf.overallResidualRiskLevel.value == 0

    print("passed test")
