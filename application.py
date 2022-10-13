from flask import Flask
from flask_restful import Api

from api_resources.health_resource import HealthResource
from api_resources.cyrce_resource import CyrceCsfResource
from api_resources.cyrce_resource import Cyrce80053Resource
from api_resources.aggregation_resource import RiskAggregationResource
from api_resources.cyrce_resource import CyrceTtpCoverageResource

# create app and wrap with api
application = Flask(__name__)
api = Api(application)

api.add_resource(CyrceCsfResource, '/v1/cyrce_csf')
api.add_resource(Cyrce80053Resource, '/v1/cyrce_800_53')
api.add_resource(CyrceTtpCoverageResource, '/v1/cyrce_ttp_coverage')
api.add_resource(HealthResource, '/v1/health')
api.add_resource(RiskAggregationResource, '/v1/risk_aggregation')

# debug parameter not necessary, just for development
if __name__ == '__main__':
    application.run(debug=True)