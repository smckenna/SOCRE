from flask import Flask
from flask_restful import Api

from api_resources.health_resource import HealthResource
from api_resources.cyrce_resource import CyrceCsfResource
from api_resources.cyrce_resource import Cyrce80053Resource

# create app and wrap with api
application = Flask(__name__)
api = Api(application)

api.add_resource(CyrceCsfResource, '/v1/cyrce_csf')
api.add_resource(Cyrce80053Resource, '/v1/cyrce_800_53')
api.add_resource(HealthResource, '/v1/health')

# debug parameter not necessary, just suggested by flask documentation during development
if __name__ == '__main__':
    application.run(debug=True)