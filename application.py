from flask import Flask
from flask_restful import Api

from bah.resources.health_resource import HealthResource
from bah.resources.vista_resource import VistaResource

# create app and wrap with api
application = Flask(__name__)
api = Api(application)

api.add_resource(VistaResource, '/v1/vista')
api.add_resource(HealthResource, '/v1/health')

# debug parameter not necessary, just suggested by flask documentation during development
if __name__ == '__main__':
    application.run(debug=True)