from flask import Flask, request, render_template
from pymongo import MongoClient
from datetime import date

app = Flask(__name__)

client = MongoClient('localhost', 27017, username='root', password='example')

db = client.trivy
clusterrbac = db.clusterrbac
clusterinfra = db.clusterinfra
vulnerability = db.vulnerability
compliance = db.compliance
sbom = db.sbom
rbac = db.rbac
secret = db.secret
audit = db.audit

#other
other = db.other

@app.route('/webhook', methods=['POST'])
def webhook():
    if request.method == 'POST':
        kind = request.json["kind"]
        match kind:
            case "ClusterRbacAssessmentReport":
                clusterrbac.insert_one(request.json)
            case "ClusterInfraAssessmentReport":
                clusterinfra.insert_one(request.json)
            case "VulnerabilityReport":
                vulnerability.insert_one(request.json)
            case "ClusterComplianceReport":
                compliance.insert_one(request.json)
            case "SbomReport":
                sbom.insert_one(request.json)
            case "RbacAssessmentReport":
                rbac.insert_one(request.json)
            case "ExposedSecretReport":
                secret.insert_one(request.json)
            case "ConfigAuditReport":
                audit.insert_one(request.json)
            case _:
                other.insert_one(request.json)
        return "Webhook received!"

@app.route('/')
@app.route('/vulnerability/<date_input>')
def vulnerability_route(date_input=None):
    if date_input == None:
        date_input = date.today().strftime("%Y-%m-%d")
    query = {"metadata.creationTimestamp":{"$regex":"^" + date_input}}
    return render_template("index.html", data=vulnerability.find(query))

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.run(host='0.0.0.0', port=8081)
