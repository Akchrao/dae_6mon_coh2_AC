from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify(status="ok", service="ehr-simulator-healthcheck"), 200

@app.route("/")
def index():
    return jsonify(service="CAN EHR Simulator (stand-in)", version="1.0"), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
