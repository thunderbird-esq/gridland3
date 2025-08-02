from flask import Flask, render_template, request, jsonify
import threading
from lib.jobs import create_job, get_job
from lib.orchestrator import run_scan

app = Flask(__name__)

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/api/jobs', methods=['POST'])
def submit_job():
    """
    Submits a new scan job.
    Expects a JSON payload with a 'target' key.
    """
    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({"error": "Target is required"}), 400

    target = data['target']
    job = create_job(target)

    # Run the scan in a background thread
    scan_thread = threading.Thread(
        target=run_scan,
        args=(job.id, target, True, 100) # aggressive=True, threads=100 for now
    )
    scan_thread.start()

    return jsonify({"job_id": job.id}), 202

@app.route('/api/jobs/<job_id>', methods=['GET'])
def get_job_status(job_id: str):
    """
    Retrieves the status, logs, and results for a given job.
    """
    job = get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    return jsonify(job.__dict__)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
