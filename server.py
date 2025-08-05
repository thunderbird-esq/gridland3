#!/usr/bin/env python3
"""
Flask server launcher for Gridland
"""
from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO
import threading
import logging
import os
from datetime import datetime
from lib.jobs import create_job, get_job
from lib.orchestrator import run_scan
from fpdf import FPDF

class ReportPDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Gridland Security Scan Report', 0, 1, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(5)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, body)
        self.ln()

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'a_very_secret_key'
socketio = SocketIO(app)

# Configure web interface logging
def setup_web_logging() -> logging.Logger:
    """Setup detailed logging for web interface operations"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"gridland_web_server_{timestamp}.log"
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    log_path = os.path.join('logs', log_filename)
    
    # Configure logger
    logger = logging.getLogger('gridland_web')
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # File handler for detailed logs
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler for Flask output
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Detailed formatter for file
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    # Simple formatter for console
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"=== GRIDLAND WEB SERVER SESSION STARTED ===")
    logger.info(f"Timestamp: {timestamp}")
    logger.info(f"Log file: {log_path}")
    logger.info(f"=" * 50)
    
    return logger

# Initialize web logger
web_logger = setup_web_logging()

@app.route('/')
def index():
    """Serves the main HTML page."""
    web_logger.info("Serving main HTML page")
    web_logger.debug(f"Request from {request.remote_addr}")
    return render_template('index.html')

@app.route('/api/jobs', methods=['POST'])
def submit_job():
    """
    Submits a new scan job.
    Expects a JSON payload with a 'target' key.
    """
    web_logger.info(f"Job submission request from {request.remote_addr}")
    
    data = request.get_json()
    web_logger.debug(f"Request data: {data}")
    
    if not data or 'target' not in data:
        web_logger.warning("Job submission failed - missing target")
        return jsonify({"error": "Target is required"}), 400

    target = data['target']
    web_logger.info(f"Creating job for target: {target}")
    
    try:
        job = create_job(target)
        web_logger.debug(f"Job created with ID: {job.id}")

        # Run the scan in a background thread
        web_logger.info(f"Starting background scan thread for job {job.id}")
        scan_thread = threading.Thread(
            target=run_scan,
            args=(job.id, target),
            kwargs={'aggressive': True, 'threads': 100, 'socketio': socketio}
        )
        scan_thread.start()
        web_logger.debug(f"Background thread started for job {job.id}")

        web_logger.info(f"Job {job.id} successfully submitted")
        return jsonify({"job_id": job.id}), 202
        
    except Exception as e:
        web_logger.error(f"Job submission failed: {str(e)}")
        web_logger.debug(f"Job submission exception details", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/jobs/<job_id>', methods=['GET'])
def get_job_status(job_id: str):
    """
    Retrieves the status, logs, and results for a given job.
    """
    web_logger.debug(f"Job status request for {job_id} from {request.remote_addr}")
    
    try:
        job = get_job(job_id)
        if not job:
            web_logger.warning(f"Job {job_id} not found")
            return jsonify({"error": "Job not found"}), 404

        web_logger.debug(f"Returning status for job {job_id}: {job.status}")
        return jsonify(job.to_dict())
        
    except Exception as e:
        web_logger.error(f"Error retrieving job {job_id}: {str(e)}")
        web_logger.debug(f"Job status exception details", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/report/<job_id>')
def generate_report(job_id):
    job = get_job(job_id)
    if not job:
        return "Job not found", 404

    pdf = ReportPDF()
    pdf.add_page()

    # --- Report Header ---
    pdf.chapter_title(f"Scan Report for Target: {job.target}")

    # --- LLM Analysis Summary ---
    if job.analysis:
        pdf.chapter_title("Intelligence Analysis")
        pdf.chapter_body(job.analysis)

    # --- Detailed Findings ---
    pdf.chapter_title("Detailed Findings")
    for result in job.results:
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, f"Device: {result.ip} ({result.brand or 'Unknown'})", 0, 1)

        pdf.set_font('Arial', '', 10)
        if result.credentials:
            pdf.multi_cell(0, 5, f"  Credentials Found: {', '.join(result.credentials.keys())}")
        if result.vulnerabilities:
             pdf.multi_cell(0, 5, f"  Vulnerabilities: {len(result.vulnerabilities)} found.")
        if result.streams:
            pdf.multi_cell(0, 5, f"  Streams Found: {len(result.streams)}")

    return Response(pdf.output(dest='S').encode('latin-1'),
                    mimetype='application/pdf',
                    headers={'Content-Disposition': f'attachment;filename=gridland_report_{job_id}.pdf'})

if __name__ == '__main__':
    web_logger.info("Starting Flask development server on port 5000")
    web_logger.warning("This is a development server - not for production use")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)