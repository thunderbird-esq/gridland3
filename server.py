from flask import Flask, render_template, request, Response
from gridland_clean import GridlandScanner
import threading
import json
from queue import Queue

app = Flask(__name__)

# Global variable to hold the current scanner instance
current_scanner = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    global current_scanner
    target = request.form.get('target')
    if not target:
        return Response("Error: Target is required.", status=400)

    def generate_scan_output():
        global current_scanner
        log_queue = Queue()

        def scanner_callback(message):
            log_queue.put(message)

        def run_scan():
            global current_scanner
            current_scanner = GridlandScanner(progress_callback=scanner_callback)
            if '/' in target:
                current_scanner.scan_network(target)
            else:
                current_scanner.scan_target(target)
            log_queue.put(None) # Signal that the scan is complete
            current_scanner = None # Clear the scanner instance

        # Run the scanner in a background thread
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.start()

        # Yield messages from the queue
        while True:
            message = log_queue.get()
            if message is None:
                break
            yield f"data: {json.dumps({'message': message})}\n\n"

        yield f"data: {json.dumps({'message': '[SCAN COMPLETE]'})}\n\n"

    return Response(generate_scan_output(), mimetype='text/event-stream')

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    global current_scanner
    if current_scanner:
        current_scanner.stop()
        return Response("Scan stop signal sent.", status=200)
    return Response("No active scan to stop.", status=404)


if __name__ == '__main__':
    app.run(debug=True, port=5001)
