from flask import Flask, render_template, request, Response
from gridland_clean import GridlandScanner
import threading
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    if not target:
        return Response("Error: Target is required.", status=400)

    def generate_scan_output():
        def progress_callback(message):
            # We need to format this as a Server-Sent Event
            formatted_message = f"data: {json.dumps({'message': message})}\n\n"
            yield formatted_message

        # The scanner needs to run in a way that allows us to yield from its callback
        # This is tricky because the scanner runs in its own threads.
        # A queue is a good way to bridge this.
        from queue import Queue
        log_queue = Queue()

        def scanner_callback(message):
            log_queue.put(message)

        def run_scan():
            scanner = GridlandScanner(progress_callback=scanner_callback)
            if '/' in target:
                scanner.scan_network(target)
            else:
                scanner.scan_target(target)
            log_queue.put(None) # Signal that the scan is complete

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


if __name__ == '__main__':
    app.run(debug=True, port=5001)
