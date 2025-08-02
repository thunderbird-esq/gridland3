import { useState, useEffect } from 'react';
import './App.css';

import ScanForm from './components/ScanForm';
import JobStatus from './components/JobStatus';
import ResultsTable from './components/ResultsTable';
import LogViewer from './components/LogViewer';

function App() {
  const [jobId, setJobId] = useState(null);
  const [jobStatus, setJobStatus] = useState('IDLE');
  const [results, setResults] = useState([]);
  const [logs, setLogs] = useState([]);

  const handleScanSubmit = async (target) => {
    setJobId(null);
    setJobStatus('PENDING');
    setResults([]);
    setLogs([`Submitting scan for target: ${target}`]);

    try {
      const response = await fetch('/api/jobs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target }),
      });
      if (!response.ok) {
        throw new Error('Failed to submit job');
      }
      const data = await response.json();
      setJobId(data.job_id);
    } catch (error) {
      console.error(error);
      setJobStatus('FAILED');
      setLogs(prev => [...prev, 'Error submitting scan job.']);
    }
  };

  useEffect(() => {
    if (!jobId || jobStatus === 'COMPLETED' || jobStatus === 'FAILED') {
      return;
    }

    const intervalId = setInterval(async () => {
      try {
        const response = await fetch(`/api/jobs/${jobId}`);
        if (!response.ok) {
          throw new Error('Failed to fetch job status');
        }
        const data = await response.json();
        setJobStatus(data.status);
        setLogs(data.logs);
        setResults(data.results);

        if (data.status === 'COMPLETED' || data.status === 'FAILED') {
          clearInterval(intervalId);
        }
      } catch (error) {
        console.error(error);
        setJobStatus('FAILED');
        clearInterval(intervalId);
      }
    }, 2000); // Poll every 2 seconds

    return () => clearInterval(intervalId);
  }, [jobId, jobStatus]);

  return (
    <div className="App">
      <header className="App-header">
        <h1>Gridland Security Scanner</h1>
      </header>
      <main>
        <div className="scan-controls">
          <ScanForm onSubmit={handleScanSubmit} isScanning={jobStatus === 'RUNNING' || jobStatus === 'PENDING'} />
        </div>
        <div className="status-section">
          <JobStatus status={jobStatus} />
        </div>
        <div className="results-section">
          <h2>Results</h2>
          <ResultsTable results={results} />
        </div>
        <div className="logs-section">
          <h2>Scan Logs</h2>
          <LogViewer logs={logs} />
        </div>
      </main>
    </div>
  );
}

export default App;
