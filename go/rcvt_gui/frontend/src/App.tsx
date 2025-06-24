"use client"; 

import { useState, useEffect } from "react";
import "./App.css";

import {
  GetFileInfo,
  StartFileScan,
  CheckAnalysisStatus,
  ConfirmAnalysisSuccess,
  GetAnalysisResults,
} from "../wailsjs/go/main/App";

import { main } from "../wailsjs/go/models";

function App() {
  const [fileInfo, setFileInfo] = useState<main.FileInfo | null>(null);
  const [stats, setStats] = useState<main.Stats | null>(null);
  const [statusMessage, setStatusMessage] = useState("Initializing...");
  const [error, setError] = useState("");

  useEffect(() => {
    const runAnalysis = async () => {
      try {
        setStatusMessage("Getting file info...");
        const info = await GetFileInfo();
        setFileInfo(info); 

        setStatusMessage("Starting file scan...");
        const scanResult = await StartFileScan();
        if (!scanResult.Success) {
          throw new Error(`Scan failed: ${scanResult.Message}`);
        }

        setStatusMessage("Analyzing file... This can take a moment.");
        const statusResult = await CheckAnalysisStatus();
        if (!statusResult.Success) {
          throw new Error(`Analysis status check failed: ${statusResult.Message}`);
        }

        setStatusMessage("Confirming analysis...");
        const confirmed = await ConfirmAnalysisSuccess();
        if (!confirmed) {
          throw new Error("Could not confirm analysis success.");
        }

        setStatusMessage("Fetching results...");
        const analysisResult = await GetAnalysisResults();
        if (!analysisResult.Success) {
          throw new Error("Failed to get analysis results.");
        }
        
        setStats(analysisResult.Stats);
        setStatusMessage("Analysis Complete!");

      } catch (err: any) {
        setError(err.message || "An unknown error occurred.");
        setStatusMessage("Error");
      }
    };

    runAnalysis();
  }, []); 

  return (
    <div className="App">
      <h1>RightClickVirusTotal</h1>
      
      <h2>Status: {statusMessage}</h2>

        {(fileInfo && fileInfo.Name != "") && (
        <div>
            <h3>File Information</h3>
            <p><strong>Name:</strong> {fileInfo.Name}</p>
            <p><strong>Size:</strong> {fileInfo.Size} bytes</p>
        </div>
            )}

      {stats && (
        <div>
            <h3>Analysis Results</h3>
            <p style={{color: "green"}}>Harmless: {stats.Harmless}</p>
            <p style={{color: "red"}}>Malicious: {stats.Malicious}</p>
            <p style={{color: "orange"}}>Suspicious: {stats.Suspicious}</p>
            <p style={{color: "grey"}}>Undetected: {stats.Undetected}</p>
        </div>
      )}

      {error && (
        <div>
            <h3 style={{color: 'red'}}>An Error Occurred</h3>
            <p>{error}</p>
        </div>
      )}
    </div>
  );
}

export default App;
