"use client";

import { RiGithubLine } from "react-icons/ri";
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
import { BrowserOpenURL } from "../wailsjs/runtime";

const bytesToMB = (bytes: number): string => {
  if (bytes === 0) return "0.00 MB";
  const mb = bytes / (1024 * 1024);
  return mb.toFixed(2) + " MB";
};

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

        setStatusMessage("Uploading file...");
        const scanResult = await StartFileScan();
        if (!scanResult.Success) {
          throw new Error(`Scan failed: ${scanResult.Message}`);
        }

        setStatusMessage("Waiting for Analysis to Complete...");
        const statusResult = await CheckAnalysisStatus();
        if (!statusResult.Success) {
          throw new Error(
            `Analysis status check failed: ${statusResult.Message}`,
          );
        }

        setStatusMessage("Fetching results...");
        const confirmed = await ConfirmAnalysisSuccess();
        if (!confirmed) {
          throw new Error("Failed to get analysis results.");
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

  const totalDetections = stats
    ? stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected
    : 0;

  const barData =
    stats && totalDetections > 0
      ? [
          {
            label: "Malicious",
            value: stats.Malicious,
            color: "bg-red-500",
            percentage: (stats.Malicious / totalDetections) * 100,
          },
          {
            label: "Suspicious",
            value: stats.Suspicious,
            color: "bg-orange-400",
            percentage: (stats.Suspicious / totalDetections) * 100,
          },
          {
            label: "Harmless",
            value: stats.Harmless,
            color: "bg-green-500",
            percentage: (stats.Harmless / totalDetections) * 100,
          },
          {
            label: "Undetected",
            value: stats.Undetected,
            color: "bg-gray-500",
            percentage: (stats.Undetected / totalDetections) * 100,
          },
        ]
      : [];

  return (
    <div className="bg-black text-white min-h-screen flex flex-col items-center justify-center p-4 font-display">
      <div className="w-full max-w-md mx-auto z-50">
        <h1 className="text-3xl font-bold text-center mb-8 ">
          RightClickVirusTotal
        </h1>

        {error && (
          <div className="bg-red-900/50 border border-red-700 text-red-300 px-4 py-3 rounded-lg text-center">
            <h3 className="font-bold text-lg mb-2">An Error Occurred</h3>
            <p>{error}</p>
          </div>
        )}

        {!stats && !error && (
          <div className="text-center">
            <svg
              className="mx-auto animate-spin h-16 w-16"
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                stroke-width="4"
              ></circle>
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              ></path>
            </svg>
            <p className="text-xl font-semibold pt-5">{statusMessage}</p>
            {fileInfo && fileInfo.Name && (
              <div className="text-black mt-4">
                <p>
                  <span className="font-bold">{fileInfo.Name}</span>
                </p>
                <p>{bytesToMB(fileInfo.Size)}</p>
              </div>
            )}
          </div>
        )}

        {stats && !error && (
          <div className="bg-white p-6 rounded-lg shadow-lg">
            <h2 className="text-2xl font-semibold text-center mb-2 text-black">
              Analysis Complete
            </h2>
            {fileInfo && (
              <div className="text-center text-black mb-6">
                <p>
                  <strong>{fileInfo.Name}</strong> ({bytesToMB(fileInfo.Size)})
                </p>
              </div>
            )}

            <div className="space-y-4">
              {barData.map((item) => (
                <div key={item.label}>
                  <div className="flex justify-between items-center mb-1 text-sm font-medium text-black">
                    <span>{item.label}</span>
                    <span>{item.value}</span>
                  </div>
                <div className="w-full z-2 rounded-full h-4">
                    <div
                    className={`${item.color} h-full rounded-full transition-all duration-500 ease-out`}

                    style={{ width: `${item.percentage}%` }}
                    ></div>
                </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
      <footer className="flex justify-center items-center absolute bottom-0 left-0 right-0 bg-black text-white py-4 z-1 gap-1">
        <button
          onClick={() =>
            BrowserOpenURL("https://github.com/smp46/RightClickVirusTotal")
          }
          className="flex items-center justify-center text-white transition-transform duration-300 cursor-pointer hover:scale-110"
          aria-label="github"
        >
          <RiGithubLine className="text-3xl" />
        </button>
        <div>
          <p
            onClick={() => BrowserOpenURL("https://smp46.me")}
            className="flex items-center justify-center text-white cursor-pointer "
          >
            @smp46
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
