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
  AddRightClickShortcut,
  ShortcutExists,
  GetAPIKey,
  OfferShortcut,
  GetStartupError,
  FinishAddingShortcut,
  GetVersion,
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
  const [version, setVersion] = useState("0.0.0");

  const [shortcutExists, setShortcutsExists] = useState(false);
  const [offerShortcut, setOfferShortcut] = useState(false);
  const [addShortcut, setAddShortcut] = useState(false);
  const [shortcutError, setShortcutError] = useState("");
  const [finishAddingShortcut, setFinishAddingShortcut] = useState(false);
  const [startupError, setStartupError] = useState("");

  useEffect(() => {
    const runAnalysis = async () => {
      try {
        setVersion(await GetVersion());
        const isFinishingShortcut = await FinishAddingShortcut();
        setFinishAddingShortcut(isFinishingShortcut);

        if (isFinishingShortcut) {
          setAddShortcut(true);
          setOfferShortcut(false);
        } else {
          setOfferShortcut(await OfferShortcut());
        }
        setShortcutsExists(await ShortcutExists());

        const startupErr = await GetStartupError();
        if (startupErr) {
          setError(startupErr);
          setStatusMessage("Error");
          return;
        }

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

  useEffect(() => {
    const handleAddShortcut = async () => {
      if (!shortcutExists && addShortcut) {
        try {
          const apiKey = await GetAPIKey();
          if (!apiKey) {
            throw new Error("API key is required to add the shortcut.");
          }
          const result = await AddRightClickShortcut(apiKey);
          if (result == null) {
            setShortcutsExists(true);
          }
        } catch (err: any) {
          setShortcutError(
            err.message || "An error occurred while adding the shortcut.",
          );
        }
      }
    };
    handleAddShortcut();
  }, [addShortcut]);

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
        <h1 className="text-3xl font-bold text-center ">
          RightClickVirusTotal
        </h1>
        <h2 className="mb-8">{version}</h2>

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
      <footer className="bottom-0 bg-black text-white z-1">
        <div className="pt-4">
          <button
            onClick={() =>
              BrowserOpenURL("https://github.com/smp46/RightClickVirusTotal")
            }
            className="text-white transition-transform duration-300 cursor-pointer hover:scale-110"
            aria-label="github"
          >
            <RiGithubLine className="text-3xl" />
          </button>
        </div>
        <div className="bottom-0 left-0 right-0 pb-4 text-center absolute justify-center">
          {!shortcutExists && offerShortcut && shortcutError === "" && (
            <button
              onClick={() => setAddShortcut(true)}
              className="text-white cursor-pointer "
            >
              Add to Right Click Menu
            </button>
          )}
          {shortcutError === "" && addShortcut && shortcutExists && (
            <p className="text-green-500">Shortcut added successfully!</p>
          )}
          {shortcutError !== "" && (
            <p className="text-red-500">
              Unable to add shortcut: {shortcutError}
            </p>
          )}
        </div>
      </footer>
    </div>
  );
}

export default App;
