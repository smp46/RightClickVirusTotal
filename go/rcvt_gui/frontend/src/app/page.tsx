import Image from "next/image";
import Link from "next/link";

import { get_file_info } from "../wailsjs/go/main/App.js";
import { start_file_scan } from "../wailsjs/go/main/App.js";
import { check_analysis_results } from "../wailsjs/go/main/App.js";
import { confirm_analysis_success } from "../wailsjs/go/main/App.js";
import { get_analysis_results } from "../wailsjs/go/main/App.js";

export default function Home() {
  // Use to manage wich stage of the app we are in.
  // {0: uploading, 1: uploaded, 2: processing, 3: proceesed, 4: results}
  let stage = 0;

  let file_info_retrieved = false;
  let file_name = "";
  let file_size = 0;

  function getFileInfo() {
    get_file_info().then(
      (name, size) => ((file_name = name), (file_size = size)),
    );
    file_info_retrieved = true;
  }

  return <p>Hello World!</p>;
}
