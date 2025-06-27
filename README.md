<div align="center">

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]


![rcvt](https://github.com/user-attachments/assets/83dd6e56-8539-46a9-9fd4-e0169894b60a)


</div>

## About The Project

RightClickVirusTotal is a cross-platform tool that provides a simple local interface for the VirusTotal API. It's designed to be added to the context menu in Windows and Linux (with Nautilus), allowing you to easily check any file for viruses before running it. A command-line interface (CLI) is also available for all platforms.

### Built With

-  [![Go][Go-shield]][Go-url]
    
-  [![Wails][Wails-shield]][Wails-url]
    
-  [![React][React.js]][React-url]
    
-  [![TypeScript][TypeScript-shield]][TypeScript-url]

-  [![Tailwind CSS][Tailwind-shield]][Tailwind-url] 

-  [![vt-go][vt-go-shield]][vt-go-url]

## Getting Started

To build the project from source, follow these steps. For pre-built binaries, check out the [releases page](https://github.com/smp46/RightClickVirusTotal/releases).

### Prerequisites

You'll need to have Go, Node.js, and the Wails CLI installed.

-   [npm](https://nodejs.org/en/download/)
-   [Go](https://go.dev/doc/install)
-   [Wails](https://wails.io/docs/gettingstarted/installation)
    

### Installation
    
1.  Clone the repo
    
    ```
    git clone [https://github.com/smp46/RightClickVirusTotal.git](https://github.com/smp46/RightClickVirusTotal.git)
    ```
 
    
2.  Build the application
    
    ```
    cd RightClickVirusTotal && ./build-release.sh
    ```
   
  You can then find the builds in the `./builds` folder.
    

## Usage

Get a free API Key at [virustotal.com](https://www.virustotal.com).
After building or downloading, you can run the application from your terminal.

**GUI:**

```
./RCVT_Linux_amd64 gui <Your_VirusTotal_API_Key> <path_to_file>
```

CLI:

The CLI executable can be run directly (the name may vary based on your OS).

```
./RCVT_Linux_amd64 <Your_VirusTotal_API_Key> <path_to_file>
```

The GUI also offers to add a "Right Click" context menu shortcut on Windows and Linux (Nautilus) for easier use.

## Roadmap

-   [x] Cross-platform GUI and CLI
-   [ ] Ability to launch GUI with arguments, so it can be added to the content menu easier
-   [ ] Expanded Linux Desktop Environment Support
-   [ ] macOS support
    

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

Don't forget to give the project a star! Thanks again!

1.  Fork the Project
    
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
    
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
    
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
    
5.  Open a Pull Request
    

### Top contributors:

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

smp46 - me@smp46.me

Project Link: [https://github.com/smp46/RightClickVirusTotal](https://github.com/smp46/RightClickVirusTotal)

## Acknowledgments

-   [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
    
-   [VirusTotal](https://www.virustotal.com/)
    
-   [Wails](https://wails.io/)


[contributors-shield]: https://img.shields.io/github/contributors/smp46/rightclickvirustotal.svg?style=for-the-badge
[contributors-url]: https://github.com/smp46/rightclickvirustotal/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/smp46/rightclickvirustotal.svg?style=for-the-badge
[forks-url]: https://github.com/smp46/rightclickvirustotal/network/members
[stars-shield]: https://img.shields.io/github/stars/smp46/rightclickvirustotal.svg?style=for-the-badge
[stars-url]: https://github.com/smp46/rightclickvirustotal/stargazers
[issues-shield]: https://img.shields.io/github/issues/smp46/rightclickvirustotal.svg?style=for-the-badge
[issues-url]: https://github.com/smp46/rightclickvirustotal/issues
[license-shield]: https://img.shields.io/github/license/smp46/rightclickvirustotal.svg?style=for-the-badge
[license-url]: https://github.com/smp46/rightclickvirustotal/blob/main/LICENSE
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/smp46
[Go-shield]: https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white 
[Go-url]: https://go.dev/ 
[Wails-shield]: https://img.shields.io/badge/Wails-000000?style=for-the-badge&logo=wails&logoColor=FF0000 
[Wails-url]: https://wails.io/ 
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB 
[React-url]: https://reactjs.org/ 
[TypeScript-shield]: https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white 
[TypeScript-url]: https://www.typescriptlang.org/ 
[Tailwind-shield]: https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white 
[Tailwind-url]: https://tailwindcss.com/ 
[vt-go-shield]: https://img.shields.io/badge/vt--go-4285F4?style=for-the-badge&logo=google&logoColor=white 
[vt-go-url]: https://github.com/VirusTotal/vt-go
