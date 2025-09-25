# Are Browser Extensions Still Vulnerable? Revisiting DoubleX on the Latest Chrome Web Store Data

This repository contains the code for the bachelor thesis: Are Browser Extensions Still Vulnerable? Revisiting DoubleX on the Latest Chrome Web Store Data.
It contains changes to the CLI API, an AST parser replacement and introduces a database to store and evaluate the results.
For further information on DoubleX, see the original work: [DoubleX](https://github.com/Aurore54F/DoubleX).


## Summary
DoubleX statically detects vulnerable data flows in a browser extension:
- Definition and construction of an Extension Dependence Graph (EDG), i.e., semantic abstraction of extension code (including control and data flows, and pointer analysis) and model of the message interactions within and outside of an extension.
- Data flow analysis to track data from and toward security- and privacy-critical APIs in browser extensions (e.g., `tabs.executeScript`, `downloads.download`, or `topSites.get`).


## Setup

```
install python3 # (tested with 3.7.3 and 3.7.4)
install nodejs
install npm
cd src
npm install esprima # (tested with 4.0.1)
npm install escodegen # (tested with 1.14.2 and 2.0.0)
npm -g install js-beautify
```

To install graphviz (only for drawing graphs, not yet documented, please open an issue if interested):
```
pip3 install graphviz
On MacOS: install brew and then brew install graphviz
On Linux: sudo apt-get install graphviz
```

### Running the Project with Docker

You can use the included `Dockerfile` to quickly set up the development environment. This ensures all required dependencies are installed and configured properly.

#### Steps to Build and Run

1. **Build the Docker Image**  
   From the project root directory, run the following command to build the Docker image:
   ```bash
   docker build -t doublex .
   ```

2. **Run the Docker Container**  
   Start a Docker container based on the built image:
   ```bash
   docker run -it doublex
   ```

---

## PostgreSQL Database Configuration

The project uses a PostgreSQL database for storing analysis results. 
Ensure you have a PostgreSQL database configured and running before proceeding with database-related functionality.

### Environment Variables

To configure the connection to your PostgreSQL database, the following environment variables must be set:

| Environment Variable | Description                             |
|----------------------|-----------------------------------------|
| `POSTGRES_USER`      | PostgreSQL username.                    |
| `POSTGRES_PASSWORD`  | Password for the PostgreSQL user.       |
| `DB_HOST`            | Hostname or IP address of the database. |
| `POSTGRES_DB`        | Name of the PostgreSQL database.        |

### Initializing the Database

To initialize the database, run the following command with the `-i` or `--init` parameter:

```bash
python3 src/db.py --init
```

This will set up the required tables and schema in the database.

### Sample Database Operations

#### Run Analysis Results to Database
After analyzing an extension or a directory of extensions, you can store the results in the database by specifying the `source` path to the analysis result files:

```bash
python3 src/db.py -s <path-to-analysis-results>
```

#### Compare Runs
To compare two runs and save the results, use the `--compare` option with appropriate run identifiers:

```bash
python3 src/db.py -c <run1> <run2>
```

The comparison stores a CSV file in the specified destination directory or in the current working directory.

#### Calculate Evolutions
To calculate differences between extension versions, particularly for their evolution, use the `-ec` option:

```bash
python3 src/db.py -ec <path-to-analysis-results>
```

---

## CLI Arguments

### `doublex.py` Arguments

| Argument                                 | Description                                                                                         |
|------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `--manifest <path>`                      | Path to the extension `manifest.json` file. Default: `parent-path-of-content-script/manifest.json`. |
| `--analysis <path>`                      | Path to store the analysis results. Default: `analysis.json`.                                       |
| `-ad` / `--analysis-dir <path>`          | Path of the directory to store analysis files. Useful with `-dir` or `-dirs`.                       |
| `-cs` / `--content-script <path>`        | Path to the content script. Default: `empty/contentscript.js`.                                      |
| `-bp` / `--background-page <path>`       | Path to the background page or WAR if `--war` is specified. Default: `empty/background.js`.         |
| `-dir` / `--directory <path>`            | Path of the directory containing extension files. Analyzes all supported files in the directory.    |
| `-skip` / `--skip-existing`              | Skips analysis if an existing results file is detected. Used with `-dir` or `-dirs`.                |
| `-ignore` / `--ignore-extensions <path>` | Path to a file listing extensions to ignore during analysis.                                        |
| `-mv` / `--manifest-versions <path>`     | Calculates and stores `manifest_version` of extensions.                                             |

### `db.py` Arguments

| Argument                               | Description                                                                                  |
|----------------------------------------|----------------------------------------------------------------------------------------------|
| `-s` / `--source <path>`               | Path to the directory containing analysis files (mutually exclusive with `-d`).              |
| `-d` / `--destination <path>`          | Path to store exported JSON files (mutually exclusive with `-s`).                            |
| `-i` / `--init`                        | Initializes the database. Has no effect if the database is already initialized.              |
| `-c` / `--compare <run1> <run2>`       | Compares two runs and saves the result as a CSV file (e.g., `<run1>-<run2>-diff.csv`).       |
| `-ec` / `--evolutions-calc <path>`     | Compares extension versions and calculates evolution differences, saving the result as JSON. |
| `-cd` / `--compare-destination <path>` | Directory to store CSV comparison files (used with `-c`).                                    |

---

## Development Notes

- Python dependencies are listed in `requirements.txt`. Install them via:
  ```bash
  pip install -r requirements.txt
  ```
- The Docker image is based on the Python 3.9 Bookworm image and includes tools like `nodejs`, `npm`, and `graphviz`.

---

## Cite the original work
If you use DoubleX for academic research, you are highly encouraged to cite the following [paper](https://swag.cispa.saarland/papers/fass2021doublex.pdf):
```
@inproceedings{fass2021doublex,
    author="Aurore Fass and Doli{\`e}re Francis Som{\'e} and Michael Backes and Ben Stock",
    title="{\textsc{DoubleX}: Statically Detecting Vulnerable Data Flows in Browser Extensions at Scale}",
    booktitle="ACM CCS",
    year="2021"
}
```

## License

The original project is licensed under the terms of the AGPL3 license, which you can find in ```LICENSE```.